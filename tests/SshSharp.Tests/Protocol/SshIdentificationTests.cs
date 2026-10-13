using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class SshIdentificationTests
{
    [Test]
    [Arguments("SSH-2.0-OpenSSH_9.9", "2.0", "OpenSSH_9.9", null)]
    [Arguments("SSH-2.0-OpenSSH_9.9 Ubuntu-1", "2.0", "OpenSSH_9.9", "Ubuntu-1")]
    [Arguments("SSH-1.99-Dropbear", "1.99", "Dropbear", null)]
    [Arguments("SSH-2.0-a-b-c", "2.0", "a-b-c", null)]
    public async Task TryParse_Accepts(string line, string protocol, string software, string? comments)
    {
        await Assert.That(SshIdentification.TryParse(line, out var id)).IsTrue();
        await Assert.That(id!.ProtocolVersion).IsEqualTo(protocol);
        await Assert.That(id.SoftwareVersion).IsEqualTo(software);
        await Assert.That(id.Comments).IsEqualTo(comments);
        await Assert.That(id.Line).IsEqualTo(line);
    }

    [Test]
    [Arguments("")]
    [Arguments("HTTP/1.1 200 OK")]
    [Arguments("SSH-1.5-old")]
    [Arguments("SSH-2.0")]
    [Arguments("SSH-2.0-")]
    [Arguments("SSH--soft")]
    [Arguments("SSH-3.0-future")]
    [Arguments("SSH-2.0-has\u0001control")]
    [Arguments("SSH-2.0- space-first")]
    public async Task TryParse_Rejects(string line)
    {
        await Assert.That(SshIdentification.TryParse(line, out var id)).IsFalse();
        await Assert.That(id).IsNull();
    }

    [Test]
    public async Task TryParse_RejectsLinesBeyond255BytesIncludingCrLf()
    {
        var atLimit = "SSH-2.0-" + new string('x', 255 - 2 - 8);
        var over = atLimit + "x";
        await Assert.That(SshIdentification.TryParse(atLimit, out _)).IsTrue();
        await Assert.That(SshIdentification.TryParse(over, out _)).IsFalse();
    }

    [Test]
    public async Task ForClient_IdentifiesTheLibrary()
    {
        var id = SshIdentification.ForClient();
        await Assert.That(id.Line).StartsWith("SSH-2.0-SshSharp_");
        await Assert.That(id.Line.Length + 2).IsLessThanOrEqualTo(SshIdentification.MaxLength);
    }

    [Test]
    public async Task Write_AppendsCrLf_AndRejectsOversizedValues()
    {
        var buffer = new ArrayBufferWriter<byte>();
        new SshIdentification("2.0", "Test", "c1").Write(buffer);
        await Assert.That(Encoding.ASCII.GetString(buffer.WrittenSpan)).IsEqualTo("SSH-2.0-Test c1\r\n");

        var tooLong = new SshIdentification("2.0", new string('x', 300), null);
        await Assert.That(() => tooLong.Write(new ArrayBufferWriter<byte>())).Throws<InvalidOperationException>();
    }

    private static async Task<(SshIdentification? Id, string Leftover, Exception? Error)> Read(string data, bool complete = true)
    {
        var pipe = new Pipe();
        await pipe.Writer.WriteAsync(Encoding.UTF8.GetBytes(data));
        if (complete)
        {
            await pipe.Writer.CompleteAsync();
        }

        try
        {
            var id = await SshIdentification.ReadAsync(pipe.Reader, CancellationToken.None);
            var rest = new StringBuilder();
            if (complete)
            {
                while (true)
                {
                    var result = await pipe.Reader.ReadAsync();
                    rest.Append(Encoding.UTF8.GetString(result.Buffer));
                    pipe.Reader.AdvanceTo(result.Buffer.End);
                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
            }

            return (id, rest.ToString(), null);
        }
        catch (Exception ex)
        {
            return (null, string.Empty, ex);
        }
    }

    [Test]
    public async Task ReadAsync_SkipsBannerLines_AndLeavesTheRestInTheReader()
    {
        var (id, leftover, error) = await Read("Welcome\r\nto the server\nSSH-2.0-Srv one\r\nBINARYDATA");
        await Assert.That(error).IsNull();
        await Assert.That(id!.SoftwareVersion).IsEqualTo("Srv");
        await Assert.That(id.Comments).IsEqualTo("one");
        await Assert.That(leftover).IsEqualTo("BINARYDATA");
    }

    [Test]
    public async Task ReadAsync_AcceptsBareLfLineEndings()
    {
        var (id, _, error) = await Read("SSH-2.0-Srv\n");
        await Assert.That(error).IsNull();
        await Assert.That(id!.Line).IsEqualTo("SSH-2.0-Srv");
    }

    [Test]
    public async Task ReadAsync_RejectsUnsupportedVersions()
    {
        var (_, _, error) = await Read("SSH-1.5-ancient\r\n");
        await Assert.That(error).IsTypeOf<SshException>();
        await Assert.That(((SshException)error!).Reason).IsEqualTo(SshFailureReason.ProtocolError);
    }

    [Test]
    public async Task ReadAsync_FailsOnEofBeforeAnIdentification()
    {
        var (_, _, error) = await Read("just banner text, no newline");
        await Assert.That(((SshException)error!).Reason).IsEqualTo(SshFailureReason.ConnectionClosed);

        var (_, _, error2) = await Read("banner only\r\n");
        await Assert.That(((SshException)error2!).Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
    }

    [Test]
    public async Task ReadAsync_RejectsEndlessLinesAndTooManyBannerLines()
    {
        var (_, _, longLine) = await Read(new string('a', 5000), complete: false);
        await Assert.That(longLine).IsTypeOf<SshProtocolException>();

        var many = string.Concat(Enumerable.Repeat("x\r\n", 300)) + "SSH-2.0-late\r\n";
        var (_, _, tooMany) = await Read(many);
        await Assert.That(tooMany).IsTypeOf<SshProtocolException>();

        var giantBannerLine = new string('b', 5000) + "\r\nSSH-2.0-x\r\n";
        var (_, _, giant) = await Read(giantBannerLine);
        await Assert.That(giant).IsTypeOf<SshProtocolException>();
    }

    [Test]
    public async Task ReadAsync_WaitsForMoreDataAcrossReads()
    {
        var pipe = new Pipe();
        var read = SshIdentification.ReadAsync(pipe.Reader, CancellationToken.None).AsTask();
        await pipe.Writer.WriteAsync("SSH-2.0-Sl"u8.ToArray());
        await Task.Delay(30);
        await Assert.That(read.IsCompleted).IsFalse();
        await pipe.Writer.WriteAsync("ow\r\n"u8.ToArray());
        var id = await read;
        await Assert.That(id.SoftwareVersion).IsEqualTo("Slow");
    }
}