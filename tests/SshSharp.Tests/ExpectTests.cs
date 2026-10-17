using System.Text;
using System.Text.RegularExpressions;

namespace SshSharp.Tests;

/// <summary><see cref="SshExpect"/> (#115), over streams whose chunk boundaries the tests choose.</summary>
public class ExpectTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>Returns the given chunks one read at a time, then end of stream (or waits forever, for cancellation tests).</summary>
    private sealed class ScriptedStream(IEnumerable<byte[]> chunks, bool endAfter = true) : Stream
    {
        private readonly Queue<byte[]> _chunks = new(chunks);

        public int Reads { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Reads++;
            if (_chunks.TryDequeue(out var chunk))
            {
                if (chunk.Length > buffer.Length)
                {
                    throw new InvalidOperationException("The test chunk is larger than the read buffer.");
                }

                chunk.CopyTo(buffer);
                return chunk.Length;
            }

            if (!endAfter)
            {
                await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            }

            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static SshExpect Over(params string[] chunks) =>
        new(new ScriptedStream(chunks.Select(Encoding.UTF8.GetBytes)), new MemoryStream());

    [Test]
    public async Task TextSplitAcrossReads_IsFound_AndWhatFollowsIsKept()
    {
        var expect = Over("Welcome\r\nuser@host:~", "$ ", "after");

        var match = await expect.ExpectAsync("$ ", Timeout());

        await Assert.That(match.Before).IsEqualTo("Welcome\r\nuser@host:~");
        await Assert.That(match.Value).IsEqualTo("$ ");
        await Assert.That(match.Match).IsNull();
        await Assert.That((await expect.ExpectAsync("ter", Timeout())).Before).IsEqualTo("af");
    }

    [Test]
    public async Task ManyTinyReads_CostTimeInProportionToTheOutput()
    {
        // A server sending one character per packet: each read used to copy and rescan everything pending (quadratic). 300,000 reads of
        // one character, then the prompt split one character per read too.
        var chunks = Enumerable.Repeat("x", 300_000).Concat("ready$ ".Select(c => c.ToString())).Concat(["after"]);
        var expect = Over([.. chunks]);
        var started = System.Diagnostics.Stopwatch.StartNew();

        var match = await expect.ExpectAsync("ready$ ", Timeout());

        await Assert.That(match.Before.Length).IsEqualTo(300_000);
        await Assert.That(match.Value).IsEqualTo("ready$ ");
        await Assert.That(started.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That((await expect.ExpectAsync("ter", Timeout())).Before).IsEqualTo("af");
    }

    [Test]
    public async Task TheBufferKeepsExactlyTheLastCharacters_WhenItOverflows()
    {
        var chunks = Enumerable.Range(0, 50).Select(i => $"{i:D4}|").ToArray();
        var expect = new SshExpect(new ScriptedStream(chunks.Select(Encoding.UTF8.GetBytes), endAfter: true), new MemoryStream()) { MaxBufferLength = 12 };

        await Assert.That(async () => await expect.ExpectAsync("never", Timeout())).Throws<EndOfStreamException>();
        await Assert.That(expect.Pending).IsEqualTo("7|0048|0049|"); // the last 12 characters

        // A match across a trim boundary is still found when it fits in the buffer.
        string[] parts = ["aaaaaaaaaaPRO", "MPT"];
        var straddling = new SshExpect(new ScriptedStream(parts.Select(Encoding.UTF8.GetBytes)), new MemoryStream()) { MaxBufferLength = 8 };
        await Assert.That((await straddling.ExpectAsync("PROMPT", Timeout())).Value).IsEqualTo("PROMPT");
    }

    [Test]
    public async Task ARegexThatTakesTooLong_EndsTheWaitWithItsTimeout()
    {
        // Catastrophic backtracking on output the server chose: the pattern's MatchTimeout bounds it.
        var expect = Over(new string('a', 40) + "!");
        var pattern = new Regex("^(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(50));

        await Assert.That(async () => await expect.ExpectAsync(pattern, Timeout())).Throws<RegexMatchTimeoutException>();
        await Assert.That(expect.Pending).IsEqualTo(new string('a', 40) + "!");
    }

    [Test]
    public async Task TextAlreadyBuffered_IsFoundWithoutReading()
    {
        var stream = new ScriptedStream([Encoding.UTF8.GetBytes("one two three")]);
        var expect = new SshExpect(stream, new MemoryStream());

        await expect.ExpectAsync("one", Timeout());
        var reads = stream.Reads;
        await expect.ExpectAsync("two", Timeout());

        await Assert.That(stream.Reads).IsEqualTo(reads);
    }

    [Test]
    public async Task ACharacterSplitAcrossReads_IsDecodedWhole()
    {
        // "é" is C3 A9 in UTF-8; "€" is E2 82 AC.
        var stream = new ScriptedStream([[(byte)'c', (byte)'a', (byte)'f', 0xC3], [0xA9, (byte)' ', 0xE2], [0x82], [0xAC, (byte)'!']]);
        var expect = new SshExpect(stream, new MemoryStream());

        var match = await expect.ExpectAsync("é €!", Timeout());

        await Assert.That(match.Before).IsEqualTo("caf");
    }

    [Test]
    public async Task InvalidBytes_BecomeReplacementCharacters_AndMatchingGoesOn()
    {
        // SSH.NET's ShellStream.Expect discarded too much on undecodable bytes (its issue 1839); here they are kept as U+FFFD.
        var stream = new ScriptedStream([[(byte)'a', 0xFF, 0xFE, (byte)'b'], Encoding.UTF8.GetBytes("prompt> ")]);
        var expect = new SshExpect(stream, new MemoryStream());

        var match = await expect.ExpectAsync("prompt> ", Timeout());

        await Assert.That(match.Before).IsEqualTo("a��b");
    }

    [Test]
    public async Task ARegex_ReturnsItsGroups()
    {
        var expect = Over("build 12", "34 finished with status ", "0\n$ ");

        var match = await expect.ExpectAsync(new Regex(@"build (\d+) finished with status (\d+)\n"), Timeout());

        await Assert.That(match.Match!.Groups[1].Value).IsEqualTo("1234");
        await Assert.That(match.Match.Groups[2].Value).IsEqualTo("0");
        await Assert.That(expect.Pending).IsEqualTo("$ "); // read with the match, and kept for the next call
        await Assert.That((await expect.ExpectAsync("$ ", Timeout())).Before).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task OutputThatEnds_WithoutTheText_ThrowsAndKeepsWhatCame()
    {
        var expect = Over("partial output");

        await Assert.That(async () => await expect.ExpectAsync("never", Timeout())).Throws<EndOfStreamException>();
        await Assert.That(expect.Pending).IsEqualTo("partial output");
        await Assert.That((await expect.ExpectAsync("output", Timeout())).Before).IsEqualTo("partial ");
    }

    [Test]
    public async Task Cancelling_LosesNothing()
    {
        var stream = new ScriptedStream([Encoding.UTF8.GetBytes("waiting...")], endAfter: false);
        var expect = new SshExpect(stream, new MemoryStream());
        using var soon = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Assert.That(async () => await expect.ExpectAsync("done", soon.Token)).Throws<OperationCanceledException>();

        await Assert.That(expect.Pending).IsEqualTo("waiting...");
        await Assert.That((await expect.ExpectAsync("...", Timeout())).Before).IsEqualTo("waiting");
    }

    [Test]
    public async Task TheBuffer_IsBounded_KeepingTheNewestOutput()
    {
        var chunks = Enumerable.Range(0, 10).Select(i => new string((char)('a' + i), 100)).ToArray();
        var expect = new SshExpect(new ScriptedStream(chunks.Select(Encoding.UTF8.GetBytes)), new MemoryStream()) { MaxBufferLength = 150 };

        await Assert.That(async () => await expect.ExpectAsync("never", Timeout())).Throws<EndOfStreamException>();

        await Assert.That(expect.Pending).IsEqualTo(new string('i', 50) + new string('j', 100));
    }

    [Test]
    public async Task ReadLine_ReturnsLinesWithoutTheirEndings_AcrossReads_ThenTheRest_ThenNull()
    {
        // A terminal's \r\n and a plain \n; a line split across reads, and a \r\n split between them; a lone \r stays in its line.
        var expect = Over("uptime\r\n 10:19", " up 1 day\r", "\nsecond\nprogress 50%\rprogress 100%\n", "no newline at the end");

        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo("uptime");
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo(" 10:19 up 1 day");
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo("second");
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo("progress 50%\rprogress 100%");
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo("no newline at the end");
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsNull();
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsNull();
    }

    [Test]
    public async Task ReadLine_AndExpect_ShareTheBuffer()
    {
        // Wait for the prompt, send, then read what came back line by line: nothing is lost between the two kinds of read.
        var input = new MemoryStream();
        var expect = new SshExpect(new ScriptedStream(new[] { "Password: ", "\r\nWelcome\r\n$ " }.Select(Encoding.UTF8.GetBytes)), input);

        await expect.ExpectAsync("Password: ", Timeout());
        await expect.SendLineAsync("secret", Timeout());
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo(string.Empty); // the rest of the prompt's line
        await Assert.That(await expect.ReadLineAsync(Timeout())).IsEqualTo("Welcome");
        await Assert.That((await expect.ExpectAsync("$ ", Timeout())).Before).IsEqualTo(string.Empty);
        await Assert.That(Encoding.UTF8.GetString(input.ToArray())).IsEqualTo("secret\n");
    }

    [Test]
    public async Task ReadLine_ThatIsCancelled_KeepsThePartialLine()
    {
        var expect = new SshExpect(new ScriptedStream(new[] { "partial" }.Select(Encoding.UTF8.GetBytes), endAfter: false), new MemoryStream());
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Assert.That(async () => await expect.ReadLineAsync(cancel.Token)).Throws<OperationCanceledException>();

        await Assert.That(expect.Pending).IsEqualTo("partial");
    }

    [Test]
    public async Task ReadLine_LongerThanTheBuffer_IsAnError_NotACutLine()
    {
        var expect = new SshExpect(new ScriptedStream(new[] { new string('a', 100), new string('b', 100), "\nnext\n" }.Select(Encoding.UTF8.GetBytes)), new MemoryStream())
        {
            MaxBufferLength = 150,
        };

        await Assert.That(async () => await expect.ReadLineAsync(Timeout())).Throws<InvalidDataException>().WithMessageContaining("MaxBufferLength");
    }

    [Test]
    public async Task SendLine_WritesTheLineAndTheNewLine()
    {
        var input = new MemoryStream();
        var expect = new SshExpect(new ScriptedStream([]), input, Encoding.Latin1) { NewLine = "\r" };

        await expect.SendLineAsync("café", Timeout());
        await expect.SendAsync("raw", Timeout());

        await Assert.That(input.ToArray()).IsEquivalentTo(Encoding.Latin1.GetBytes("café\rraw"));
    }

    [Test]
    public async Task AnyChunking_GivesTheSameMatches()
    {
        var text = "naïve café → prompt$ second ✓ prompt$ tail";
        var bytes = Encoding.UTF8.GetBytes(text);
        var random = new Random(1234);
        for (var run = 0; run < 300; run++)
        {
            var chunks = new List<byte[]>();
            for (var at = 0; at < bytes.Length;)
            {
                var size = Math.Min(random.Next(1, 6), bytes.Length - at);
                chunks.Add(bytes[at..(at + size)]);
                at += size;
            }

            var expect = new SshExpect(new ScriptedStream(chunks), new MemoryStream());
            var first = await expect.ExpectAsync("prompt$ ", Timeout());
            var second = await expect.ExpectAsync(new Regex(@"✓ prompt\$ "), Timeout());
            await Assert.That(first.Before).IsEqualTo("naïve café → ");
            await Assert.That(second.Before).IsEqualTo("second ");
            await Assert.That(async () => await expect.ExpectAsync("never", Timeout())).Throws<EndOfStreamException>();
            await Assert.That(expect.Pending).IsEqualTo("tail");
        }
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        var expect = Over("x");
        await Assert.That(async () => await expect.ExpectAsync(string.Empty)).Throws<ArgumentException>();
        await Assert.That(async () => await expect.ExpectAsync((Regex)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => new SshExpect(new MemoryStream(), new MemoryStream()) { MaxBufferLength = 0 }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SshExpect((SshSession)null!)).Throws<ArgumentNullException>();
    }
}
