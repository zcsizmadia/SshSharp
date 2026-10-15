using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Disposing a session or a tunnel while another task reads it (#188): the reader may fail, but it must never get bytes from a buffer
/// that disposal has already given back to the pool (which zeroes it), nor crash on the chunk being taken from under it.
/// </summary>
public class SessionDisposeRaceTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>Output that is never zero, in small chunks like SFTP replies, until the channel closes.</summary>
    private static async Task StreamAsync(ExecScript script)
    {
        var chunk = Enumerable.Repeat((byte)'x', 26).ToArray();
        try
        {
            while (true)
            {
                await script.StdoutAsync(chunk);
            }
        }
        catch (Exception)
        {
            // The client closed the channel.
        }
    }

    [Test]
    public async Task DisposingASession_WhileItsOutputIsRead_NeverHandsTheReaderReleasedBytes()
    {
        await using var server = new FakeSessionServer { OnExec = StreamAsync };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());

        var reportsBefore = Instrumentation.Reports;
        var zeros = 0L;
        for (var round = 0; round < 200; round++)
        {
            var session = await client.StartCommandAsync("stream", cancellationToken: Timeout());
            var reader = Task.Run(async () =>
            {
                var buffer = new byte[64];
                try
                {
                    while (true)
                    {
                        var n = await session.StandardOutput.ReadAsync(buffer);
                        if (n == 0)
                        {
                            return;
                        }

                        Interlocked.Add(ref zeros, buffer.AsSpan(0, n).Count((byte)0));
                    }
                }
                catch (Exception ex) when (ex is ObjectDisposedException or SshException or OperationCanceledException)
                {
                    // Disposed under the read: an error is fine, wrong bytes are not.
                }
            });

            await Task.Delay(round % 5);
            await session.DisposeAsync();
            await reader.WaitAsync(Timeout());
        }

        await Assert.That(zeros).IsEqualTo(0);
        await Assert.That(Instrumentation.Reports).IsEqualTo(reportsBefore);
    }

    [Test]
    public async Task DisposingATunnel_WhileItIsRead_NeverHandsTheReaderReleasedBytes()
    {
        await using var server = new FakeSessionServer { DirectTcpIp = (_, _) => new EndlessStream() };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = "secret",
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());

        var reportsBefore = Instrumentation.Reports;
        var zeros = 0L;
        for (var round = 0; round < 200; round++)
        {
            var tunnel = await client.OpenTcpTunnelAsync("service.internal", 80, Timeout());
            var reader = Task.Run(async () =>
            {
                var buffer = new byte[64];
                try
                {
                    while (await tunnel.ReadAsync(buffer) is var n and > 0)
                    {
                        Interlocked.Add(ref zeros, buffer.AsSpan(0, n).Count((byte)0));
                    }
                }
                catch (Exception ex) when (ex is ObjectDisposedException or SshException or OperationCanceledException)
                {
                    // Disposed under the read: an error is fine, wrong bytes are not.
                }
            });

            await Task.Delay(round % 5);
            await tunnel.DisposeAsync();
            await reader.WaitAsync(Timeout());
        }

        await Assert.That(zeros).IsEqualTo(0);
        await Assert.That(Instrumentation.Reports).IsEqualTo(reportsBefore);
    }

    /// <summary>A service that sends 'x' in small pieces for as long as it is read, until it is closed.</summary>
    private sealed class EndlessStream : Stream
    {
        private volatile bool _closed;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => Fill(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Fill(buffer.Span));

        private int Fill(Span<byte> buffer)
        {
            if (_closed)
            {
                return 0;
            }

            var n = Math.Min(buffer.Length, 26);
            buffer[..n].Fill((byte)'x');
            return n;
        }

        protected override void Dispose(bool disposing)
        {
            _closed = true;
            base.Dispose(disposing);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
        }
    }
}
