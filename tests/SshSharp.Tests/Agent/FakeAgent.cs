using System.Buffers;
using System.Buffers.Binary;
using System.Net.Sockets;
using SshSharp.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>
/// An ssh-agent on a Unix domain socket (Windows 10 and later have them too), holding local keys and signing with them. Switches make it
/// misbehave the ways real agents do.
/// </summary>
internal sealed class FakeAgent : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public FakeAgent()
    {
        // Short: socket paths are limited to about 100 characters.
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ssa-" + Guid.NewGuid().ToString("N")[..12]);
        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(Path));
        _listener.Listen(16);
        _loop = Task.Run(AcceptLoopAsync);
    }

    public string Path { get; }

    /// <summary>The keys the agent holds, with their comments.</summary>
    public List<(SshPrivateKey Key, string Comment)> Keys { get; } = [];

    /// <summary>Extra raw identities listed as they are (unsupported types, for example).</summary>
    public List<byte[]> RawIdentities { get; } = [];

    /// <summary>Refuse to sign with keys whose fingerprint is listed (a removed key, or a declined confirmation).</summary>
    public HashSet<string> RefuseToSign { get; } = [];

    /// <summary>Answer signing requests with a signature claiming this algorithm (an agent that ignores the RSA flags).</summary>
    public string? ClaimAlgorithm { get; set; }

    /// <summary>Replace the reply to every request (a broken agent).</summary>
    public byte[]? RawReply { get; set; }

    /// <summary>The flags of every signing request.</summary>
    public List<uint> SignFlags { get; } = [];

    public int Connections { get; private set; }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket connection;
            try
            {
                connection = await _listener.AcceptAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Connections++;
            _ = Task.Run(() => ServeAsync(connection));
        }
    }

    private async Task ServeAsync(Socket connection)
    {
        await using var stream = new NetworkStream(connection, ownsSocket: true);
        try
        {
            var header = new byte[4];
            while (true)
            {
                try
                {
                    await stream.ReadExactlyAsync(header, _cts.Token);
                }
                catch (EndOfStreamException)
                {
                    return;
                }

                var request = new byte[BinaryPrimitives.ReadUInt32BigEndian(header)];
                await stream.ReadExactlyAsync(request, _cts.Token);
                var reply = RawReply ?? Handle(request);
                if (RawReply is null)
                {
                    var frame = new byte[4 + reply.Length];
                    BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)reply.Length);
                    reply.CopyTo(frame, 4);
                    reply = frame;
                }

                await stream.WriteAsync(reply, _cts.Token);
                if (RawReply is not null)
                {
                    return; // and hang up: a reply cut short must not leave the client waiting
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
        {
            // The client went away.
        }
    }

    private byte[] Handle(byte[] request)
    {
        var reader = new SshReader(request);
        switch (reader.ReadByte())
        {
            case 11:
                return Build(w =>
                {
                    w.WriteByte(12);
                    w.WriteUInt32((uint)(Keys.Count + RawIdentities.Count));
                    foreach (var (key, comment) in Keys)
                    {
                        w.WriteString(key.PublicKey.Span);
                        w.WriteString(comment);
                    }

                    foreach (var raw in RawIdentities)
                    {
                        w.WriteString(raw);
                        w.WriteString("raw");
                    }
                });

            case 13:
            {
                var blob = reader.ReadString().ToArray();
                var data = reader.ReadString().ToArray();
                var flags = reader.ReadUInt32();
                lock (SignFlags)
                {
                    SignFlags.Add(flags);
                }

                var key = Keys.Select(k => k.Key).FirstOrDefault(k => k.PublicKey.Span.SequenceEqual(blob));
                if (key is null || RefuseToSign.Contains(key.Fingerprint))
                {
                    return [5];
                }

                var plainType = SshCertificate.BaseAlgorithm(key.KeyType);
                var algorithm = plainType == "ssh-rsa" ? (flags & 4) != 0 ? "rsa-sha2-512" : "rsa-sha2-256" : plainType;
                var signature = ClaimAlgorithm is { } claimed
                    ? Build(w => { w.WriteString(claimed); w.WriteString(new byte[64]); })
                    : key.Sign(key.Certificate is null ? algorithm : algorithm + "-cert-v01@openssh.com", data);
                return Build(w =>
                {
                    w.WriteByte(14);
                    w.WriteString(signature);
                });
            }

            default:
                return [5];
        }
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Dispose();
        try
        {
            await _loop;
        }
        catch (Exception)
        {
            // Stopped.
        }

        File.Delete(Path);
        _cts.Dispose();
    }
}
