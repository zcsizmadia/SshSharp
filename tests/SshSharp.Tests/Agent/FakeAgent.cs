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

    /// <summary>
    /// The extensions the agent lists for RFC 9987's <c>query</c>, or null for an agent that does not implement it. Answered with
    /// SSH_AGENT_EXTENSION_RESPONSE, or SSH_AGENT_SUCCESS when <see cref="QueryRepliesWithSuccess"/> is set (older OpenSSH agents).
    /// </summary>
    public string[]? Extensions { get; set; }

    public bool QueryRepliesWithSuccess { get; set; }

    /// <summary>The key blob of the last signing request answered for a raw identity.</summary>
    public byte[]? LastSignedBlob { get; private set; }

    /// <summary>The flags of every signing request.</summary>
    public List<uint> SignFlags { get; } = [];

    /// <summary>A session-bind@openssh.com request the agent received, and whether the host key's signature over the session id verified.</summary>
    public sealed record Binding(byte[] HostKey, byte[] SessionId, bool IsForwarding, bool SignatureValid);

    /// <summary>Every session binding received, in order.</summary>
    public List<Binding> Bindings { get; } = [];

    /// <summary>Answer session-bind with failure, as agents without the extension do (OpenSSH before 8.9, other agents).</summary>
    public bool RejectBinding { get; set; }

    /// <summary>
    /// Refuse to sign on a connection not bound to a session, as ssh-agent does for a destination-constrained key (<c>ssh-add -h</c>):
    /// "refusing use of destination-constrained key to sign on unbound connection".
    /// </summary>
    public bool RequireBinding { get; set; }

    /// <summary>The data of the last signing request.</summary>
    public byte[]? LastSignedData { get; private set; }

    /// <summary>The state of one agent connection: its session binding, which lasts as long as the connection.</summary>
    private sealed class ConnectionState
    {
        public Binding? Bound { get; set; }
    }

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
            var state = new ConnectionState();
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
                var reply = RawReply ?? Handle(request, state);
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

    private byte[] Handle(byte[] request, ConnectionState state)
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

                LastSignedData = data;
                if (RequireBinding && state.Bound is null)
                {
                    return [5];
                }

                var key = Keys.Select(k => k.Key).FirstOrDefault(k => k.PublicKey.Span.SequenceEqual(blob));
                if (key is null && ClaimAlgorithm is { } rawClaim && RawIdentities.Any(raw => raw.AsSpan().SequenceEqual(blob)))
                {
                    // A raw identity the agent cannot really sign for (a security key, say): answer as such an agent would, with a
                    // signature of the claimed algorithm, so the client's handling of the reply can be checked.
                    LastSignedBlob = blob;
                    return Build(w =>
                    {
                        w.WriteByte(14);
                        w.WriteString(Build(s => { s.WriteString(rawClaim); s.WriteString(new byte[64]); }));
                    });
                }

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

            case 27:
            {
                var extension = reader.ReadUtf8String();
                if (extension == "query" && Extensions is { } extensions)
                {
                    return Build(w =>
                    {
                        w.WriteByte(QueryRepliesWithSuccess ? (byte)6 : (byte)29);
                        w.WriteString("query");
                        foreach (var name in extensions)
                        {
                            w.WriteString(name);
                        }
                    });
                }

                if (extension == "session-bind@openssh.com" && !RejectBinding)
                {
                    // As ssh-agent does: verify the host key's signature over the session id; one binding per connection.
                    var hostKey = reader.ReadString().ToArray();
                    var sessionId = reader.ReadString().ToArray();
                    var signature = reader.ReadString().ToArray();
                    var forwarding = reader.ReadBoolean();
                    var plain = global::SshSharp.SshCertificate.IsCertificateAlgorithm(new SshReader(hostKey).ReadUtf8String())
                        ? global::SshSharp.SshCertificate.FromBlob(hostKey).Key
                        : global::SshSharp.Keys.SshPublicKey.Parse(hostKey);
                    var signatureAlgorithm = new SshReader(signature).ReadUtf8String();
                    var binding = new Binding(hostKey, sessionId, forwarding, plain.VerifySignature(signatureAlgorithm, signature, sessionId));
                    lock (Bindings)
                    {
                        Bindings.Add(binding);
                    }

                    if (!binding.SignatureValid || state.Bound is not null)
                    {
                        return [5];
                    }

                    state.Bound = binding;
                    return [6];
                }

                return [5];
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
