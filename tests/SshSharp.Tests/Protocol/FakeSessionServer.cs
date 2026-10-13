using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>What a scripted command can do once the client has asked to run it.</summary>
internal sealed class ExecScript(FakeSessionServer server, FakeSessionServer.ServerChannel channel, string command)
{
    public string Command { get; } = command;

    /// <summary>Sends stdout, pausing whenever the client's receive window is exhausted (as a real server must).</summary>
    public Task StdoutAsync(byte[] data) => server.SendDataAsync(channel, data, extended: false);

    public Task StderrAsync(byte[] data) => server.SendDataAsync(channel, data, extended: true);

    public Task ExitStatusAsync(uint status) => server.SendRequestAsync(channel, "exit-status", w => w.WriteUInt32(status));

    public Task ExitSignalAsync(string signal) => server.SendRequestAsync(channel, "exit-signal", w =>
    {
        w.WriteString(signal);
        w.WriteBoolean(false);
        w.WriteString(string.Empty);
        w.WriteString(string.Empty);
    });

    public Task EofAsync() => server.SendChannelAsync(SshMessage.ChannelEof, channel);

    public Task CloseAsync() => server.SendChannelAsync(SshMessage.ChannelClose, channel);

    /// <summary>The usual ending: exit status, EOF, then CLOSE.</summary>
    public async Task FinishAsync(uint status)
    {
        await ExitStatusAsync(status);
        await EofAsync();
        await CloseAsync();
    }
}

/// <summary>
/// An in-memory SSH server that handles the service request, user authentication and channels, so client features can be tested
/// without a real sshd. Commands are scripted with <see cref="OnExec"/>.
/// </summary>
internal sealed class FakeSessionServer : IAsyncDisposable
{
    internal sealed class ServerChannel(uint id)
    {
        public uint Id { get; } = id;

        public uint ClientId { get; set; }

        public long ClientWindow { get; set; }

        public uint ClientMaxPacket { get; set; }

        public bool CloseReceived { get; set; }

        public bool CloseSent { get; set; }

        public SemaphoreSlim WindowChanged { get; } = new(0);

        /// <summary>For a direct-tcpip channel: the connection the server relays the channel to.</summary>
        public Stream? Tunnel { get; set; }
    }

    private readonly FakeSshServer _server;
    private readonly Dictionary<uint, ServerChannel> _channels = [];
    private readonly CancellationTokenSource _cts = new();
    private uint _nextId;
    private Task? _loop;

    public FakeSessionServer(FakeServerOptions? options = null) => _server = new FakeSshServer(options);

    public Stream ClientStream => _server.ClientStream;

    public FakeSshServer Raw => _server;

    public string Password { get; init; } = "secret";

    public string UserName { get; init; } = "tester";

    public bool AllowNone { get; init; }

    public string[] AdvertisedMethods { get; init; } = ["password"];

    /// <summary>Refuse the exec request.</summary>
    public bool RefuseExec { get; init; }

    /// <summary>Refuse to open channels.</summary>
    public bool RefuseChannels { get; init; }

    /// <summary>The window and maximum packet size the server advertises for its own receiving.</summary>
    public uint ServerWindow { get; init; } = 2 * 1024 * 1024;

    public uint ServerMaxPacket { get; init; } = 32768;

    /// <summary>Ignore the client's window and send data regardless (protocol violation).</summary>
    public bool IgnoreClientWindow { get; init; }

    public Func<ExecScript, Task> OnExec { get; set; } = script => script.FinishAsync(0);

    public List<string> Commands { get; } = [];

    public List<byte[]> Unrecognized { get; } = [];

    public List<byte[]> ReceivedData { get; } = [];

    public bool UnimplementedReceived { get; private set; }

    public bool GlobalFailureReceived { get; private set; }

    /// <summary>Where direct-tcpip channels go: return a stream to relay to (for example another fake server), or null to refuse.</summary>
    public Func<string, int, Stream?>? DirectTcpIp { get; set; }

    /// <summary>The host:port of every direct-tcpip channel the client asked for.</summary>
    public List<string> DirectTcpIpRequests { get; } = [];

    /// <summary>Names of the global requests the client sent, in order.</summary>
    public List<string> GlobalRequests { get; } = [];

    /// <summary>Never answer global requests (a server that has stopped responding).</summary>
    public bool IgnoreGlobalRequests { get; set; }

    /// <summary>A certificate authority's public key: user certificates it signed are accepted (sshd's TrustedUserCAKeys).</summary>
    public byte[]? TrustedUserAuthority { get; init; }

    /// <summary>Public keys (SSH wire format) the server accepts for <see cref="UserName"/>.</summary>
    public List<byte[]> AuthorizedKeys { get; init; } = [];

    /// <summary>Require publickey and then password (partial success after the key), like <c>AuthenticationMethods publickey,password</c>.</summary>
    public bool RequirePasswordAfterPublicKey { get; init; }

    /// <summary>Every authentication method the client tried, in order; signed publickey attempts add "publickey-signed:alg".</summary>
    public List<string> AuthAttempts { get; } = [];

    private bool _publicKeyDone;

    /// <summary>When set, channel opens are answered only after this task completes (to race the client's cancellation).</summary>
    public Task? HoldChannelOpen { get; set; }

    /// <summary>A snapshot of the channels the client has opened.</summary>
    public IReadOnlyList<ServerChannel> Channels
    {
        get
        {
            lock (_channels)
            {
                return [.. _channels.Values];
            }
        }
    }

    public Task StartAsync()
    {
        var handshake = _server.StartAsync(_cts.Token);
        _loop = Task.Run(async () =>
        {
            await handshake;
            await LoopAsync();
        });
        return handshake;
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();

        // The client is gone, so nothing reads the server-to-client pipe any more: a script blocked writing into it holds the send lock,
        // and the loop may be waiting for that lock to answer a CLOSE. Closing the client's ends releases every blocked writer first.
        _server.ClientStream.Dispose();
        if (_loop is not null)
        {
            try
            {
                await _loop;
            }
            catch (Exception)
            {
                // The loop ends with whatever error the closed pipe produces.
            }
        }

        await _server.DisposeAsync();
        _cts.Dispose();
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            DecodedPacket packet;
            try
            {
                packet = await _server.ReceiveAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or EndOfStreamException or InvalidOperationException)
            {
                return;
            }

            using (packet)
            {
                await HandleAsync(packet.Payload);
            }
        }
    }

    private async Task HandleAsync(ReadOnlyMemory<byte> payloadMemory)
    {
        var payload = payloadMemory.ToArray();
        var reader = new SshReader(payload);
        var type = reader.ReadByte();
        switch (type)
        {
            case SshMessage.ServiceRequest:
            {
                var name = reader.ReadUtf8String();
                await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.ServiceAccept); w.WriteString(name); }));
                break;
            }

            case SshMessage.UserAuthRequest:
            {
                var user = reader.ReadUtf8String();
                reader.ReadUtf8String();
                var method = reader.ReadUtf8String();
                lock (AuthAttempts)
                {
                    AuthAttempts.Add(method);
                }

                bool ok;
                if (method == "publickey")
                {
                    var hasSignature = reader.ReadBoolean();
                    var algorithm = reader.ReadUtf8String();
                    var blob = reader.ReadString().ToArray();
                    var authorized = user == UserName && (AuthorizedKeys.Any(k => k.AsSpan().SequenceEqual(blob)) || CertificateTrusted(algorithm, blob, user));
                    if (!hasSignature)
                    {
                        // RFC 4252 section 7: PK_OK says "this key would do; now sign".
                        if (authorized)
                        {
                            await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.UserAuthPkOk); w.WriteString(algorithm); w.WriteString(blob); }));
                        }
                        else
                        {
                            await SendAuthFailureAsync(AdvertisedMethods, partial: false);
                        }

                        break;
                    }

                    var signature = reader.ReadString().ToArray();
                    ok = authorized && SignatureValid(user, algorithm, blob, signature);
                    if (ok)
                    {
                        lock (AuthAttempts)
                        {
                            AuthAttempts.Add("publickey-signed:" + algorithm);
                        }
                    }

                    if (ok && RequirePasswordAfterPublicKey && !_publicKeyDone)
                    {
                        _publicKeyDone = true;
                        await SendAuthFailureAsync(["password"], partial: true);
                        break;
                    }
                }
                else
                {
                    ok = user == UserName && ((method == "none" && AllowNone)
                        || (method == "password" && PasswordMatches(ref reader) && (!RequirePasswordAfterPublicKey || _publicKeyDone)));
                }

                if (ok)
                {
                    await _server.SendAsync(new byte[] { SshMessage.UserAuthSuccess });
                }
                else
                {
                    await SendAuthFailureAsync(RequirePasswordAfterPublicKey && _publicKeyDone ? ["password"] : AdvertisedMethods, partial: false);
                }

                break;
            }

            case SshMessage.GlobalRequest:
            {
                var name = reader.ReadUtf8String();
                lock (GlobalRequests)
                {
                    GlobalRequests.Add(name);
                }

                // Like OpenSSH: unknown requests (keepalive@openssh.com included) get a failure, which is still an answer.
                if (reader.ReadBoolean() && !IgnoreGlobalRequests)
                {
                    await _server.SendAsync(new byte[] { SshMessage.RequestFailure });
                }

                break;
            }

            case SshMessage.RequestFailure:
                GlobalFailureReceived = true;
                break;

            case SshMessage.Unimplemented:
                UnimplementedReceived = true;
                break;

            case SshMessage.ChannelOpen:
            {
                var channelType = reader.ReadUtf8String();
                var clientId = reader.ReadUInt32();
                var window = reader.ReadUInt32();
                var maxPacket = reader.ReadUInt32();
                var tunnelHost = channelType == "direct-tcpip" ? reader.ReadUtf8String() : null;
                var tunnelPort = channelType == "direct-tcpip" ? (int)reader.ReadUInt32() : 0;
                if (RefuseChannels)
                {
                    await _server.SendAsync(Build(w =>
                    {
                        w.WriteByte(SshMessage.ChannelOpenFailure);
                        w.WriteUInt32(clientId);
                        w.WriteUInt32(2);
                        w.WriteString("administratively prohibited");
                        w.WriteString(string.Empty);
                    }));
                    break;
                }

                if (HoldChannelOpen is { } hold)
                {
                    await hold.WaitAsync(_cts.Token);
                }

                // direct-tcpip (RFC 4254 section 7.2): connect to host:port and relay, like sshd does for ProxyJump.
                Stream? tunnel = null;
                if (tunnelHost is not null)
                {
                    lock (DirectTcpIpRequests)
                    {
                        DirectTcpIpRequests.Add($"{tunnelHost}:{tunnelPort}");
                    }

                    tunnel = DirectTcpIp?.Invoke(tunnelHost, tunnelPort);
                    if (tunnel is null)
                    {
                        await _server.SendAsync(Build(w =>
                        {
                            w.WriteByte(SshMessage.ChannelOpenFailure);
                            w.WriteUInt32(clientId);
                            w.WriteUInt32(2);
                            w.WriteString("connect failed");
                            w.WriteString(string.Empty);
                        }));
                        break;
                    }
                }

                var channel = new ServerChannel(_nextId++) { ClientId = clientId, ClientWindow = window, ClientMaxPacket = maxPacket, Tunnel = tunnel };
                lock (_channels)
                {
                    _channels[channel.Id] = channel;
                }

                await _server.SendAsync(Build(w =>
                {
                    w.WriteByte(SshMessage.ChannelOpenConfirmation);
                    w.WriteUInt32(clientId);
                    w.WriteUInt32(channel.Id);
                    w.WriteUInt32(ServerWindow);
                    w.WriteUInt32(ServerMaxPacket);
                }));

                if (tunnel is not null)
                {
                    _ = Task.Run(() => PumpTunnelAsync(channel, tunnel));
                }

                break;
            }

            case SshMessage.ChannelRequest:
            {
                var channel = Find(reader.ReadUInt32());
                var requestType = reader.ReadUtf8String();
                var wantReply = reader.ReadBoolean();
                if (requestType == "exec" && !RefuseExec)
                {
                    var command = reader.ReadUtf8String();
                    lock (Commands)
                    {
                        Commands.Add(command);
                    }

                    if (wantReply)
                    {
                        await SendChannelAsync(SshMessage.ChannelSuccess, channel);
                    }

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await OnExec(new ExecScript(this, channel, command));
                        }
                        catch (Exception)
                        {
                            // The client went away mid-script.
                        }
                    });
                }
                else if (wantReply)
                {
                    await SendChannelAsync(SshMessage.ChannelFailure, channel);
                }

                break;
            }

            case SshMessage.ChannelWindowAdjust:
            {
                var channel = Find(reader.ReadUInt32());
                lock (channel)
                {
                    channel.ClientWindow += reader.ReadUInt32();
                }

                channel.WindowChanged.Release();
                break;
            }

            case SshMessage.ChannelData:
            {
                var channel = Find(reader.ReadUInt32());
                var data = reader.ReadString().ToArray();
                if (channel.Tunnel is { } tunnel)
                {
                    await tunnel.WriteAsync(data);
                    await tunnel.FlushAsync();
                    break;
                }

                lock (ReceivedData)
                {
                    ReceivedData.Add(data);
                }

                break;
            }

            case SshMessage.ChannelEof:
                break;

            case SshMessage.ChannelClose:
            {
                var channel = Find(reader.ReadUInt32());
                channel.CloseReceived = true;
                if (channel.Tunnel is { } closing)
                {
                    channel.Tunnel = null;
                    await closing.DisposeAsync();
                }

                if (!channel.CloseSent)
                {
                    await SendChannelAsync(SshMessage.ChannelClose, channel);
                }

                break;
            }

            default:
                lock (Unrecognized)
                {
                    Unrecognized.Add(payload);
                }

                break;
        }
    }

    /// <summary>Relays what the tunnel's far end sends back to the client as channel data, then EOF and CLOSE when it ends.</summary>
    private async Task PumpTunnelAsync(ServerChannel channel, Stream tunnel)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (await tunnel.ReadAsync(buffer, _cts.Token) is var read and > 0)
            {
                await SendDataAsync(channel, buffer[..read], extended: false);
            }

            await SendChannelAsync(SshMessage.ChannelEof, channel);
            if (!channel.CloseSent)
            {
                await SendChannelAsync(SshMessage.ChannelClose, channel);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or IOException or InvalidOperationException or SshException)
        {
            // The client or the far end went away.
        }
    }

    private Task SendAuthFailureAsync(string[] methods, bool partial) =>
        _server.SendAsync(Build(w => { w.WriteByte(SshMessage.UserAuthFailure); w.WriteNameList(methods); w.WriteBoolean(partial); })).AsTask();

    /// <summary>Like sshd's TrustedUserCAKeys: a user certificate from <see cref="TrustedUserAuthority"/>, valid now, naming the user.</summary>
    private bool CertificateTrusted(string algorithm, byte[] blob, string user)
    {
        if (TrustedUserAuthority is not { } authority || !SshCertificate.IsCertificateAlgorithm(algorithm))
        {
            return false;
        }

        try
        {
            var certificate = SshCertificate.FromBlob(blob);
            var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return certificate.Type == SshCertificateType.User
                && certificate.AuthorityKey.Span.SequenceEqual(authority)
                && certificate.HasValidAuthoritySignature()
                && now >= certificate.ValidAfterSeconds && now < certificate.ValidBeforeSeconds
                && certificate.Principals.Contains(user);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    /// <summary>Checks a publickey signature exactly as a server must: over the session id and the request.</summary>
    private bool SignatureValid(string user, string algorithm, byte[] blob, byte[] signature)
    {
        var signed = Build(w =>
        {
            w.WriteString(_server.SessionId!);
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(user);
            w.WriteString("ssh-connection");
            w.WriteString("publickey");
            w.WriteBoolean(true);
            w.WriteString(algorithm);
            w.WriteString(blob);
        });
        try
        {
            return SshCertificate.IsCertificateAlgorithm(algorithm)
                ? SshCertificate.FromBlob(blob).Key.VerifySignature(SshCertificate.BaseAlgorithm(algorithm), signature, signed)
                : SshSharp.Keys.SshPublicKey.Parse(blob).VerifySignature(algorithm, signature, signed);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    private bool PasswordMatches(ref SshReader reader)
    {
        reader.ReadBoolean();
        return reader.ReadUtf8String() == Password;
    }

    private ServerChannel Find(uint id)
    {
        lock (_channels)
        {
            return _channels[id];
        }
    }

    internal async Task SendChannelAsync(byte type, ServerChannel channel)
    {
        if (type == SshMessage.ChannelClose)
        {
            channel.CloseSent = true;
        }

        await _server.SendAsync(Build(w => { w.WriteByte(type); w.WriteUInt32(channel.ClientId); }));
    }

    internal async Task SendRequestAsync(ServerChannel channel, string type, Action<SshWriter> body)
    {
        await _server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelRequest);
            w.WriteUInt32(channel.ClientId);
            w.WriteString(type);
            w.WriteBoolean(false);
            body(w);
        }));
    }

    internal async Task SendDataAsync(ServerChannel channel, byte[] data, bool extended)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            var take = (int)Math.Min(data.Length - offset, channel.ClientMaxPacket);
            if (!IgnoreClientWindow)
            {
                while (true)
                {
                    lock (channel)
                    {
                        if (channel.ClientWindow >= take)
                        {
                            channel.ClientWindow -= take;
                            break;
                        }
                    }

                    await channel.WindowChanged.WaitAsync(_cts.Token);
                }
            }

            var chunk = data.AsMemory(offset, take);
            await _server.SendAsync(Build(w =>
            {
                w.WriteByte(extended ? SshMessage.ChannelExtendedData : SshMessage.ChannelData);
                w.WriteUInt32(channel.ClientId);
                if (extended)
                {
                    w.WriteUInt32(1);
                }

                w.WriteString(chunk.Span);
            }));
            offset += take;
        }
    }

    /// <summary>Sends a raw message to the client (to inject protocol violations).</summary>
    public ValueTask SendRawAsync(byte[] payload) => _server.SendAsync(payload);

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }
}