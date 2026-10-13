using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>What a scripted command can do once the client has asked to run it.</summary>
internal sealed class ExecScript(FakeSessionServer server, FakeSessionServer.ServerChannel channel, string command)
{
    public string Command { get; } = command;

    // Script messages are dropped once the server has sent CLOSE, as a real server sends nothing after it (see SendOnChannelAsync).

    /// <summary>Sends stdout, pausing whenever the client's receive window is exhausted (as a real server must).</summary>
    public Task StdoutAsync(byte[] data) => server.SendDataAsync(channel, data, extended: false, fromScript: true);

    public Task StderrAsync(byte[] data) => server.SendDataAsync(channel, data, extended: true, fromScript: true);

    public Task ExitStatusAsync(uint status) => server.SendRequestAsync(channel, "exit-status", w => w.WriteUInt32(status), fromScript: true);

    public Task ExitSignalAsync(string signal) => server.SendRequestAsync(channel, "exit-signal", w =>
    {
        w.WriteString(signal);
        w.WriteBoolean(false);
        w.WriteString(string.Empty);
        w.WriteString(string.Empty);
    }, fromScript: true);

    /// <summary>The next data the client sent on the channel, or null once it sent EOF.</summary>
    public async Task<byte[]?> ReadInputAsync(CancellationToken cancellationToken = default)
    {
        while (await channel.Input.Reader.WaitToReadAsync(cancellationToken))
        {
            if (channel.Input.Reader.TryRead(out var data))
            {
                return data;
            }
        }

        return null;
    }

    /// <summary>Lets the client send <paramref name="bytes"/> more (SSH_MSG_CHANNEL_WINDOW_ADJUST), as a server does after consuming input.</summary>
    public Task GrantWindowAsync(uint bytes) => server.SendRawAsync(Build(w =>
    {
        w.WriteByte(SshMessage.ChannelWindowAdjust);
        w.WriteUInt32(channel.ClientId);
        w.WriteUInt32(bytes);
    })).AsTask();

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>The channel requests the client sent before and while the program runs.</summary>
    public FakeSessionServer.ChannelRequestRecord[] Requests
    {
        get
        {
            lock (channel.Requests)
            {
                return [.. channel.Requests];
            }
        }
    }

    public Task EofAsync() => server.SendChannelAsync(SshMessage.ChannelEof, channel, fromScript: true);

    public Task CloseAsync() => server.SendChannelAsync(SshMessage.ChannelClose, channel, fromScript: true);

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

        /// <summary>Serializes the server's messages on this channel with its CLOSE handling.</summary>
        public SemaphoreSlim SendGate { get; } = new(1, 1);

        public volatile bool EofSent;

        public volatile bool EofReceived;

        /// <summary>For a channel the server opened: completes with whether the client accepted it.</summary>
        public TaskCompletionSource<bool>? Opened { get; init; }

        /// <summary>Data the client sent (stdin), completed at its EOF.</summary>
        public System.Threading.Channels.Channel<byte[]> Input { get; } = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();

        /// <summary>Every channel request the client sent, in order.</summary>
        public List<ChannelRequestRecord> Requests { get; } = [];

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

    /// <summary>Runs for a "shell" request (the script's command is empty).</summary>
    public Func<ExecScript, Task> OnShell { get; set; } = script => script.FinishAsync(0);

    /// <summary>Environment variable names the server accepts, like sshd's AcceptEnv; others are dropped.</summary>
    public string[] AcceptEnv { get; init; } = [];

    /// <summary>Refuse pty-req (a server with no terminals, or PermitTTY no).</summary>
    public bool RefusePty { get; init; }

    /// <summary>Refuse the shell request.</summary>
    public bool RefuseShell { get; init; }

    /// <summary>A channel request as the server parsed it: the type, its string and number arguments, and pty-req's encoded modes.</summary>
    internal sealed record ChannelRequestRecord(string Type, bool WantReply, string[] Args, byte[]? Modes = null);

    public List<string> Commands { get; } = [];

    public List<byte[]> Unrecognized { get; } = [];

    public List<byte[]> ReceivedData { get; } = [];

    public bool UnimplementedReceived { get; private set; }

    public bool GlobalFailureReceived { get; private set; }

    /// <summary>Where direct-tcpip channels go: return a stream to relay to (for example another fake server), or null to refuse.</summary>
    public Func<string, int, Stream?>? DirectTcpIp { get; set; }

    /// <summary>The host:port of every direct-tcpip channel the client asked for.</summary>
    public List<string> DirectTcpIpRequests { get; } = [];

    /// <summary>The originator address:port of every direct-tcpip channel.</summary>
    public List<string> DirectTcpIpOriginators { get; } = [];

    /// <summary>Where direct-streamlocal channels go: a stream to relay to, or null to refuse.</summary>
    public Func<string, Stream?>? DirectStreamLocal { get; set; }

    /// <summary>The socket path of every direct-streamlocal channel the client asked for.</summary>
    public List<string> DirectStreamLocalRequests { get; } = [];

    /// <summary>Refuse tcpip-forward (sshd's AllowTcpForwarding no).</summary>
    public bool RefuseRemoteForwarding { get; init; }

    /// <summary>Ports the client asked the server to listen on (tcpip-forward), with their bind addresses.</summary>
    public Dictionary<int, string> RemoteForwards { get; } = [];

    /// <summary>Ports the client cancelled (cancel-tcpip-forward).</summary>
    public List<int> CancelledRemoteForwards { get; } = [];

    /// <summary>
    /// Plays a connection arriving at a remotely forwarded port: opens a forwarded-tcpip channel to the client and returns the far end of
    /// it, or null when the client refuses the channel.
    /// </summary>
    public async Task<Stream?> ConnectForwardedAsync(int port, string connectedAddress = "localhost", string originator = "203.0.113.7", int originatorPort = 50123)
    {
        // The tunnel is attached before the open is sent: the client may confirm and close at once (nothing listening locally), and a
        // CLOSE handled before the tunnel was attached would leave the far end waiting forever.
        var (near, far) = DuplexStream.CreatePair();
        var channel = new ServerChannel(_nextId++) { Opened = new(TaskCreationOptions.RunContinuationsAsynchronously), Tunnel = near };
        lock (_channels)
        {
            _channels[channel.Id] = channel;
        }

        await _server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpen);
            w.WriteString("forwarded-tcpip");
            w.WriteUInt32(channel.Id);
            w.WriteUInt32(ServerWindow);
            w.WriteUInt32(ServerMaxPacket);
            w.WriteString(connectedAddress);
            w.WriteUInt32((uint)port);
            w.WriteString(originator);
            w.WriteUInt32((uint)originatorPort);
        }));
        if (!await channel.Opened!.Task.WaitAsync(TimeSpan.FromSeconds(30)))
        {
            await near.DisposeAsync();
            await far.DisposeAsync();
            return null;
        }

        _ = Task.Run(() => PumpTunnelAsync(channel, near));
        return far;
    }

    /// <summary>Host keys announced after authentication (hostkeys-00@openssh.com) and proven on request (UpdateHostKeys).</summary>
    public List<FakeHostKey>? AnnouncedHostKeys { get; init; }

    /// <summary>Send invalid proofs for hostkeys-prove-00@openssh.com (an impostor that cannot sign with the announced keys).</summary>
    public bool CorruptHostKeyProofs { get; init; }

    /// <summary>Prove RSA keys with SHA-1 "ssh-rsa" signatures, as OpenSSH before 8.x does when the host key in use is not RSA.</summary>
    public bool ProveRsaWithSha1 { get; init; }

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

    /// <summary>
    /// Methods that must all succeed in this order, like sshd's <c>AuthenticationMethods</c>: each one but the last gets a partial success,
    /// and failures list only the next method.
    /// </summary>
    public string[]? AuthenticationChain { get; init; }

    private int _chainStep;

    /// <summary>One keyboard-interactive round: what the server asks, and the answers it accepts.</summary>
    public sealed record KeyboardRound(string Name, string Instruction, (string Text, bool Echo)[] Prompts, string[] Answers);

    /// <summary>The keyboard-interactive rounds; the method succeeds when every round is answered as expected.</summary>
    public List<KeyboardRound> KeyboardInteractiveRounds { get; init; } = [];

    /// <summary>Keep sending this round forever (a server that never finishes).</summary>
    public bool EndlessKeyboardInteractive { get; init; }

    /// <summary>The answers the client sent, one list per round.</summary>
    public List<string[]> KeyboardInteractiveAnswers { get; } = [];

    private int _keyboardRound = -1;

    /// <summary>Sent as SSH_MSG_USERAUTH_BANNER before the first authentication reply.</summary>
    public string? AuthenticationBanner { get; init; }

    private bool _bannerSent;

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
        if (payload[0] == SshMessage.UserAuthRequest && AuthenticationBanner is { } bannerText && !_bannerSent)
        {
            // Before the first authentication reply, like sshd's Banner.
            _bannerSent = true;
            await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.UserAuthBanner); w.WriteString(bannerText); w.WriteString(""); }));
        }

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

                _keyboardRound = -1; // a new request abandons a keyboard-interactive exchange in progress (RFC 4252 section 5)
                bool ok;
                if (method == "keyboard-interactive")
                {
                    reader.ReadUtf8String(); // language tag
                    reader.ReadUtf8String(); // submethods
                    if (user != UserName || KeyboardInteractiveRounds.Count == 0)
                    {
                        await FinishAuthAsync(method, ok: false);
                        break;
                    }

                    _keyboardRound = 0;
                    await SendKeyboardRoundAsync(KeyboardInteractiveRounds[0]);
                    break;
                }

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
                            await SendAuthFailureAsync(CurrentMethods(), partial: false);
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

                await FinishAuthAsync(method, ok);
                break;
            }

            case SshMessage.UserAuthInfoResponse:
            {
                if (_keyboardRound < 0)
                {
                    throw new InvalidOperationException("INFO_RESPONSE without a keyboard-interactive exchange.");
                }

                var answers = new string[reader.ReadUInt32()];
                for (var i = 0; i < answers.Length; i++)
                {
                    answers[i] = reader.ReadUtf8String();
                }

                lock (KeyboardInteractiveAnswers)
                {
                    KeyboardInteractiveAnswers.Add(answers);
                }

                var round = KeyboardInteractiveRounds[_keyboardRound];
                if (EndlessKeyboardInteractive)
                {
                    await SendKeyboardRoundAsync(round);
                    break;
                }

                if (!answers.SequenceEqual(round.Answers))
                {
                    _keyboardRound = -1;
                    await FinishAuthAsync("keyboard-interactive", ok: false);
                    break;
                }

                if (++_keyboardRound < KeyboardInteractiveRounds.Count)
                {
                    await SendKeyboardRoundAsync(KeyboardInteractiveRounds[_keyboardRound]);
                    break;
                }

                _keyboardRound = -1;
                await FinishAuthAsync("keyboard-interactive", ok: true);
                break;
            }

            case SshMessage.GlobalRequest:
            {
                var name = reader.ReadUtf8String();
                lock (GlobalRequests)
                {
                    GlobalRequests.Add(name);
                }

                var wantReply = reader.ReadBoolean();
                if (name == "hostkeys-prove-00@openssh.com" && AnnouncedHostKeys is { } announced)
                {
                    // Prove possession of each requested key: sign "hostkeys-prove-00@openssh.com", the session id and the key.
                    var requested = new List<byte[]>();
                    while (!reader.IsEmpty)
                    {
                        requested.Add(reader.ReadString().ToArray());
                    }

                    var proofs = requested.Select(blob =>
                    {
                        var key = announced.First(k => k.Blob.AsSpan().SequenceEqual(blob));
                        var signed = Build(w => { w.WriteString(name); w.WriteString(_server.SessionId!); w.WriteString(blob); });
                        var signature = key.Sign(key.KeyType == "ssh-rsa" ? (ProveRsaWithSha1 ? "ssh-rsa" : "rsa-sha2-512") : key.KeyType, signed);
                        if (CorruptHostKeyProofs)
                        {
                            signature[^1] ^= 1;
                        }

                        return signature;
                    }).ToList();
                    await _server.SendAsync(Build(w =>
                    {
                        w.WriteByte(SshMessage.RequestSuccess);
                        foreach (var proof in proofs)
                        {
                            w.WriteString(proof);
                        }
                    }));
                    break;
                }

                if (name is "tcpip-forward" or "cancel-tcpip-forward")
                {
                    // RFC 4254 section 7.1: listen (port 0: pick one, and say which), or stop listening.
                    var address = reader.ReadUtf8String();
                    var port = (int)reader.ReadUInt32();
                    var ok = !RefuseRemoteForwarding;
                    var picked = 0;
                    lock (RemoteForwards)
                    {
                        if (name == "tcpip-forward" && ok)
                        {
                            picked = port == 0 ? 40000 + RemoteForwards.Count : port;
                            ok = RemoteForwards.TryAdd(picked, address);
                        }
                        else if (name == "cancel-tcpip-forward")
                        {
                            ok = RemoteForwards.Remove(port);
                            CancelledRemoteForwards.Add(port);
                        }
                    }

                    if (wantReply)
                    {
                        await _server.SendAsync(Build(w =>
                        {
                            w.WriteByte(ok ? SshMessage.RequestSuccess : SshMessage.RequestFailure);
                            if (ok && name == "tcpip-forward" && port == 0)
                            {
                                w.WriteUInt32((uint)picked);
                            }
                        }));
                    }

                    break;
                }

                // Like OpenSSH: unknown requests (keepalive@openssh.com included) get a failure, which is still an answer.
                if (wantReply && !IgnoreGlobalRequests)
                {
                    await _server.SendAsync(new byte[] { SshMessage.RequestFailure });
                }

                break;
            }

            case SshMessage.ChannelOpenConfirmation:
            {
                // The client accepted a channel we opened (forwarded-tcpip).
                var channel = Find(reader.ReadUInt32());
                channel.ClientId = reader.ReadUInt32();
                lock (channel)
                {
                    channel.ClientWindow = reader.ReadUInt32();
                }

                channel.ClientMaxPacket = reader.ReadUInt32();
                channel.Opened?.TrySetResult(true);
                break;
            }

            case SshMessage.ChannelOpenFailure:
            {
                // An answer to ConnectForwardedAsync, or (for a raw open a test sent) recorded like any unexpected message.
                ServerChannel? channel;
                lock (_channels)
                {
                    _channels.Remove(reader.ReadUInt32(), out channel);
                }

                if (channel?.Opened is { } opened)
                {
                    opened.TrySetResult(false);
                    break;
                }

                lock (Unrecognized)
                {
                    Unrecognized.Add(payload);
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
                if (tunnelHost is not null)
                {
                    var originator = $"{reader.ReadUtf8String()}:{reader.ReadUInt32()}";
                    lock (DirectTcpIpOriginators)
                    {
                        DirectTcpIpOriginators.Add(originator);
                    }
                }

                string? socketPath = null;
                if (channelType == "direct-streamlocal@openssh.com")
                {
                    socketPath = reader.ReadUtf8String();
                    reader.ReadUtf8String(); // reserved
                    reader.ReadUInt32(); // reserved
                    lock (DirectStreamLocalRequests)
                    {
                        DirectStreamLocalRequests.Add(socketPath);
                    }
                }
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
                }

                if (socketPath is not null)
                {
                    tunnel = DirectStreamLocal?.Invoke(socketPath);
                }

                if (tunnelHost is not null || socketPath is not null)
                {
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
                var args = new List<string>();
                byte[]? modes = null;
                switch (requestType)
                {
                    case "exec" or "signal" or "subsystem":
                        args.Add(reader.ReadUtf8String());
                        break;
                    case "env":
                        args.Add(reader.ReadUtf8String());
                        args.Add(reader.ReadUtf8String());
                        break;
                    case "pty-req" or "window-change":
                        if (requestType == "pty-req")
                        {
                            args.Add(reader.ReadUtf8String());
                        }

                        for (var i = 0; i < 4; i++)
                        {
                            args.Add(reader.ReadUInt32().ToString(System.Globalization.CultureInfo.InvariantCulture));
                        }

                        modes = requestType == "pty-req" ? reader.ReadString().ToArray() : null;
                        break;
                }

                var record = new ChannelRequestRecord(requestType, wantReply, [.. args], modes);
                lock (channel.Requests)
                {
                    channel.Requests.Add(record);
                }

                var accepted = requestType switch
                {
                    "exec" => !RefuseExec,
                    "shell" => !RefuseShell,
                    "pty-req" => !RefusePty,
                    "env" => AcceptEnv.Contains(record.Args[0]),
                    "window-change" or "signal" => true,
                    _ => false,
                };
                if (wantReply)
                {
                    await SendChannelAsync(accepted ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure, channel);
                }

                if (accepted && requestType is "exec" or "shell")
                {
                    var command = requestType == "exec" ? record.Args[0] : "";
                    if (requestType == "exec")
                    {
                        lock (Commands)
                        {
                            Commands.Add(command);
                        }
                    }

                    var script = requestType == "exec" ? OnExec : OnShell;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await script(new ExecScript(this, channel, command));
                        }
                        catch (Exception)
                        {
                            // The client went away mid-script.
                        }
                    });
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

                channel.Input.Writer.TryWrite(data);
                break;
            }

            case SshMessage.ChannelEof:
            {
                var channel = Find(reader.ReadUInt32());
                channel.Input.Writer.TryComplete();
                channel.EofReceived = true;
                if (channel.Tunnel is { } tunnel)
                {
                    (tunnel as DuplexStream)?.CloseWrite(); // relay the half-close, as sshd does with shutdown(SHUT_WR)
                    if (channel.EofSent)
                    {
                        await SendChannelAsync(SshMessage.ChannelClose, channel, fromScript: true); // both directions are done
                    }
                }

                break;
            }

            case SshMessage.ChannelClose:
            {
                var channel = Find(reader.ReadUInt32());
                channel.CloseReceived = true;
                channel.Input.Writer.TryComplete();
                if (channel.Tunnel is { } closing)
                {
                    channel.Tunnel = null;
                    await closing.DisposeAsync();
                }

                // Under the send gate (inside SendOnChannelAsync): the reply marks the channel closed atomically with a racing script send.
                if (!channel.CloseSent)
                {
                    await SendOnChannelAsync(channel, Build(w => { w.WriteByte(SshMessage.ChannelClose); w.WriteUInt32(channel.ClientId); }), fromScript: true, isClose: true);
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

            // Like sshd: the far end finished writing, which is EOF; CLOSE follows once the client has finished too (a half-close
            // leaves the other direction open).
            await SendChannelAsync(SshMessage.ChannelEof, channel, fromScript: true);
            channel.EofSent = true;
            if (channel.EofReceived)
            {
                await SendChannelAsync(SshMessage.ChannelClose, channel, fromScript: true);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or IOException or InvalidOperationException or SshException)
        {
            // The client or the far end went away.
        }
    }

    /// <summary>The methods a failure lists: the next one in <see cref="AuthenticationChain"/>, or the advertised ones.</summary>
    private string[] CurrentMethods() =>
        AuthenticationChain is { } chain ? [chain[Math.Min(_chainStep, chain.Length - 1)]]
        : RequirePasswordAfterPublicKey && _publicKeyDone ? ["password"]
        : AdvertisedMethods;

    /// <summary>Answers a finished attempt: success, a partial success when <see cref="AuthenticationChain"/> wants more, or failure.</summary>
    private async Task FinishAuthAsync(string method, bool ok)
    {
        if (ok && AuthenticationChain is { } chain)
        {
            if (_chainStep < chain.Length && chain[_chainStep] == method)
            {
                if (++_chainStep < chain.Length)
                {
                    await SendAuthFailureAsync([chain[_chainStep]], partial: true);
                    return;
                }
            }
            else
            {
                ok = false; // valid, but not the method the chain wants now
            }
        }

        if (!ok)
        {
            await SendAuthFailureAsync(CurrentMethods(), partial: false);
            return;
        }

        await _server.SendAsync(new byte[] { SshMessage.UserAuthSuccess });
        if (AnnouncedHostKeys is { } announced)
        {
            // Like sshd with UpdateHostKeys clients: list every host key right after authentication.
            await _server.SendAsync(Build(w =>
            {
                w.WriteByte(SshMessage.GlobalRequest);
                w.WriteString("hostkeys-00@openssh.com");
                w.WriteBoolean(false);
                foreach (var key in announced)
                {
                    w.WriteString(key.Blob);
                }
            }));
        }
    }

    private Task SendKeyboardRoundAsync(KeyboardRound round) =>
        _server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.UserAuthInfoRequest);
            w.WriteString(round.Name);
            w.WriteString(round.Instruction);
            w.WriteString(""); // language tag
            w.WriteUInt32((uint)round.Prompts.Length);
            foreach (var (text, echo) in round.Prompts)
            {
                w.WriteString(text);
                w.WriteBoolean(echo);
            }
        })).AsTask();

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

    /// <summary>
    /// Sends one message on a channel under its send gate. With <paramref name="fromScript"/>, nothing is sent once the server has sent
    /// CLOSE (a real server sends nothing after it); the check and the send are atomic with the CLOSE handling, so a script racing the
    /// client's CLOSE cannot slip a message in after the reply.
    /// </summary>
    private async Task<bool> SendOnChannelAsync(ServerChannel channel, byte[] payload, bool fromScript, bool isClose = false)
    {
        await channel.SendGate.WaitAsync();
        try
        {
            if (fromScript && channel.CloseSent)
            {
                return false;
            }

            if (isClose)
            {
                channel.CloseSent = true;
            }

            await _server.SendAsync(payload);
            return true;
        }
        finally
        {
            channel.SendGate.Release();
        }
    }

    internal async Task SendChannelAsync(byte type, ServerChannel channel, bool fromScript = false) =>
        await SendOnChannelAsync(channel, Build(w => { w.WriteByte(type); w.WriteUInt32(channel.ClientId); }), fromScript, isClose: type == SshMessage.ChannelClose);

    internal async Task SendRequestAsync(ServerChannel channel, string type, Action<SshWriter> body, bool fromScript = false) =>
        await SendOnChannelAsync(channel, Build(w =>
        {
            w.WriteByte(SshMessage.ChannelRequest);
            w.WriteUInt32(channel.ClientId);
            w.WriteString(type);
            w.WriteBoolean(false);
            body(w);
        }), fromScript);

    internal async Task SendDataAsync(ServerChannel channel, byte[] data, bool extended, bool fromScript = false)
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
            var sent = await SendOnChannelAsync(channel, Build(w =>
            {
                w.WriteByte(extended ? SshMessage.ChannelExtendedData : SshMessage.ChannelData);
                w.WriteUInt32(channel.ClientId);
                if (extended)
                {
                    w.WriteUInt32(1);
                }

                w.WriteString(chunk.Span);
            }), fromScript);
            if (!sent)
            {
                return;
            }

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