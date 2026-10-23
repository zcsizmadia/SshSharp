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

    /// <summary>OpenSSH's <c>eow@openssh.com</c>: the program closed its input, so the client should stop sending it.</summary>
    public Task EndOfWriteAsync() => server.SendRequestAsync(channel, "eow@openssh.com", _ => { }, fromScript: true);

    /// <summary>An <c>exit-signal</c> with the signal name and then whatever <paramref name="rest"/> writes (for malformed ones).</summary>
    public Task ExitSignalRawAsync(string signal, Action<SshWriter> rest) => server.SendRequestAsync(channel, "exit-signal", w =>
    {
        w.WriteString(signal);
        rest(w);
    }, fromScript: true);

    public Task ExitSignalAsync(string signal, bool coreDumped = false, string message = "") => server.SendRequestAsync(channel, "exit-signal", w =>
    {
        w.WriteString(signal);
        w.WriteBoolean(coreDumped);
        w.WriteString(message);
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

    /// <summary>
    /// Lets the client send <paramref name="bytes"/> more (SSH_MSG_CHANNEL_WINDOW_ADJUST), as a server does after consuming input. Like
    /// every script message, it is dropped once the server has sent CLOSE: the client may already have forgotten the channel.
    /// </summary>
    public Task GrantWindowAsync(uint bytes) => server.SendWindowAdjustAsync(channel, bytes);

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

        /// <summary>How many CHANNEL_EOF messages the client sent (RFC 4254 allows one).</summary>
        public int EofCount;

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

    /// <summary>The session identifier (the exchange hash of the first key exchange).</summary>
    public byte[]? SessionId => _server.SessionId;

    public FakeSshServer Raw => _server;

    public string Password { get; init; } = TestSecrets.Password;

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

    /// <summary>The subsystems the server offers, by name (the script's command is the name); a request for any other is refused, as sshd does.</summary>
    public Dictionary<string, Func<ExecScript, Task>> Subsystems { get; } = new(StringComparer.Ordinal);

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
    public Task<Stream?> ConnectForwardedAsync(int port, string connectedAddress = "localhost", string originator = "203.0.113.7", int originatorPort = 50123) =>
        OpenChannelToClientAsync("forwarded-tcpip", w =>
        {
            w.WriteString(connectedAddress);
            w.WriteUInt32((uint)port);
            w.WriteString(originator);
            w.WriteUInt32((uint)originatorPort);
        });

    /// <summary>Socket paths the client asked the server to listen on (streamlocal-forward@openssh.com).</summary>
    public HashSet<string> RemoteSocketForwards { get; } = [];

    /// <summary>Socket paths the client cancelled (cancel-streamlocal-forward@openssh.com).</summary>
    public List<string> CancelledRemoteSocketForwards { get; } = [];

    /// <summary>Plays a connection arriving at a remotely forwarded Unix socket: a forwarded-streamlocal@openssh.com channel to the client.</summary>
    public Task<Stream?> ConnectForwardedSocketAsync(string socketPath) =>
        OpenChannelToClientAsync("forwarded-streamlocal@openssh.com", w =>
        {
            w.WriteString(socketPath);
            w.WriteString(string.Empty); // reserved
        });

    /// <summary>
    /// Plays a program on the server using the forwarded agent: opens an agent channel (OpenSSH's <c>auth-agent@openssh.com</c>, or RFC
    /// 9987's <c>agent-connect</c>), or null when refused.
    /// </summary>
    public Task<Stream?> OpenAgentChannelAsync(string type = "auth-agent@openssh.com") => OpenChannelToClientAsync(type, null);

    /// <summary>The channel the server most recently opened to the client (a forwarded connection), to inspect its window.</summary>
    public ServerChannel? LastChannelToClient { get; private set; }

    /// <summary>How much more the client lets the server send on <paramref name="channel"/> now (its receive window, as the server sees it).</summary>
    public static long ClientWindowOf(ServerChannel channel)
    {
        lock (channel)
        {
            return channel.ClientWindow;
        }
    }

    /// <summary>Opens a channel to the client and returns its far end as a stream, or null when the client refuses it.</summary>
    private async Task<Stream?> OpenChannelToClientAsync(string type, Action<SshWriter>? data)
    {
        // The tunnel is attached before the open is sent: the client may confirm and close at once (nothing listening locally), and a
        // CLOSE handled before the tunnel was attached would leave the far end waiting forever.
        var (near, far) = DuplexStream.CreatePair();
        var channel = new ServerChannel(_nextId++) { Opened = new(TaskCreationOptions.RunContinuationsAsynchronously), Tunnel = near };
        lock (_channels)
        {
            _channels[channel.Id] = channel;
        }

        LastChannelToClient = channel;

        await _server.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ChannelOpen);
            w.WriteString(type);
            w.WriteUInt32(channel.Id);
            w.WriteUInt32(ServerWindow);
            w.WriteUInt32(ServerMaxPacket);
            data?.Invoke(w);
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

    /// <summary>
    /// When set, a forwarding request (tcpip-forward, streamlocal-forward) is carried out at once but answered only once this completes,
    /// and nothing after it is processed before then: a slow server, for cancelling a request it has already accepted.
    /// </summary>
    public TaskCompletionSource? HoldForwardReplies { get; set; }

    /// <summary>A certificate authority's public key: user certificates it signed are accepted (sshd's TrustedUserCAKeys).</summary>
    public byte[]? TrustedUserAuthority { get; init; }

    /// <summary>Public keys (SSH wire format) the server accepts for <see cref="UserName"/>.</summary>
    public List<byte[]> AuthorizedKeys { get; init; } = [];

    /// <summary>Require publickey and then password (partial success after the key), like <c>AuthenticationMethods publickey,password</c>.</summary>
    public bool RequirePasswordAfterPublicKey { get; init; }

    /// <summary>Every authentication method the client tried, in order; signed publickey attempts add "publickey-signed:alg".</summary>
    public List<string> AuthAttempts { get; } = [];

    /// <summary>The signature algorithm of every publickey request, in order.</summary>
    public List<string> PublicKeyAlgorithms { get; } = [];

    /// <summary>Every publickey request, in order, accepted or not: "query:alg" without a signature, "signed:alg" with one.</summary>
    public List<string> PublicKeyRequests { get; } = [];

    /// <summary>Extensions to send in a second EXT_INFO during authentication, to a client that announced ext-info-in-auth@openssh.com.</summary>
    public IReadOnlyDictionary<string, string>? ExtInfoDuringAuth { get; init; }

    private bool _lateExtInfoSent;

    /// <summary>Whether transport pings (ping@openssh.com) are answered; how many arrived.</summary>
    public bool AnswerPings { get; set; } = true;

    public int PingsReceived { get; private set; }

    /// <summary>
    /// The next ping is dropped and a key re-exchange started from the server side instead, as OpenSSH treats a PING that arrives
    /// during its key exchange: never answered.
    /// </summary>
    public bool DropNextPingAndRekey { get; set; }

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

    /// <summary>How many CHANNEL_OPEN messages arrived, counted before <see cref="HoldChannelOpen"/> holds them.</summary>
    public int ChannelOpensReceived => Volatile.Read(ref _channelOpensReceived);

    private int _channelOpensReceived;

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

    /// <summary>Completes (in any state) when the server's loop ends, which it does when the client disconnects.</summary>
    public Task Finished => _loop is { } loop ? loop.ContinueWith(static _ => { }, TaskScheduler.Default) : Task.CompletedTask;

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
        if (payload[0] == SshMessage.UserAuthRequest && ExtInfoDuringAuth is { } lateExtensions && !_lateExtInfoSent
            && _server.ClientExtensions.ContainsKey("ext-info-in-auth@openssh.com"))
        {
            // PROTOCOL 1.10: after the client's first USERAUTH_REQUEST, a second EXT_INFO (per-user server-sig-algs, for example).
            _lateExtInfoSent = true;
            await _server.SendAsync(Build(w =>
            {
                w.WriteByte(SshMessage.ExtInfo);
                w.WriteUInt32((uint)lateExtensions.Count);
                foreach (var (name, value) in lateExtensions)
                {
                    w.WriteString(name);
                    w.WriteString(value);
                }
            }));
        }

        if (payload[0] == SshMessage.Ping)
        {
            PingsReceived++;
            if (DropNextPingAndRekey)
            {
                DropNextPingAndRekey = false;
                _ = _server.RekeyAsync(_cts.Token);
                return;
            }

            if (AnswerPings)
            {
                var ping = new SshReader(payload);
                ping.ReadByte();
                var data = ping.ReadString().ToArray();
                await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.Pong); w.WriteString(data); }));
            }

            return;
        }

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
                _gssapiUser = null; // and a gssapi-with-mic exchange
                bool ok;
                if (method == SshUserAuth.GssapiMethod)
                {
                    var count = reader.ReadUInt32();
                    var offered = new List<byte[]>();
                    for (var i = 0; i < count; i++)
                    {
                        offered.Add(reader.ReadString().ToArray());
                    }

                    lock (GssapiMechanismsOffered)
                    {
                        GssapiMechanismsOffered.AddRange(offered);
                    }

                    if (Gssapi is not { } gss || user != UserName || !offered.Any(o => o.AsSpan().SequenceEqual(SshSharp.Protocol.Gssapi.Krb5Oid)))
                    {
                        await FinishAuthAsync(method, ok: false);
                        break;
                    }

                    _gssapiUser = user;
                    _gssapiServerRound = 0;
                    await _server.SendAsync(Build(w =>
                    {
                        w.WriteByte(SshUserAuth.GssapiResponse);
                        w.WriteString(gss.ChooseWrongMechanism ? [0x06, 0x01, 0x2A] : SshSharp.Protocol.Gssapi.Krb5Oid);
                    }));
                    break;
                }

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

                if (method is "publickey" or HostBoundMethod)
                {
                    var hasSignature = reader.ReadBoolean();
                    var algorithm = reader.ReadUtf8String();
                    var blob = reader.ReadString().ToArray();
                    lock (PublicKeyAlgorithms)
                    {
                        PublicKeyAlgorithms.Add(algorithm);
                    }

                    lock (PublicKeyRequests)
                    {
                        PublicKeyRequests.Add((hasSignature ? "signed:" : "query:") + algorithm);
                    }

                    // Host-bound (PROTOCOL 3.1): the client names the host key it verified, which must be the one this server presented.
                    var boundHostKey = method == HostBoundMethod ? reader.ReadString().ToArray() : null;
                    if (boundHostKey is not null)
                    {
                        lock (HostBoundKeys)
                        {
                            HostBoundKeys.Add(boundHostKey);
                        }
                    }

                    var authorized = user == UserName && (AuthorizedKeys.Any(k => k.AsSpan().SequenceEqual(blob)) || CertificateTrusted(algorithm, blob, user))
                        && (boundHostKey is null || boundHostKey.AsSpan().SequenceEqual(PresentedHostKey));
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
                    ok = authorized && SignatureValid(user, method, algorithm, blob, boundHostKey, signature);
                    if (ok)
                    {
                        lock (AuthAttempts)
                        {
                            AuthAttempts.Add((boundHostKey is null ? "publickey-signed:" : "publickey-hostbound-signed:") + algorithm);
                        }
                    }

                    if (ok && RequirePasswordAfterPublicKey && !_publicKeyDone)
                    {
                        _publicKeyDone = true;
                        await SendAuthFailureAsync(["password"], partial: true);
                        break;
                    }
                }
                else if (method == "password" && user == UserName && PasswordExpired)
                {
                    // RFC 4252 section 8: an expired password is answered with PASSWD_CHANGEREQ, and a change request carries old and new.
                    var isChange = reader.ReadBoolean();
                    var password = reader.ReadUtf8String();
                    var newPassword = isChange ? reader.ReadUtf8String() : null;
                    lock (PasswordsReceived)
                    {
                        PasswordsReceived.Add(password);
                        if (newPassword is not null)
                        {
                            NewPasswordsReceived.Add(newPassword);
                        }
                    }

                    if (password != Password || (newPassword is not null && NewPasswordsRefused < 0))
                    {
                        await FinishAuthAsync(method, ok: false); // a wrong old password, or a server that will not change it at all
                        break;
                    }

                    if (newPassword is null || NewPasswordsReceived.Count <= NewPasswordsRefused)
                    {
                        var prompt = newPassword is null ? PasswordChangePrompt : "Password too short.";
                        await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.UserAuthPasswordChangeRequest); w.WriteString(prompt); w.WriteString("en"); }));
                        break;
                    }

                    ChangedPassword = newPassword;
                    await FinishAuthAsync(method, ok: true);
                    break;
                }
                else
                {
                    ok = user == UserName && ((method == "none" && AllowNone)
                        || (method == "password" && PasswordMatches(ref reader) && (!RequirePasswordAfterPublicKey || _publicKeyDone)));
                }

                await FinishAuthAsync(method, ok);
                break;
            }

            case SshUserAuth.GssapiToken when _gssapiUser is not null && Gssapi is { } gss:
            {
                // The fake mechanism: the client sends C0, C1, ...; the server answers S1, S2, ... until the client's last token.
                var token = System.Text.Encoding.ASCII.GetString(reader.ReadString());
                lock (GssapiTokensReceived)
                {
                    GssapiTokensReceived.Add(token);
                }

                if (gss.SendStatusMessage)
                {
                    // SSH_MSG_USERAUTH_GSSAPI_ERROR: the server's GSS-API status, informational.
                    await _server.SendAsync(Build(w => { w.WriteByte(SshUserAuth.GssapiError); w.WriteUInt32(0); w.WriteUInt32(0); w.WriteString("note"); w.WriteString(""); }));
                }

                if (gss.FailWithErrorToken || (gss.FailLastTokenWithErrorToken && token == $"C{gss.Rounds}"))
                {
                    await _server.SendAsync(Build(w => { w.WriteByte(SshUserAuth.GssapiErrorToken); w.WriteString("server-error"u8); }));
                    _gssapiUser = null;
                    await FinishAuthAsync(SshUserAuth.GssapiMethod, ok: false);
                    break;
                }

                if (token != $"C{gss.Rounds}")
                {
                    _gssapiServerRound++;
                    await _server.SendAsync(Build(w => { w.WriteByte(SshUserAuth.GssapiToken); w.WriteString(System.Text.Encoding.ASCII.GetBytes($"S{_gssapiServerRound}")); }));
                }

                break;
            }

            case SshUserAuth.GssapiMic when _gssapiUser is null && Gssapi is not null:
                // A MIC after the exchange failed: OpenSSH has no handler for it any more.
                await _server.SendAsync(Build(w => { w.WriteByte(SshMessage.Unimplemented); w.WriteUInt32(0); }));
                break;

            case SshUserAuth.GssapiMic when _gssapiUser is { } gssUser && Gssapi is { } gss:
            {
                var mic = reader.ReadString().ToArray();
                var expected = FakeGssapi.Mic(Build(w =>
                {
                    w.WriteString(_server.SessionId!);
                    w.WriteByte(SshMessage.UserAuthRequest);
                    w.WriteString(gssUser);
                    w.WriteString("ssh-connection");
                    w.WriteString(SshUserAuth.GssapiMethod);
                }));
                _gssapiUser = null;
                GssapiMicValid = mic.AsSpan().SequenceEqual(expected);
                await FinishAuthAsync(SshUserAuth.GssapiMethod, ok: GssapiMicValid && !gss.RejectMic);
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

                if (name is "streamlocal-forward@openssh.com" or "cancel-streamlocal-forward@openssh.com")
                {
                    var socketPath = reader.ReadUtf8String();
                    bool accepted;
                    lock (RemoteSocketForwards)
                    {
                        if (name == "streamlocal-forward@openssh.com")
                        {
                            accepted = !RefuseRemoteForwarding && RemoteSocketForwards.Add(socketPath);
                        }
                        else
                        {
                            accepted = RemoteSocketForwards.Remove(socketPath);
                            CancelledRemoteSocketForwards.Add(socketPath);
                        }
                    }

                    if (HoldForwardReplies is { } hold && name == "streamlocal-forward@openssh.com")
                    {
                        await hold.Task;
                    }

                    if (wantReply)
                    {
                        await _server.SendAsync(new[] { accepted ? SshMessage.RequestSuccess : SshMessage.RequestFailure });
                    }

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

                    if (HoldForwardReplies is { } hold && name == "tcpip-forward")
                    {
                        await hold.Task;
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
                Interlocked.Increment(ref _channelOpensReceived);
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
                    case "break":
                        args.Add(reader.ReadUInt32().ToString(System.Globalization.CultureInfo.InvariantCulture));
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
                    "break" => !RefusePty && channel.Requests.Any(r => r.Type == "pty-req"), // as sshd: only to a terminal
                    "subsystem" => Subsystems.ContainsKey(record.Args[0]),
                    _ => false,
                };
                if (wantReply)
                {
                    await SendChannelAsync(accepted ? SshMessage.ChannelSuccess : SshMessage.ChannelFailure, channel);
                }

                if (accepted && requestType is "exec" or "shell" or "subsystem")
                {
                    var command = requestType is "exec" or "subsystem" ? record.Args[0] : "";
                    if (requestType == "exec")
                    {
                        lock (Commands)
                        {
                            Commands.Add(command);
                        }
                    }

                    var script = requestType switch
                    {
                        "exec" => OnExec,
                        "subsystem" => Subsystems[command],
                        _ => OnShell,
                    };
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
                Interlocked.Increment(ref channel.EofCount);
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
                // As a script: nothing may follow the CLOSE, which the client's CLOSE can trigger at any moment.
                await SendDataAsync(channel, buffer[..read], extended: false, fromScript: true);
                if (channel.CloseSent)
                {
                    return;
                }
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

    /// <summary>The server side of gssapi-with-mic with the fake mechanism (<see cref="FakeGssapi"/>); null refuses the method.</summary>
    public FakeGssapiServer? Gssapi { get; init; }

    public List<byte[]> GssapiMechanismsOffered { get; } = [];

    public List<string> GssapiTokensReceived { get; } = [];

    public bool GssapiMicValid { get; private set; }

    private string? _gssapiUser;
    private int _gssapiServerRound;

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
                && certificate.VerifySignature()
                && now >= certificate.ValidAfterSeconds && now < certificate.ValidBeforeSeconds
                && certificate.Principals.Contains(user);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    /// <summary>Checks a publickey signature exactly as a server must: over the session id and the request.</summary>
    /// <summary>The host-bound public key method (PROTOCOL 3.1).</summary>
    private const string HostBoundMethod = "publickey-hostbound-v00@openssh.com";

    /// <summary>The host keys clients named in host-bound authentication requests.</summary>
    public List<byte[]> HostBoundKeys { get; } = [];

    /// <summary>What this server presented as its host key (its certificate, when it has one).</summary>
    private byte[] PresentedHostKey => (_server.Options.HostCertificate ?? _server.Options.HostKey).Blob;

    private bool SignatureValid(string user, string method, string algorithm, byte[] blob, byte[]? boundHostKey, byte[] signature)
    {
        var signed = Build(w =>
        {
            w.WriteString(_server.SessionId!);
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(user);
            w.WriteString("ssh-connection");
            w.WriteString(method);
            w.WriteBoolean(true);
            w.WriteString(algorithm);
            w.WriteString(blob);
            if (boundHostKey is not null)
            {
                w.WriteString(boundHostKey);
            }
        });
        try
        {
            return SshCertificate.IsCertificateAlgorithm(algorithm)
                ? SshCertificate.FromBlob(blob).Key.VerifySignature(SshCertificate.BaseAlgorithm(algorithm), signature, signed)
                : SshSharp.Keys.VerifyingKey.Parse(blob).VerifySignature(algorithm, signature, signed);
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    private bool PasswordMatches(ref SshReader reader)
    {
        reader.ReadBoolean();
        var password = reader.ReadUtf8String();
        lock (PasswordsReceived)
        {
            PasswordsReceived.Add(password);
        }

        return password == Password;
    }

    /// <summary>Every password the client sent with the password method, in order (the old one, for a change request).</summary>
    public List<string> PasswordsReceived { get; } = [];

    /// <summary>
    /// The right password has expired: it is answered with SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (<see cref="PasswordChangePrompt"/>), and a
    /// change request with it as the old password succeeds once <see cref="NewPasswordsRefused"/> new passwords were refused.
    /// </summary>
    public bool PasswordExpired { get; init; }

    public string PasswordChangePrompt { get; init; } = "Your password has expired.";

    /// <summary>New passwords answered with another change request before one is accepted; negative refuses changes with FAILURE.</summary>
    public int NewPasswordsRefused { get; init; }

    /// <summary>The new passwords the client sent, in order.</summary>
    public List<string> NewPasswordsReceived { get; } = [];

    /// <summary>The new password the server accepted, if any.</summary>
    public string? ChangedPassword { get; private set; }

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

    internal async Task SendWindowAdjustAsync(ServerChannel channel, uint bytes) =>
        await SendOnChannelAsync(channel, Build(w =>
        {
            w.WriteByte(SshMessage.ChannelWindowAdjust);
            w.WriteUInt32(channel.ClientId);
            w.WriteUInt32(bytes);
        }), fromScript: true);

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