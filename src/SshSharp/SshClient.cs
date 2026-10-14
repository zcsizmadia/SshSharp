using System.Buffers;
using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>An authenticated SSH client connection: run commands over it. Create one with <see cref="ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>.</summary>
public sealed partial class SshClient : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly SshClientOptions _options;
    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly IAsyncDisposable? _owner;
    private readonly ILogger _logger;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, SshRemotePortForwarder> _remoteForwards = new();
    private int _disposed;

    private SshClient(SshConnection connection, SshClientOptions options, Stream stream, bool leaveOpen, IAsyncDisposable? owner, string serverIdentification, SshHostKey hostKey, ILogger logger)
    {
        _logger = logger;
        _connection = connection;
        _options = options;
        _stream = stream;
        _leaveOpen = leaveOpen;
        _owner = owner;
        ServerIdentification = serverIdentification;
        HostKey = hostKey;
    }

    /// <summary>The connection layer, for tests of channel behaviour that has no public API yet.</summary>
    internal SshConnection Connection => _connection;

    /// <summary>The server's identification string, for example <c>SSH-2.0-OpenSSH_9.9</c>.</summary>
    public string ServerIdentification { get; }

    /// <summary>The host key the server proved possession of.</summary>
    public SshHostKey HostKey { get; }

    /// <summary>
    /// The algorithms in use: key exchange (and whether it is post-quantum, <see cref="SshNegotiatedAlgorithms.IsPostQuantum"/>), host key
    /// signature, ciphers and MACs. A key re-exchange can change them; each read returns the current ones.
    /// </summary>
    public SshNegotiatedAlgorithms Algorithms => new(_connection.Algorithms);

    /// <summary>
    /// Whether the connection is still up: false once the server disconnected, the connection failed (including a missed keep-alive,
    /// see <see cref="SshClientOptions.KeepAliveInterval"/>), or the client was disposed.
    /// </summary>
    public bool IsConnected => _disposed == 0 && _connection.Failure is null;

    /// <summary>Cancelled when the connection ends for any reason, so pending work can stop or reconnect. <see cref="ConnectionError"/> says why.</summary>
    public CancellationToken ConnectionClosed => _connection.Closed;

    /// <summary>Why the connection ended (an <see cref="SshException"/>, usually), or null while it is up.</summary>
    public Exception? ConnectionError => _connection.Failure;

    /// <summary>Connects to <paramref name="host"/> over TCP, performs the handshake and authenticates.</summary>
    public static async Task<SshClient> ConnectAsync(string host, int port, SshClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Proxy is { } proxy)
        {
            var proxied = await proxy.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            return await ConnectCoreAsync(proxied, options, leaveOpen: false, owner: null, host, port, cancellationToken).ConfigureAwait(false);
        }

        var tcp = new TcpClient { NoDelay = true };
        try
        {
            try
            {
                await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                // The host name stays out of the message (exception text often ends up in logs); it is in the caller's hands already.
                throw new SshException(SshFailureReason.ConnectFailed, $"Could not connect to the server: {ex.SocketErrorCode}.", ex);
            }

            return await ConnectCoreAsync(tcp.GetStream(), options, leaveOpen: false, owner: new Owned(tcp), host, port, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>Runs the SSH protocol over an existing stream (a socket, a WebSocket wrapper, a tunnel from another connection, ...).</summary>
    /// <param name="stream">A connected, duplex stream.</param>
    /// <param name="options">Connection options.</param>
    /// <param name="leaveOpen">Whether to leave <paramref name="stream"/> open when the client is disposed.</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    public static Task<SshClient> ConnectAsync(Stream stream, SshClientOptions options, bool leaveOpen = false, CancellationToken cancellationToken = default) =>
        ConnectCoreAsync(stream, options, leaveOpen, owner: null, host: null, port: 22, cancellationToken);

    /// <summary>Runs <paramref name="command"/> on the server and collects its output and exit status.</summary>
    /// <exception cref="SshException">The server refused the command or the connection failed.</exception>
    /// <exception cref="InvalidOperationException">The output exceeded <see cref="SshClientOptions.MaxCommandOutputBytes"/>.</exception>
    public async Task<SshCommandResult> RunCommandAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

        using var activity = SshTelemetry.Activities.StartActivity("SshSharp.Command");
        var outcome = "error";
        var channel = await _connection.OpenSessionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SshLog.CommandStarting(_logger, command.Length, channel.LocalId);
            if (!await channel.RequestAsync("exec", true, w => w.WriteString(command), cancellationToken).ConfigureAwait(false))
            {
                throw new SshException(SshFailureReason.ChannelClosed, "The server refused to execute the command.");
            }

            var stdout = new ArrayBufferWriter<byte>();
            var stderr = new ArrayBufferWriter<byte>();
            long total = 0;
            while (await channel.ReadAsync(cancellationToken).ConfigureAwait(false) is { } chunk)
            {
                using (chunk)
                {
                    total += chunk.Data.Length;
                    if (total > _options.MaxCommandOutputBytes)
                    {
                        throw new InvalidOperationException($"The command produced more than {_options.MaxCommandOutputBytes} bytes of output.");
                    }

                    (chunk.IsExtended ? stderr : stdout).Write(chunk.Data.Span);
                }
            }

            // The exit status arrives before the server's CLOSE.
            await channel.WaitClosedAsync(cancellationToken).ConfigureAwait(false);
            int? exitStatus = channel.ExitStatus is { } status ? (int)status : null;
            outcome = exitStatus == 0 ? "success" : "failure";
            activity?.SetTag("ssh.command.exit_status", exitStatus);
            SshLog.CommandFinished(_logger, channel.LocalId, exitStatus, channel.ExitSignal);
            return new SshCommandResult(exitStatus, channel.ExitSignal, stdout.WrittenMemory, stderr.WrittenMemory);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);
            throw;
        }
        finally
        {
            SshTelemetry.Commands.Add(1, new KeyValuePair<string, object?>("result", outcome));
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);

            // Output left unread (the limit was exceeded, or the call cancelled) goes back to the buffer pool.
            channel.DiscardUnread();
        }
    }

    /// <summary>Starts the user's login shell, usually with a terminal (<see cref="SshSessionOptions.Terminal"/>) for interactive use.</summary>
    /// <exception cref="SshException">The server refused the terminal or the shell, or the connection failed.</exception>
    public Task<SshSession> StartShellAsync(SshSessionOptions? options = null, CancellationToken cancellationToken = default) =>
        StartSessionAsync("shell", null, options, cancellationToken);

    /// <summary>
    /// Starts <paramref name="command"/> with its input and output as streams, for long-running or interactive commands. For a command whose
    /// output fits in memory, <see cref="RunCommandAsync"/> is simpler.
    /// </summary>
    /// <exception cref="SshException">The server refused the terminal or the command, or the connection failed.</exception>
    public Task<SshSession> StartCommandAsync(string command, SshSessionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        return StartSessionAsync("exec", command, options, cancellationToken);
    }

    /// <summary>
    /// Starts a subsystem, as <c>ssh -s</c> does: a protocol the server runs by name (<c>sftp</c>, <c>netconf</c>, or one the server
    /// configures with sshd's <c>Subsystem</c>), with no shell in between. The session's <see cref="SshSession.StandardInput"/> and
    /// <see cref="SshSession.StandardOutput"/> carry the subsystem's protocol, byte for byte.
    /// </summary>
    /// <param name="name">The subsystem's name, for example <c>sftp</c>.</param>
    /// <param name="options">Environment variables (and, rarely, a terminal) for the session.</param>
    /// <param name="cancellationToken">Cancels starting the subsystem.</param>
    /// <exception cref="SshException">The server does not offer the subsystem (<see cref="SshFailureReason.ChannelClosed"/>), or the
    /// connection failed.</exception>
    public Task<SshSession> StartSubsystemAsync(string name, SshSessionOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.Any(char.IsControl))
        {
            throw new ArgumentException("A subsystem name must not contain control characters.", nameof(name));
        }

        return StartSessionAsync("subsystem", name, options, cancellationToken);
    }

    private async Task<SshSession> StartSessionAsync(string kind, string? command, SshSessionOptions? options, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var terminal = options?.Terminal;
        terminal?.Validate();
        var environment = options?.Environment ?? new Dictionary<string, string>();
        foreach (var (name, value) in environment)
        {
            if (string.IsNullOrEmpty(name) || name.Contains('=') || name.Contains('\0') || value is null || value.Contains('\0'))
            {
                throw new ArgumentException("Environment variable names must be non-empty without '=', and names and values without NUL.", nameof(options));
            }
        }

        var channel = await _connection.OpenSessionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            channel.SplitExtended = true;

            // In ssh's order: the terminal, agent forwarding, then the environment, then the program.
            if (terminal is not null && !await channel.RequestAsync("pty-req", true, w =>
            {
                w.WriteString(terminal.TerminalType);
                w.WriteUInt32((uint)terminal.Columns);
                w.WriteUInt32((uint)terminal.Rows);
                w.WriteUInt32((uint)terminal.WidthPixels);
                w.WriteUInt32((uint)terminal.HeightPixels);
                w.WriteString(terminal.EncodeModes());
            }, cancellationToken).ConfigureAwait(false))
            {
                throw new SshException(SshFailureReason.ChannelClosed, "The server refused to allocate a terminal.");
            }

            if (_options.ForwardAgent is not null)
            {
                // No reply, as ssh sends it: a server that does not forward agents just ignores it. RFC 9987 names the request "agent-req",
                // to be used only when the server announces "agent-forward"; otherwise OpenSSH's name, which servers have long understood.
                EnsureChannelDispatch();
                var request = _connection.ServerExtensions.ContainsKey("agent-forward") ? "agent-req" : "auth-agent-req@openssh.com";
                await channel.RequestAsync(request, false, null, cancellationToken).ConfigureAwait(false);
            }

            foreach (var (name, value) in environment)
            {
                // No reply: servers drop names they do not accept (sshd's AcceptEnv), as ssh expects.
                await channel.RequestAsync("env", false, w =>
                {
                    w.WriteString(name);
                    w.WriteString(value);
                }, cancellationToken).ConfigureAwait(false);
            }

            if (!await channel.RequestAsync(kind, true, command is null ? null : w => w.WriteString(command), cancellationToken).ConfigureAwait(false))
            {
                throw new SshException(SshFailureReason.ChannelClosed, kind switch
                {
                    "shell" => "The server refused to start a shell.",
                    "subsystem" => $"The server does not offer the '{command}' subsystem, or refused it.",
                    _ => "The server refused to execute the command.",
                });
            }

            SshLog.SessionStarted(_logger, kind, channel.LocalId, terminal is not null);
            return new SshSession(channel, terminal is not null, _logger);
        }
        catch
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
            throw;
        }
    }

    /// <summary>Disconnects and releases the connection.</summary>
    public async ValueTask DisposeAsync()
    {
        // Concurrent calls: only the first one tears down (and decrements the connection count).
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await DisposeConfiguredForwardingsAsync().ConfigureAwait(false);
        SshTelemetry.Connections.Add(-1);
        await _connection.DisposeAsync().ConfigureAwait(false);
        if (!_leaveOpen)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }

        if (_owner is not null)
        {
            await _owner.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<SshClient> ConnectCoreAsync(Stream stream, SshClientOptions options, bool leaveOpen, IAsyncDisposable? owner, string? host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var logger = options.Logger ?? NullLogger.Instance;
        using var activity = SshTelemetry.Activities.StartActivity("SshSharp.Connect");
        var started = Stopwatch.GetTimestamp();

        var preferences = options.AlgorithmPreferences ?? (options.FipsMode ? AlgorithmPreferences.Fips() : new AlgorithmPreferences());
        bool prefersCertificates;
        try
        {
            prefersCertificates = await options.HostKeyVerifier.PrefersCertificatesAsync(host, port, options.HostKeyAlias, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            prefersCertificates = false; // an unreadable known_hosts is reported by the verification itself, with the key it concerns
        }

        if (prefersCertificates)
        {
            // A certificate authority is trusted for this host: ask for its certificate first, as ssh does.
            preferences = preferences.WithCertificateHostKeysFirst();
        }

        var transportOptions = new SshTransportOptions
        {
            Preferences = preferences,
            MinimumRsaBits = options.MinimumRsaBits,
            RekeyBytes = Math.Min(options.RekeyAfterBytes, SshClientOptions.MaxRekeyAfterBytes),
            RekeyInterval = options.RekeyAfterTime,
            Logger = logger,
            TimeProvider = options.TimeProvider,
            VerifyHostKey = async (info, ct) =>
            {
                var key = new SshHostKey(info.Algorithm, info.KeyType, info.Fingerprint, info.Blob, info.KeySizeBits) { Certificate = info.Certificate };
                SshHostKeyVerdict verdict;
                try
                {
                    verdict = await options.HostKeyVerifier.VerifyAsync(new SshHostKeyContext(host, port, options.HostKeyAlias, key), ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // known_hosts could not be read or written (a locked or protected file): the key was not verified. Without this, the
                    // IOException would be reported as a lost connection.
                    throw new SshHostKeyException($"The host key {info.Fingerprint} could not be checked: {ex.Message}", key);
                }

                if (!verdict.IsAccepted)
                {
                    SshLog.HostKeyRejected(logger, info.Fingerprint);
                    throw new SshHostKeyException(verdict.Reason ?? $"The host key {info.Fingerprint} was not accepted.", key);
                }

                return true;
            },
        };
        var transport = new SshTransport(stream, transportOptions);
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            await AuthenticateAsync(transport, options, logger, cancellationToken).ConfigureAwait(false);

            var hostKey = transport.HostKey!;
            var algorithms = transport.Algorithms!;
            var publicHostKey = new SshHostKey(hostKey.Algorithm, hostKey.KeyType, hostKey.Fingerprint, hostKey.Blob, hostKey.KeySizeBits) { Certificate = hostKey.Certificate };
            var connection = new SshConnection(transport, logger, options.TimeProvider);

            // Before the receive loop starts: the server announces its host keys right after authentication.
            WatchHostKeyUpdates(connection, options, host, port, publicHostKey, logger);
            connection.Start();
            if (options.KeepAliveInterval is { } keepAlive)
            {
                connection.StartKeepAlive(keepAlive, options.KeepAliveCountMax);
            }

            SshTelemetry.Connections.Add(1);
            var postQuantum = SshAlgorithms.IsPostQuantum(algorithms.Kex);
            SshTelemetry.ConnectDuration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds, new KeyValuePair<string, object?>("ssh.kex.post_quantum", postQuantum));
            activity?.SetTag("ssh.kex", algorithms.Kex);
            activity?.SetTag("ssh.kex.post_quantum", postQuantum);
            activity?.SetTag("ssh.cipher", algorithms.CipherClientToServer);
            activity?.SetTag("ssh.host_key.type", hostKey.KeyType);
            SshLog.Connected(logger, algorithms.Kex, algorithms.CipherClientToServer, hostKey.KeyType, hostKey.Fingerprint);
            if (!postQuantum)
            {
                // Like OpenSSH 10.1's WarnWeakCrypto, but at Information level: common servers (OpenSSH before 9.9) cannot do better yet.
                SshLog.KeyExchangeNotPostQuantum(logger, algorithms.Kex);
            }

            return new SshClient(
                connection, options, stream, leaveOpen, owner, transport.ServerIdentification!.Line,
                publicHostKey, logger);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);

            // Cleanup must not replace the real error with one from a stream that is already broken.
            try
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                if (!leaveOpen)
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                }
            }
            catch (Exception cleanup) when (cleanup is IOException or ObjectDisposedException)
            {
                // Already broken.
            }

            // The stream failing (socket reset, a ProxyCommand that exited) is a lost connection, reported as an SshException.
            if (ex is IOException)
            {
                throw SshConnection.ConnectionLost(ex);
            }

            throw;
        }
    }

    /// <summary>ssh's default order, less the methods SshSharp does not implement (gssapi-with-mic, hostbased).</summary>
    internal static readonly string[] DefaultAuthenticationOrder = ["publickey", "keyboard-interactive", "password"];

    /// <summary>Walks of the method order; each one after the first needs a partial success, so this bounds a server that never finishes.</summary>
    private const int MaxAuthenticationPasses = 8;

    private static async Task AuthenticateAsync(SshTransport transport, SshClientOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        var auth = new SshUserAuth(transport, options.UserName, options.AuthenticationBanner);
        await auth.RequestServiceAsync(cancellationToken).ConfigureAwait(false);

        // Like ssh: "none" first (it succeeds only on servers that allow anonymous access, and otherwise lists the methods the server
        // accepts), then each method in order. After a partial success the server lists what it still wants, which may be a method
        // earlier in the order (AuthenticationMethods password,publickey), so the order is walked again.
        SshLog.Authenticating(logger, "none");
        var outcome = await auth.NoneAsync(cancellationToken).ConfigureAwait(false);
        if (outcome.Success)
        {
            SshLog.Authenticated(logger, "none");
            return;
        }

        var order = options.AuthenticationOrder ?? DefaultAuthenticationOrder;
        var methods = outcome.RemainingMethods;
        var passes = 0;
        bool progressed;
        do
        {
            progressed = false;
            for (var step = 0; step < order.Count; step++)
            {
                AuthOutcome? result = null;
                switch (order[step])
                {
                    case "publickey":
                        foreach (var key in options.PrivateKeys)
                        {
                            if (!methods.Contains("publickey"))
                            {
                                break;
                            }

                            if (SshUserAuth.ChooseSignatureAlgorithm(key, transport.ServerExtensions) is not { } algorithm)
                            {
                                continue; // the server accepts no signature algorithm this key can make (for example an RSA key and no rsa-sha2-*)
                            }

                            SshLog.Authenticating(logger, "publickey");
                            try
                            {
                                result = await auth.PublicKeyAsync(key, algorithm, cancellationToken).ConfigureAwait(false);
                            }
                            catch (SshException ex) when (ex.Reason == SshFailureReason.AgentFailed)
                            {
                                // The agent lost the key or the user declined to confirm: the next key may still do.
                                SshLog.AgentKeySkipped(logger, key.Fingerprint, ex.Message);
                                result = null;
                                continue;
                            }

                            if (result.Success || result.PartialSuccess)
                            {
                                break;
                            }

                            methods = result.RemainingMethods;
                        }

                        break;

                    case "keyboard-interactive" when methods.Contains("keyboard-interactive"):
                        var respond = options.KeyboardInteractive;
                        if (respond is null && options.Password is { } secret && !(methods.Contains("password") && order.Skip(step + 1).Contains("password")))
                        {
                            respond = AnswerWithPassword(secret); // a server that takes passwords only this way (PAM)
                        }

                        if (respond is not null)
                        {
                            SshLog.Authenticating(logger, "keyboard-interactive");
                            result = await auth.KeyboardInteractiveAsync(respond, cancellationToken).ConfigureAwait(false);
                        }

                        break;

                    case "password" when options.Password is { } password && methods.Contains("password"):
                        SshLog.Authenticating(logger, "password");
                        result = await auth.PasswordAsync(password, cancellationToken).ConfigureAwait(false);
                        break;
                }

                if (result is null)
                {
                    continue;
                }

                if (result.Success)
                {
                    SshLog.Authenticated(logger, order[step]);
                    return;
                }

                methods = result.RemainingMethods;
                progressed |= result.PartialSuccess;
            }
        }
        while (progressed && ++passes < MaxAuthenticationPasses);

        SshLog.AuthenticationFailed(logger, string.Join(", ", methods));
        throw new SshAuthenticationException($"Authentication failed. The server accepts: {string.Join(", ", methods)}.", methods);
    }

    /// <summary>
    /// Answers keyboard-interactive with the password: a round with no questions gets no answers, and the first round that asks for exactly
    /// one hidden input gets the password. Anything else (a second password round, a one-time code, a visible question) ends the attempt.
    /// </summary>
    private static Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>> AnswerWithPassword(string password)
    {
        var answered = false;
        return (request, _) =>
        {
            if (request.Prompts.Count == 0)
            {
                return new ValueTask<IReadOnlyList<string>?>([]);
            }

            if (answered || request.Prompts.Count != 1 || request.Prompts[0].Echo)
            {
                return new ValueTask<IReadOnlyList<string>?>((IReadOnlyList<string>?)null);
            }

            answered = true;
            return new ValueTask<IReadOnlyList<string>?>([password]);
        };
    }
}