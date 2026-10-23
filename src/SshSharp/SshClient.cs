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

    /// <summary>The options this client was connected with (for tests of what ssh_config resolution passes on).</summary>
    internal SshClientOptions Options => _options;
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

    /// <summary>What binds an agent connection to this session; forwarded agent connections are bound with it (<c>is_forwarding</c>).</summary>
    internal AgentBinding? AgentBinding { get; init; }

    /// <summary>The keys the server accepted during authentication (a success, or a partial success on the way), for AddKeysToAgent.</summary>
    internal IReadOnlyList<SshPrivateKey> AcceptedKeys { get; private set; } = [];

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
    /// The session identifier (RFC 4253 section 7.2): the exchange hash of the first key exchange, which stays the same for the
    /// connection's life, re-exchanges included. Both sides know it, and signatures made during authentication are bound to it, so it
    /// identifies this connection, for example to correlate with the server's records or to bind something of your own to it. It is not
    /// secret. This is a copy, which stays readable after the client is disposed.
    /// </summary>
    public ReadOnlyMemory<byte> SessionId { get; private init; }

    /// <summary>When the connection was established (the moment authentication succeeded), in UTC.</summary>
    public DateTimeOffset ConnectedAt { get; private init; }

    /// <summary>
    /// The address and port of the server, as the TCP connection sees it, when the connection runs over a socket: a TCP connection
    /// SshSharp made (with <see cref="ConnectAsync(string, int, SshClientOptions, CancellationToken)"/>, or by <c>ssh_config</c> alias
    /// without a jump host or proxy command), or a <see cref="NetworkStream"/> passed to
    /// <see cref="ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>. Through an HTTP or SOCKS proxy it is the proxy's
    /// address. Null over any other stream (a ProxyJump tunnel, a ProxyCommand, a pipe). Read once, when the connection is made. An IPv4
    /// address is given as such, not in the IPv4-mapped IPv6 form (<c>::ffff:192.0.2.1</c>) a dual-mode socket reports.
    /// </summary>
    public System.Net.EndPoint? RemoteEndPoint { get; private init; }

    /// <summary>The local address and port of the TCP connection, under the same conditions as <see cref="RemoteEndPoint"/>; null otherwise.</summary>
    public System.Net.EndPoint? LocalEndPoint { get; private init; }

    /// <summary>
    /// SSH message bytes sent over the connection so far, from the key exchange on: the payload of each packet, key exchange messages
    /// (KEXINIT, NEWKEYS, EXT_INFO) included, before compression, encryption, padding and MAC, as the <c>sshsharp.bytes.sent</c> metric counts them.
    /// Safe to read from any thread.
    /// </summary>
    public long BytesSent => _connection.BytesSent;

    /// <summary>SSH message bytes received over the connection so far, counted as <see cref="BytesSent"/> is (after decryption and decompression).</summary>
    public long BytesReceived => _connection.BytesReceived;

    /// <summary>
    /// Re-exchanges keys now, as ssh's <c>~R</c> escape does, and completes once the new keys are in use in both directions. Keys are also
    /// renewed on their own after <see cref="SshClientOptions.RekeyAfterBytes"/> or <see cref="SshClientOptions.RekeyAfterTime"/>, and when
    /// the server asks; if a re-exchange is already running, this waits for it instead of starting another. Channels stay open: data waits
    /// while the keys change and then continues. The host key must be the same as at the start, or the connection fails.
    /// </summary>
    /// <param name="cancellationToken">Stops waiting. Once started, the exchange continues; the connection cannot go back to the old keys.</param>
    /// <exception cref="SshException">The connection is closed or failed, or failed during the exchange.</exception>
    public Task RekeyAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return _connection.RekeyAsync(cancellationToken);
    }

    /// <summary>
    /// Whether the connection is still up: false once the server disconnected, the connection failed (including a missed keep-alive,
    /// see <see cref="SshClientOptions.KeepAliveInterval"/>), or the client was disposed.
    /// </summary>
    public bool IsConnected => _disposed == 0 && _connection.Failure is null;

    /// <summary>Cancelled when the connection ends for any reason, so pending work can stop or reconnect. <see cref="ConnectionError"/> says why.</summary>
    public CancellationToken ConnectionClosed => _connection.Closed;

    /// <summary>Why the connection ended (an <see cref="SshException"/>, usually), or null while it is up.</summary>
    public Exception? ConnectionError => _connection.Failure;

    /// <summary>
    /// Measures the round trip to the server and proves the connection is alive. OpenSSH 9.5 and later answer a transport ping
    /// (<c>ping@openssh.com</c>); other servers get a <c>keepalive@openssh.com</c> request, whose answer arrives just as quickly.
    /// </summary>
    /// <exception cref="SshException">The connection is closed or failed meanwhile.</exception>
    public Task<TimeSpan> PingAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return _connection.PingAsync(cancellationToken);
    }

    /// <summary>
    /// Opens no more sessions on this connection (commands, shells, SFTP), and tells an OpenSSH server to refuse any as well, as ssh does
    /// once it knows it will not open another (OpenSSH's <c>no-more-sessions@openssh.com</c>): a process that later gets hold of this
    /// connection cannot quietly start a session on it, and an OpenSSH server drops the connection if one is tried anyway. Sessions already
    /// open, port forwarding and tunnels are unaffected. Like ssh, the request goes only to OpenSSH servers (some others abort on it);
    /// with others, only this client refuses.
    /// </summary>
    /// <returns>Whether the server was told; false for servers other than OpenSSH.</returns>
    /// <exception cref="SshException">The connection is closed or failed meanwhile.</exception>
    public Task<bool> PreventNewSessionsAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return _connection.PreventNewSessionsAsync(cancellationToken);
    }

    /// <summary>
    /// Connects to <paramref name="host"/> over TCP, performs the handshake and authenticates. <see cref="SshClientOptions.ConnectTimeout"/>
    /// bounds the whole attempt, and <see cref="SshClientOptions.AddressFamily"/> chooses which of the host's addresses are tried. With
    /// <see cref="SshClientOptions.JumpHosts"/>, the server is reached through them, and <paramref name="host"/> is resolved by the last one.
    /// </summary>
    /// <exception cref="SshException">The server could not be reached (<see cref="SshFailureReason.ConnectFailed"/>), the attempt took longer
    /// than <see cref="SshClientOptions.ConnectTimeout"/> (<see cref="SshFailureReason.Timeout"/>), or the handshake or authentication
    /// failed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public static async Task<SshClient> ConnectAsync(string host, int port, SshClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        ArgumentNullException.ThrowIfNull(options);

        // Algorithm lists that leave nothing to offer fail here, before the network is touched (the jump hosts' too).
        _ = options.AlgorithmPreferences ?? AlgorithmPreferences.FromOptions(options);
        foreach (var jump in options.JumpHosts)
        {
            _ = jump.Options.AlgorithmPreferences ?? AlgorithmPreferences.FromOptions(jump.Options);
        }

        IReadOnlyList<System.Net.IPEndPoint>? local = options.LocalEndPoint is { } bind ? [bind] : null;

        // On the clock that times the waits between ConnectionAttempts, so the two are measured alike.
        using var deadline = new ConnectDeadline(options.ConnectTimeout, cancellationToken, options.TimeProvider);
        using var measurement = new ConnectMeasurement(options.Proxy is null && options.JumpHosts.Count == 0 ? port : null);
        try
        {
            Stream stream;
            Owned? owner = null;
            try
            {
                // The host name stays out of error messages (exception text often ends up in logs); it is in the caller's hands already.
                if (options.JumpHosts.Count > 0)
                {
                    (stream, owner) = await ConnectThroughJumpHostsAsync(host, port, options, local, deadline.Token).ConfigureAwait(false);
                }
                else
                {
                    stream = await OpenStreamAsync(host, port, options, local, "the server", deadline.Token).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (!deadline.Expired)
            {
                measurement.Failed(ex);
                throw;
            }

            try
            {
                return await ConnectCoreAsync(stream, options, leaveOpen: false, owner, host, port, measurement, deadline.Token).ConfigureAwait(false);
            }
            catch when (owner is not null)
            {
                // The chain of jump hosts goes with the connection that failed to start over it.
                await owner.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch (OperationCanceledException) when (deadline.Expired)
        {
            var error = deadline.Error();
            measurement.Failed(error); // unless the handshake already recorded its own failure
            throw error;
        }
    }

    /// <summary>Runs the SSH protocol over an existing stream (a socket, a WebSocket wrapper, a tunnel from another connection, ...).</summary>
    /// <param name="stream">A connected, duplex stream.</param>
    /// <param name="options">Connection options. <see cref="SshClientOptions.ConnectTimeout"/> bounds the handshake and authentication.</param>
    /// <param name="leaveOpen">Whether to leave <paramref name="stream"/> open when the client is disposed.</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    public static async Task<SshClient> ConnectAsync(Stream stream, SshClientOptions options, bool leaveOpen = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        using var deadline = new ConnectDeadline(options.ConnectTimeout, cancellationToken, options.TimeProvider);
        try
        {
            return await ConnectCoreAsync(stream, options, leaveOpen, owner: null, host: null, port: 22, measurement: null, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.Expired)
        {
            throw deadline.Error();
        }
    }

    /// <summary>Runs <paramref name="command"/> on the server and collects its output and exit status.</summary>
    /// <remarks>
    /// The command's standard input stays open and empty: a command that reads it waits until it is cancelled. To give it input, or to
    /// close its input, use <see cref="RunCommandAsync(string, SshSessionOptions?, SshCommandInput?, CancellationToken)"/>.
    /// </remarks>
    /// <exception cref="SshException">The server refused the command or the connection failed.</exception>
    /// <exception cref="InvalidOperationException">The output exceeded <see cref="SshClientOptions.MaxCommandOutputBytes"/>.</exception>
    public Task<SshCommandResult> RunCommandAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        return RunCommandCoreAsync(command, session: null, standardInput: null, cancellationToken);
    }

    /// <summary>
    /// Runs <paramref name="command"/> on the server with environment variables, a terminal or standard input, and collects its output and
    /// exit status. The session is set up as <see cref="StartCommandAsync"/> sets it up. <paramref name="standardInput"/> is written while
    /// the output is collected, and end-of-file follows it (at once when there is none), so a command that reads its input to the end
    /// (<c>cat</c>, <c>sh -s</c>) finishes. A command that exits without reading all of its input is not an error.
    /// </summary>
    /// <param name="command">The command line, run by the user's login shell.</param>
    /// <param name="options">Environment variables (sent as <c>env</c> requests, which servers accept only for the names they allow) and a
    /// terminal; null for neither. With a terminal, the server merges standard error into standard output, and the input goes through the
    /// terminal, which echoes it and does not pass end-of-file on to the program.</param>
    /// <param name="standardInput">The command's standard input, or null for none (empty input).</param>
    /// <param name="cancellationToken">Cancels the command: the session is closed, and the server hangs up on the program.</param>
    /// <exception cref="SshException">The server refused the terminal or the command, or the connection failed.</exception>
    /// <exception cref="InvalidOperationException">The output exceeded <see cref="SshClientOptions.MaxCommandOutputBytes"/>.</exception>
    public Task<SshCommandResult> RunCommandAsync(string command, SshSessionOptions? options, SshCommandInput? standardInput = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var (terminal, environment) = ValidateSessionOptions(options);
        return RunCommandCoreAsync(command, new SessionSetup(terminal, environment), standardInput, cancellationToken);
    }

    /// <summary>The validated terminal and environment of <see cref="SshSessionOptions"/>.</summary>
    private readonly record struct SessionSetup(SshTerminalOptions? Terminal, IReadOnlyDictionary<string, string> Environment);

    /// <summary>
    /// Runs a command and collects its output. Without <paramref name="session"/>, as 1.0 does: agent forwarding if configured, then
    /// <c>exec</c>, with standard input left open. With it, the session requests of <see cref="StartCommandAsync"/>, then the input and
    /// end-of-file.
    /// </summary>
    private async Task<SshCommandResult> RunCommandCoreAsync(string command, SessionSetup? session, SshCommandInput? standardInput, CancellationToken cancellationToken)
    {
        using var activity = SshTelemetry.Activities.StartActivity("SshSharp.Command");
        var outcome = "error";
        string? errorType = null;
        var channel = await _connection.OpenSessionAsync(cancellationToken).ConfigureAwait(false);

        // Stops the input writer when the command ends or fails, and stops the output reader when the input fails.
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var writing = Task.CompletedTask;
        try
        {
            SshLog.CommandStarting(_logger, command.Length, channel.LocalId);
            if (session is { } setup)
            {
                await RequestSessionAsync(channel, "exec", command, setup, cancellationToken).ConfigureAwait(false);
                writing = WriteInputAsync(channel, standardInput, stop);
            }
            else
            {
                // As every session does (ForwardAgent's contract); before 1.1 this one did not ask (#287).
                await RequestAgentForwardingAsync(channel, cancellationToken).ConfigureAwait(false);
                if (!await channel.RequestAsync("exec", true, w => w.WriteString(command), cancellationToken).ConfigureAwait(false))
                {
                    throw new SshException(SshFailureReason.ChannelClosed, "The server refused to execute the command.");
                }
            }

            var stdout = new ArrayBufferWriter<byte>();
            ArrayBufferWriter<byte>? stderr = null; // most commands write nothing there
            long total = 0;
            while (await channel.ReadAsync(stop.Token).ConfigureAwait(false) is { } chunk)
            {
                using (chunk)
                {
                    total += chunk.Data.Length;
                    if (total > _options.MaxCommandOutputBytes)
                    {
                        throw new InvalidOperationException($"The command produced more than {_options.MaxCommandOutputBytes} bytes of output.");
                    }

                    (chunk.IsExtended ? stderr ??= new ArrayBufferWriter<byte>() : stdout).Write(chunk.Data.Span);
                }
            }

            // The exit status arrives before the server's CLOSE.
            await channel.WaitClosedAsync(stop.Token).ConfigureAwait(false);

            // Input the command never read is no failure; a local error reading the input stream is. Only the writer cancels stop on its
            // own (the caller's token cancels it too, but then the read above throws): it failed, and is about to throw, so wait for it.
            if (stop.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                await writing.ConfigureAwait(false);
            }

            await stop.CancelAsync().ConfigureAwait(false);
            if (writing.IsCompleted)
            {
                await writing.ConfigureAwait(false);
            }
            int? exitStatus = channel.ExitStatus is { } status ? (int)status : null;
            outcome = exitStatus == 0 ? "success" : "failure";
            activity?.SetTag("ssh.command.exit_status", exitStatus);
            SshLog.CommandFinished(_logger, channel.LocalId, exitStatus, channel.ExitSignal?.Name);
            return new SshCommandResult(exitStatus, channel.ExitSignal, stdout.WrittenMemory, stderr?.WrittenMemory ?? ReadOnlyMemory<byte>.Empty);
        }
        catch (OperationCanceledException ex) when (stop.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Only the writer cancels stop while the output is read (the caller's token cancels it too, but that is excluded here): writing
            // the input failed (the stream threw, or the connection failed), which stopped the output reader, so report that error. The
            // writer cancels stop just before it throws, so it is finishing: wait for it rather than race it.
            await writing.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            if (!writing.IsFaulted)
            {
                errorType = SshTelemetry.Failed(activity, ex);
                throw;
            }

            var failure = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(writing.Exception!.InnerException!);
            errorType = SshTelemetry.Failed(activity, failure.SourceException);
            failure.Throw();
            throw;
        }
        catch (Exception ex)
        {
            errorType = SshTelemetry.Failed(activity, ex);
            throw;
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);

            // The writer is not waited for: a stream whose ReadAsync ignores cancellation would hold the call after the command ended.
            // Stopped, it sends nothing more (the channel is closed below) and returns its buffer itself whenever the read returns. Its
            // failure was already reported above, or the run failed first and that is what the caller sees; either way it is observed.
            _ = writing.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);

            var tags = new TagList { { "result", outcome } };
            if (errorType is not null)
            {
                tags.Add("error.type", errorType);
            }

            SshTelemetry.Commands.Add(1, tags);
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
    /// output fits in memory, <see cref="RunCommandAsync(string, SshSessionOptions?, SshCommandInput?, CancellationToken)"/> is simpler.
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

    /// <summary>
    /// Writes the input, then end-of-file. The command may stop reading its input, or exit, before all of it is sent: that is how a pipe
    /// behaves, and not an error. Any other failure cancels <paramref name="stop"/>, so the output reader stops, and faults the task.
    /// </summary>
    private static async Task WriteInputAsync(SshChannel channel, SshCommandInput? input, CancellationTokenSource stop)
    {
        // Taken now: the run may end, and dispose stop, while this writer still waits on a stream that ignores cancellation.
        var token = stop.Token;
        try
        {
            if (input is not null)
            {
                await input.WriteToAsync(channel, token).ConfigureAwait(false);
            }

            await channel.SendEofAsync(token).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex.Reason == SshFailureReason.ChannelClosed)
        {
            // The command closed its input (eow@openssh.com) or ended and the channel closed: the rest of the input is not wanted.
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // The command ended, failed or was cancelled; the output reader reports which.
        }
        catch (Exception)
        {
            // Once stopped, RunCommandAsync may have returned without waiting for this writer and disposed stop: cancel only before that.
            if (!stop.IsCancellationRequested)
            {
                await stop.CancelAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    /// <summary>Checks the terminal and environment of <paramref name="options"/> before anything is sent.</summary>
    private static (SshTerminalOptions? Terminal, IReadOnlyDictionary<string, string> Environment) ValidateSessionOptions(SshSessionOptions? options)
    {
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

        return (terminal, environment);
    }

    private async Task<SshSession> StartSessionAsync(string kind, string? command, SshSessionOptions? options, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var (terminal, environment) = ValidateSessionOptions(options);
        var channel = await _connection.OpenSessionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            channel.SplitExtended = true;
            await RequestSessionAsync(channel, kind, command, new SessionSetup(terminal, environment), cancellationToken).ConfigureAwait(false);
            SshLog.SessionStarted(_logger, kind, channel.LocalId, terminal is not null);
            // As ssh: only a session with a terminal is typed into.
            var obfuscator = terminal is not null && _options.ObscureKeystrokeTiming is { } interval
                ? new KeystrokeTimingObfuscator(channel, _connection, interval)
                : null;
            return new SshSession(channel, terminal is not null, _logger, () => _connection.Failure is not null, obfuscator);
        }
        catch
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
            throw;
        }
    }

    /// <summary>With <see cref="SshClientOptions.ForwardAgent"/>, asks the server to forward the agent on this session.</summary>
    private async Task RequestAgentForwardingAsync(SshChannel channel, CancellationToken cancellationToken)
    {
        if (_options.ForwardAgent is not null)
        {
            // No reply, as ssh sends it: a server that does not forward agents just ignores it. RFC 9987 names the request "agent-req",
            // to be used only when the server announces "agent-forward"; otherwise OpenSSH's name, which servers have long understood.
            EnsureChannelDispatch();
            var request = _connection.ServerExtensions.ContainsKey("agent-forward") ? "agent-req" : "auth-agent-req@openssh.com";
            await channel.RequestAsync(request, false, null, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Sends a session's requests, in ssh's order: the terminal, agent forwarding, the environment, then the program.</summary>
    private async Task RequestSessionAsync(SshChannel channel, string kind, string? command, SessionSetup setup, CancellationToken cancellationToken)
    {
        var (terminal, environment) = setup;
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

        await RequestAgentForwardingAsync(channel, cancellationToken).ConfigureAwait(false);
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

    // measurement: the caller's, started before it made the network connection; null to measure from here.
    private static async Task<SshClient> ConnectCoreAsync(Stream stream, SshClientOptions options, bool leaveOpen, IAsyncDisposable? owner, string? host, int port,
        ConnectMeasurement? measurement, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var logger = options.Logger ?? NullLogger.Instance;
        using var own = measurement is null ? new ConnectMeasurement(tcpPort: null) : null;
        measurement ??= own!;

        SshTransportOptions transportOptions;
        try
        {
            transportOptions = await TransportOptionsAsync(options, host, port, logger, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            measurement.Failed(ex);
            // The stream is this method's to dispose from the start, also when preparing fails (a cancellation while known_hosts is read).
            if (!leaveOpen)
            {
                await DisposeQuietlyAsync(stream).ConfigureAwait(false);
            }

            throw;
        }

        var transport = new SshTransport(stream, transportOptions);
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            var acceptedKeys = new List<SshPrivateKey>();
            await AuthenticateAsync(transport, options, transportOptions.Preferences.PublicKeys, logger, acceptedKeys, host, port, cancellationToken)
                .ConfigureAwait(false);
            var client = CompleteConnection(transport, stream, options, leaveOpen, owner, host, port, logger, measurement);
            client.AcceptedKeys = acceptedKeys;
            return client;
        }
        catch (Exception ex)
        {
            measurement.Failed(ex is IOException ? SshConnection.ConnectionLost(ex) : ex);

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

    private static async Task DisposeQuietlyAsync(Stream stream)
    {
        try
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Already broken.
        }
    }

    /// <summary>The transport's settings: algorithm preferences (certificate host keys first when an authority is trusted) and host key checks.</summary>
    private static async Task<SshTransportOptions> TransportOptionsAsync(SshClientOptions options, string? host, int port, ILogger logger, CancellationToken cancellationToken)
    {
        var preferences = options.AlgorithmPreferences ?? AlgorithmPreferences.FromOptions(options);
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

        return new SshTransportOptions
        {
            ClientIdentification = SshIdentification.ForClient(options.VersionAddendum),
            Preferences = preferences,
            MinimumRsaBits = options.RequiredRsaSize,
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
    }

    /// <summary>Starts the connection layer over an authenticated transport and records the outcome.</summary>
    private static SshClient CompleteConnection(SshTransport transport, Stream stream, SshClientOptions options, bool leaveOpen, IAsyncDisposable? owner,
        string? host, int port, ILogger logger, ConnectMeasurement measurement)
    {
        var activity = measurement.Activity;
        var hostKey = transport.HostKey!;
        var algorithms = transport.Algorithms!;
        var publicHostKey = new SshHostKey(hostKey.Algorithm, hostKey.KeyType, hostKey.Fingerprint, hostKey.Blob, hostKey.KeySizeBits) { Certificate = hostKey.Certificate };
        var connection = new SshConnection(transport, logger, options.TimeProvider)
        {
            ChannelWindowSize = (uint)options.ChannelWindowSize,
            // A packet larger than the window could never be sent whole, so the window bounds it.
            ChannelMaxPacketSize = (uint)Math.Min(options.ChannelMaxPacketSize, options.ChannelWindowSize),
        };

        // Before the receive loop starts: the server announces its host keys right after authentication.
        WatchHostKeyUpdates(connection, options, host, port, publicHostKey, logger);
        connection.Start();
        if (options.EffectiveKeepAliveInterval is { } keepAlive)
        {
            connection.StartKeepAlive(keepAlive, options.KeepAliveCountMax);
        }

        connection.StartChannelTimeouts(options.ChannelTimeouts);
        SshTelemetry.Connections.Add(1);
        var postQuantum = SshAlgorithms.IsPostQuantum(algorithms.Kex);
        measurement.Succeeded(postQuantum);
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

        var (remote, local) = EndPointsOf(stream);
        return new SshClient(
            connection, options, stream, leaveOpen, owner, transport.ServerIdentification!.Line,
            publicHostKey, logger)
        {
            AgentBinding = transport.AgentBinding,
            // A copy: the transport wipes its own when the connection is disposed, and the caller cannot reach it through this one.
            SessionId = transport.SessionId!.AsSpan().ToArray(),
            ConnectedAt = options.TimeProvider.GetUtcNow(),
            RemoteEndPoint = remote,
            LocalEndPoint = local,
        };
    }

    /// <summary>The endpoints of the socket under <paramref name="stream"/>, when it is a <see cref="NetworkStream"/>; read once, while it is open.</summary>
    private static (System.Net.EndPoint? Remote, System.Net.EndPoint? Local) EndPointsOf(Stream stream)
    {
        if (stream is not NetworkStream { Socket: var socket })
        {
            return (null, null);
        }

        try
        {
            return (Unmapped(socket.RemoteEndPoint), Unmapped(socket.LocalEndPoint));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return (null, null); // already closed: the connection fails on its own
        }

        // A dual-mode socket (a NetworkStream the caller passed may have one; SshSharp's own sockets have the address's family) reports
        // an IPv4 peer as ::ffff:a.b.c.d: give the address that was reached.
        static System.Net.EndPoint? Unmapped(System.Net.EndPoint? endPoint) =>
            endPoint is System.Net.IPEndPoint { Address.IsIPv4MappedToIPv6: true } ip ? new System.Net.IPEndPoint(ip.Address.MapToIPv4(), ip.Port) : endPoint;
    }

    /// <summary>ssh's default order, less hostbased (not implemented); gssapi-with-mic is tried only with <see cref="SshClientOptions.Gssapi"/>.</summary>
    internal static readonly string[] DefaultAuthenticationOrder = [SshUserAuth.GssapiMethod, "publickey", "keyboard-interactive", "password"];

    /// <summary>Walks of the method order; each one after the first needs a partial success, so this bounds a server that never finishes.</summary>
    private const int MaxAuthenticationPasses = 8;

    /// <summary>Requests for a new password the client answers for one password, before it treats the password as expired and unchanged.</summary>
    internal const int MaxPasswordChangeRequests = 3;

    /// <summary>
    /// Authenticates in a span of its own (<c>SshSharp.Authenticate</c>, inside the connect span): the method that got in and the
    /// requests it took, or <c>error.type</c>. Never the user name, nor which keys were offered.
    /// </summary>
    private static async Task AuthenticateAsync(SshTransport transport, SshClientOptions options, IReadOnlyList<string>? allowedSignatures, ILogger logger,
        List<SshPrivateKey> acceptedKeys, string? host, int port, CancellationToken cancellationToken)
    {
        using var activity = SshTelemetry.Activities.StartActivity("SshSharp.Authenticate");
        var auth = new SshUserAuth(transport, options.UserName, options.AuthenticationBanner);
        try
        {
            var method = await AuthenticateCoreAsync(auth, transport, options, allowedSignatures, logger, acceptedKeys, host, port, cancellationToken)
                .ConfigureAwait(false);
            activity?.SetTag("ssh.auth.method", method);
        }
        catch (Exception ex)
        {
            // As the connect span reports it: a stream that failed is a lost connection.
            SshTelemetry.Failed(activity, ex is IOException ? SshConnection.ConnectionLost(ex) : ex);
            throw;
        }
        finally
        {
            activity?.SetTag("ssh.auth.attempts", auth.Attempts);
        }
    }

    /// <summary>Walks the methods until one gets in, and returns its name; throws <see cref="SshAuthenticationException"/> when none does.</summary>
    private static async Task<string> AuthenticateCoreAsync(SshUserAuth auth, SshTransport transport, SshClientOptions options, IReadOnlyList<string>? allowedSignatures,
        ILogger logger, List<SshPrivateKey> acceptedKeys, string? host, int port, CancellationToken cancellationToken)
    {
        await auth.RequestServiceAsync(cancellationToken).ConfigureAwait(false);

        // Like ssh: "none" first (it succeeds only on servers that allow anonymous access, and otherwise lists the methods the server
        // accepts), then each method in order. After a partial success the server lists what it still wants, which may be a method
        // earlier in the order (AuthenticationMethods password,publickey), so the order is walked again.
        SshLog.Authenticating(logger, "none");
        var outcome = await auth.NoneAsync(cancellationToken).ConfigureAwait(false);
        if (outcome.Success)
        {
            SshLog.Authenticated(logger, "none");
            return "none";
        }

        var order = options.PreferredAuthentications ?? DefaultAuthenticationOrder;
        var methods = outcome.RemainingMethods;

        // What each attempt came to, for the exception if none succeeds: methods and key fingerprints only, never a secret or the user.
        var attempts = new List<SshAuthenticationAttempt>();
        var reported = new HashSet<string>(StringComparer.Ordinal); // methods already listed as not offered or unavailable
        void Report(string method, SshAuthenticationOutcome what)
        {
            if (reported.Add(method))
            {
                attempts.Add(new SshAuthenticationAttempt(method, what));
            }
        }

        void Record(string method, AuthOutcome result, string? fingerprint = null)
        {
            if (!result.Success)
            {
                attempts.Add(new SshAuthenticationAttempt(method, result.PartialSuccess ? SshAuthenticationOutcome.PartialSuccess : SshAuthenticationOutcome.Rejected, fingerprint));
            }
        }

        var passwords = new PasswordSource(options, host, port);
        var passwordThroughKeyboard = false;
        var passes = 0;
        bool progressed;
        do
        {
            progressed = false;
            if (passes > 0)
            {
                passwords.NewPass();
            }

            for (var step = 0; step < order.Count; step++)
            {
                AuthOutcome? result = null;
                switch (order[step])
                {
                    case SshUserAuth.GssapiMethod when options.Gssapi is { } gssapi:
                        if (!methods.Contains(SshUserAuth.GssapiMethod))
                        {
                            Report(SshUserAuth.GssapiMethod, SshAuthenticationOutcome.NotOffered);
                            break;
                        }

                        if (!Gssapi.IsSupported || (gssapi.TargetHost ?? host) is not { Length: > 0 } target)
                        {
                            Report(SshUserAuth.GssapiMethod, SshAuthenticationOutcome.Unavailable);
                            break;
                        }

                        IGssapiContext context;
                        try
                        {
                            context = gssapi.ContextFactory(target, gssapi.Credential, gssapi.DelegateCredentials);
                        }
                        catch (Exception ex) when (ex is PlatformNotSupportedException or DllNotFoundException or EntryPointNotFoundException
                            or InvalidOperationException or System.ComponentModel.Win32Exception)
                        {
                            // No GSS-API library or provider here (libgssapi missing on Linux, say): the other methods remain.
                            var reason = ex.GetType().Name;
                            SshLog.GssapiUnavailable(logger, reason);
                            Report(SshUserAuth.GssapiMethod, SshAuthenticationOutcome.Unavailable);
                            break;
                        }

                        using (context)
                        {
                            SshLog.Authenticating(logger, SshUserAuth.GssapiMethod);
                            result = await auth.GssapiAsync(context, cancellationToken).ConfigureAwait(false);
                        }

                        if (result is null)
                        {
                            attempts.Add(new SshAuthenticationAttempt(SshUserAuth.GssapiMethod, SshAuthenticationOutcome.Unavailable)); // no ticket, say
                        }
                        else
                        {
                            Record(SshUserAuth.GssapiMethod, result);
                        }

                        break;

                    case "publickey" when options.PrivateKeys.Count > 0:
                        if (!methods.Contains("publickey"))
                        {
                            Report("publickey", SshAuthenticationOutcome.NotOffered);
                            break;
                        }

                        foreach (var key in options.PrivateKeys)
                        {
                            if (!methods.Contains("publickey"))
                            {
                                break;
                            }

                            if (SshUserAuth.ChooseSignatureAlgorithm(key, transport.ServerExtensions, allowedSignatures) is not { } algorithm)
                            {
                                // The server accepts no signature algorithm this key can make (for example an RSA key and no rsa-sha2-*),
                                // or PubkeyAcceptedAlgorithms allows none of them: as ssh, the key is not offered.
                                attempts.Add(new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.NoAcceptedAlgorithm, key.Fingerprint));
                                continue;
                            }

                            SshLog.Authenticating(logger, "publickey");
                            try
                            {
                                result = await auth.PublicKeyAsync(key, algorithm, cancellationToken).ConfigureAwait(false);
                            }
                            catch (SshException ex) when (ex.Reason == SshFailureReason.AgentFailed)
                            {
                                // The agent lost the key or the user declined to confirm: the next key may still do.
                                SshLog.AgentKeySkipped(logger, key.Fingerprint, new(ex));
                                attempts.Add(new SshAuthenticationAttempt("publickey", SshAuthenticationOutcome.SigningFailed, key.Fingerprint));
                                result = null;
                                continue;
                            }

                            Record("publickey", result, key.Fingerprint);
                            if (result.Success || result.PartialSuccess)
                            {
                                acceptedKeys.Add(key);
                                break;
                            }

                            methods = result.RemainingMethods;
                        }

                        break;

                    case "keyboard-interactive":
                        if (options.KeyboardInteractive is { } respond)
                        {
                            if (!methods.Contains("keyboard-interactive"))
                            {
                                Report("keyboard-interactive", SshAuthenticationOutcome.NotOffered);
                                break;
                            }

                            SshLog.Authenticating(logger, "keyboard-interactive");
                            result = await auth.KeyboardInteractiveAsync(respond, cancellationToken).ConfigureAwait(false);
                            if (result is null)
                            {
                                attempts.Add(new SshAuthenticationAttempt("keyboard-interactive", SshAuthenticationOutcome.Declined));
                            }
                            else
                            {
                                Record("keyboard-interactive", result);
                            }
                        }
                        else if (passwords.IsSet && methods.Contains("keyboard-interactive")
                            && !(methods.Contains("password") && order.Skip(step + 1).Contains("password")))
                        {
                            // A server that takes passwords only this way (PAM): the password answers a single hidden question.
                            passwordThroughKeyboard = true;
                            result = await PasswordThroughKeyboardInteractiveAsync(auth, passwords, attempts, logger, cancellationToken).ConfigureAwait(false);
                        }

                        break;

                    case "password" when passwords.IsSet:
                        if (!methods.Contains("password"))
                        {
                            if (!passwordThroughKeyboard)
                            {
                                Report("password", SshAuthenticationOutcome.NotOffered);
                            }

                            break;
                        }

                        while (passwords.HasMore)
                        {
                            var (password, declined) = await passwords.NextAsync("password", cancellationToken).ConfigureAwait(false);
                            if (password is null)
                            {
                                if (declined)
                                {
                                    attempts.Add(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.Declined));
                                }

                                break;
                            }

                            SshLog.Authenticating(logger, "password");
                            var sent = await SendPasswordAsync(auth, options, password, host, port, attempts, cancellationToken).ConfigureAwait(false);
                            if (sent is null)
                            {
                                break; // expired and not changed: another password would not be the answer
                            }

                            result = sent;
                            if (result.Success || result.PartialSuccess)
                            {
                                break;
                            }

                            passwords.Rejected();
                            methods = result.RemainingMethods;
                            if (!methods.Contains("password"))
                            {
                                break;
                            }
                        }

                        break;
                }

                if (result is null)
                {
                    continue;
                }

                if (result.Success)
                {
                    SshLog.Authenticated(logger, order[step]);
                    return order[step];
                }

                methods = result.RemainingMethods;
                progressed |= result.PartialSuccess;
            }
        }
        while (progressed && ++passes < MaxAuthenticationPasses);

        SshLog.AuthenticationFailed(logger, string.Join(", ", methods));
        var tried = attempts.Count > 0 ? $" Attempts: {string.Join("; ", attempts)}." : " No method was tried: give credentials for one of them.";
        throw new SshAuthenticationException($"Authentication failed. The server accepts: {string.Join(", ", methods)}.{tried}", methods, attempts);
    }

    /// <summary>
    /// Sends a password; when it has expired and the server asks for a new one (RFC 4252 section 8), asks
    /// <see cref="SshClientOptions.ChangePassword"/> and sends the change, up to <see cref="MaxPasswordChangeRequests"/> times. Returns the
    /// server's answer, or null when the password is expired and was not changed (recorded as such).
    /// </summary>
    private static async Task<AuthOutcome?> SendPasswordAsync(SshUserAuth auth, SshClientOptions options, string password, string? host, int port,
        List<SshAuthenticationAttempt> attempts, CancellationToken cancellationToken)
    {
        var result = await auth.PasswordAsync(password, cancellationToken).ConfigureAwait(false);
        for (var request = 1; result.ChangeRequest is { } change; request++)
        {
            string? newPassword = null;
            if (options.ChangePassword is { } changePassword && request <= MaxPasswordChangeRequests)
            {
                newPassword = await changePassword(new SshPasswordChangeRequest(change.Prompt, change.Language, options.UserName, host, port, request), cancellationToken)
                    .ConfigureAwait(false);
            }

            if (newPassword is null)
            {
                // Declined, no handler, or the server refused every new password: the password stays as it was. RFC 4252 forbids a
                // server to accept the expired one, so the next method is the way in, if any.
                attempts.Add(new SshAuthenticationAttempt("password", SshAuthenticationOutcome.PasswordChangeRequired));
                return null;
            }

            result = await auth.ChangePasswordAsync(password, newPassword, cancellationToken).ConfigureAwait(false);
        }

        if (!result.Success)
        {
            attempts.Add(new SshAuthenticationAttempt("password", result.PartialSuccess ? SshAuthenticationOutcome.PartialSuccess : SshAuthenticationOutcome.Rejected));
        }

        return result;
    }

    /// <summary>
    /// keyboard-interactive answered with the password (<see cref="PasswordSource"/>): again after each refusal, while the provider may
    /// be asked. Returns the last outcome, or null when no attempt was made or this side gave up (recorded as declined).
    /// </summary>
    private static async Task<AuthOutcome?> PasswordThroughKeyboardInteractiveAsync(SshUserAuth auth, PasswordSource passwords,
        List<SshAuthenticationAttempt> attempts, ILogger logger, CancellationToken cancellationToken)
    {
        AuthOutcome? last = null;
        while (passwords.HasMore)
        {
            var answer = new KeyboardInteractivePassword(passwords);
            SshLog.Authenticating(logger, "keyboard-interactive");
            var result = await auth.KeyboardInteractiveAsync(answer.RespondAsync, cancellationToken).ConfigureAwait(false);
            if (result is null)
            {
                // The questions were not a single password prompt (a one-time code, a second round), or the provider declined.
                attempts.Add(new SshAuthenticationAttempt("keyboard-interactive", SshAuthenticationOutcome.Declined));
                return last;
            }

            last = result;
            if (!result.Success)
            {
                attempts.Add(new SshAuthenticationAttempt("keyboard-interactive",
                    result.PartialSuccess ? SshAuthenticationOutcome.PartialSuccess : SshAuthenticationOutcome.Rejected));
            }

            if (result.Success || result.PartialSuccess || !answer.Answered || !result.RemainingMethods.Contains("keyboard-interactive"))
            {
                return result;
            }

            passwords.Rejected();
        }

        return last;
    }

    /// <summary>
    /// The passwords to try, in order: <see cref="SshClientOptions.Password"/>, then what <see cref="SshClientOptions.PasswordProvider"/>
    /// answers, at most <see cref="SshClientOptions.NumberOfPasswordPrompts"/> times per connection.
    /// </summary>
    private sealed class PasswordSource(SshClientOptions options, string? host, int port)
    {
        private bool _givenRejected;
        private bool _lastWasGiven;
        private bool _anyRejected;
        private bool _declined;
        private int _prompts;

        /// <summary>Whether there is a password, or a provider to ask for one.</summary>
        public bool IsSet => options.Password is not null || options.PasswordProvider is not null;

        /// <summary>Whether <see cref="NextAsync"/> may still give a password.</summary>
        public bool HasMore =>
            (options.Password is not null && !_givenRejected)
            || (options.PasswordProvider is not null && !_declined && _prompts < options.NumberOfPasswordPrompts);

        /// <summary>The next password; null when there is none left, with Declined when the provider just said to stop.</summary>
        public async ValueTask<(string? Password, bool Declined)> NextAsync(string method, CancellationToken cancellationToken)
        {
            if (options.Password is { } given && !_givenRejected)
            {
                _lastWasGiven = true;
                return (given, false);
            }

            if (options.PasswordProvider is not { } provider || _declined || _prompts >= options.NumberOfPasswordPrompts)
            {
                return (null, false);
            }

            _lastWasGiven = false;
            _prompts++;
            var password = await provider(new SshPasswordPrompt(options.UserName, host, port, method, _prompts, _anyRejected), cancellationToken)
                .ConfigureAwait(false);
            if (password is null)
            {
                _declined = true;
                return (null, true);
            }

            return (password, false);
        }

        /// <summary>The server refused the last password: the given one is not sent again in this walk of the order.</summary>
        public void Rejected()
        {
            _anyRejected = true;
            _givenRejected |= _lastWasGiven;
        }

        /// <summary>
        /// A new walk of the order after a partial success: the server's state changed, so the given password may be tried again (it may
        /// have been refused only because another method had to come first). Prompts already made still count.
        /// </summary>
        public void NewPass() => _givenRejected = false;
    }

    /// <summary>
    /// Answers keyboard-interactive with a password: a round with no questions gets no answers, and the first round that asks for exactly
    /// one hidden input gets the password, asked for only then. Anything else (a second password round, a one-time code, a visible
    /// question) ends the attempt.
    /// </summary>
    private sealed class KeyboardInteractivePassword(PasswordSource passwords)
    {
        /// <summary>Whether a password was sent.</summary>
        public bool Answered { get; private set; }

        public async ValueTask<IReadOnlyList<string>?> RespondAsync(SshKeyboardInteractiveRequest request, CancellationToken cancellationToken)
        {
            if (request.Prompts.Count == 0)
            {
                return [];
            }

            if (Answered || request.Prompts.Count != 1 || request.Prompts[0].Echo)
            {
                return null;
            }

            var (password, _) = await passwords.NextAsync("keyboard-interactive", cancellationToken).ConfigureAwait(false);
            if (password is null)
            {
                return null;
            }

            Answered = true;
            return [password];
        }
    }
}
