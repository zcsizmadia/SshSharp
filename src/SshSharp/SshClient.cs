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
        if (await options.HostKeyVerifier.PrefersCertificatesAsync(host, port, options.HostKeyAlias, cancellationToken).ConfigureAwait(false))
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
                var verdict = await options.HostKeyVerifier.VerifyAsync(new SshHostKeyContext(host, port, options.HostKeyAlias, key), ct).ConfigureAwait(false);
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
            var connection = new SshConnection(transport, logger, options.TimeProvider);
            connection.Start();
            if (options.KeepAliveInterval is { } keepAlive)
            {
                connection.StartKeepAlive(keepAlive, options.KeepAliveCountMax);
            }

            SshTelemetry.Connections.Add(1);
            SshTelemetry.ConnectDuration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds);
            activity?.SetTag("ssh.kex", algorithms.Kex);
            activity?.SetTag("ssh.cipher", algorithms.CipherClientToServer);
            activity?.SetTag("ssh.host_key.type", hostKey.KeyType);
            SshLog.Connected(logger, algorithms.Kex, algorithms.CipherClientToServer, hostKey.KeyType, hostKey.Fingerprint);

            return new SshClient(
                connection, options, stream, leaveOpen, owner, transport.ServerIdentification!.Line,
                new SshHostKey(hostKey.Algorithm, hostKey.KeyType, hostKey.Fingerprint, hostKey.Blob, hostKey.KeySizeBits) { Certificate = hostKey.Certificate }, logger);
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

    private static async Task AuthenticateAsync(SshTransport transport, SshClientOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        await SshUserAuth.RequestServiceAsync(transport, cancellationToken).ConfigureAwait(false);

        // Like ssh: "none" first (it succeeds only on servers that allow anonymous access, and otherwise lists the methods the server
        // accepts), then each key, then the password. After a partial success the server lists what it still wants.
        SshLog.Authenticating(logger, "none");
        var outcome = await SshUserAuth.NoneAsync(transport, options.UserName, cancellationToken).ConfigureAwait(false);
        if (outcome.Success)
        {
            SshLog.Authenticated(logger, "none");
            return;
        }

        var methods = outcome.RemainingMethods;
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
            outcome = await SshUserAuth.PublicKeyAsync(transport, options.UserName, key, algorithm, cancellationToken).ConfigureAwait(false);
            if (outcome.Success)
            {
                SshLog.Authenticated(logger, "publickey");
                return;
            }

            methods = outcome.RemainingMethods;
        }

        if (options.Password is { } password && methods.Contains("password"))
        {
            SshLog.Authenticating(logger, "password");
            outcome = await SshUserAuth.PasswordAsync(transport, options.UserName, password, cancellationToken).ConfigureAwait(false);
            if (outcome.Success)
            {
                SshLog.Authenticated(logger, "password");
                return;
            }

            methods = outcome.RemainingMethods;
        }

        SshLog.AuthenticationFailed(logger, string.Join(", ", methods));
        throw new SshAuthenticationException($"Authentication failed. The server accepts: {string.Join(", ", methods)}.", methods);
    }
}