using System.Buffers;
using System.Net.Sockets;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>An authenticated SSH client connection: run commands over it. Create one with <see cref="ConnectAsync(Stream, SshClientOptions, bool, CancellationToken)"/>.</summary>
public sealed class SshClient : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly SshClientOptions _options;
    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly IDisposable? _owner;
    private bool _disposed;

    private SshClient(SshConnection connection, SshClientOptions options, Stream stream, bool leaveOpen, IDisposable? owner, string serverIdentification, SshHostKey hostKey)
    {
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

    /// <summary>Connects to <paramref name="host"/> over TCP, performs the handshake and authenticates.</summary>
    public static async Task<SshClient> ConnectAsync(string host, int port, SshClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            return await ConnectCoreAsync(tcp.GetStream(), options, leaveOpen: false, owner: tcp, cancellationToken).ConfigureAwait(false);
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
        ConnectCoreAsync(stream, options, leaveOpen, owner: null, cancellationToken);

    /// <summary>Runs <paramref name="command"/> on the server and collects its output and exit status.</summary>
    /// <exception cref="SshException">The server refused the command or the connection failed.</exception>
    /// <exception cref="InvalidOperationException">The output exceeded <see cref="SshClientOptions.MaxCommandOutputBytes"/>.</exception>
    public async Task<SshCommandResult> RunCommandAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var channel = await _connection.OpenSessionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
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
            return new SshCommandResult(channel.ExitStatus is { } status ? (int)status : null, channel.ExitSignal, stdout.WrittenMemory, stderr.WrittenMemory);
        }
        finally
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Disconnects and releases the connection.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _connection.DisposeAsync().ConfigureAwait(false);
        if (!_leaveOpen)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }

        _owner?.Dispose();
    }

    private static async Task<SshClient> ConnectCoreAsync(Stream stream, SshClientOptions options, bool leaveOpen, IDisposable? owner, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var transportOptions = new SshTransportOptions
        {
            Preferences = options.AlgorithmPreferences ?? new AlgorithmPreferences(),
            MinimumRsaBits = options.MinimumRsaBits,
            RekeyBytes = options.RekeyAfterBytes,
            RekeyInterval = options.RekeyAfterTime,
            VerifyHostKey = (info, ct) => options.HostKeyVerifier(new SshHostKey(info.Algorithm, info.KeyType, info.Fingerprint, info.Blob, info.KeySizeBits), ct),
        };
        var transport = new SshTransport(stream, transportOptions);
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);
            await AuthenticateAsync(transport, options, cancellationToken).ConfigureAwait(false);

            var hostKey = transport.HostKey!;
            var connection = new SshConnection(transport);
            connection.Start();
            return new SshClient(
                connection, options, stream, leaveOpen, owner, transport.ServerIdentification!.Line,
                new SshHostKey(hostKey.Algorithm, hostKey.KeyType, hostKey.Fingerprint, hostKey.Blob, hostKey.KeySizeBits));
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            if (!leaveOpen)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async Task AuthenticateAsync(SshTransport transport, SshClientOptions options, CancellationToken cancellationToken)
    {
        await SshUserAuth.RequestServiceAsync(transport, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<string> methods = [];
        if (options.Password is { } password)
        {
            var outcome = await SshUserAuth.PasswordAsync(transport, options.UserName, password, cancellationToken).ConfigureAwait(false);
            if (outcome.Success)
            {
                return;
            }

            methods = outcome.RemainingMethods;
        }
        else
        {
            // No credentials: "none" succeeds only on servers that allow anonymous access, and otherwise reveals the accepted methods.
            var outcome = await SshUserAuth.NoneAsync(transport, options.UserName, cancellationToken).ConfigureAwait(false);
            if (outcome.Success)
            {
                return;
            }

            methods = outcome.RemainingMethods;
        }

        throw new SshException(
            SshFailureReason.AuthenticationFailed,
            $"Authentication failed for user '{options.UserName}'. The server accepts: {string.Join(", ", methods)}.");
    }
}