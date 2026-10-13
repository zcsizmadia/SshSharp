using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net.Sockets;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

/// <summary>
/// An SSH agent (<c>ssh-agent</c>, the Windows OpenSSH agent service, or any agent speaking the same protocol) that holds private keys and
/// signs with them, so the keys never enter this process. List its keys with <see cref="GetKeysAsync"/> and pass them in
/// <see cref="SshClientOptions.PrivateKeys"/>; every signature is then made by the agent.
/// </summary>
/// <remarks>Each request opens a new connection to the agent, so an agent restarted between connections is picked up.</remarks>
public sealed class SshAgent
{
    /// <summary>The Windows OpenSSH agent service's pipe, used when <c>SSH_AUTH_SOCK</c> is not set.</summary>
    internal const string WindowsPipe = @"\\.\pipe\openssh-ssh-agent";

    private const string PipePrefix = @"\\.\pipe\";

    /// <summary>OpenSSH's limit on an agent message (AGENT_MAX_LEN).</summary>
    internal const int MaxMessageLength = 256 * 1024;

    /// <summary>The most keys accepted from one listing (OpenSSH's MAX_AGENT_IDENTITIES).</summary>
    internal const int MaxKeys = 2048;

    private const byte Failure = 5;
    private const byte RequestIdentities = 11;
    private const byte IdentitiesAnswer = 12;
    private const byte SignRequest = 13;
    private const byte SignResponse = 14;
    private const uint RsaSha2_256 = 2;
    private const uint RsaSha2_512 = 4;

    private readonly Func<CancellationToken, ValueTask<Stream>> _connect;

    /// <summary>An agent at <paramref name="path"/>: a Unix domain socket, or on Windows a named pipe such as <c>\\.\pipe\openssh-ssh-agent</c>.</summary>
    public SshAgent(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Path = path;
        _connect = ct => ConnectAsync(path, ct);
    }

    internal SshAgent(string path, Func<CancellationToken, ValueTask<Stream>> connect)
    {
        Path = path;
        _connect = connect;
    }

    /// <summary>The socket or pipe the agent listens on.</summary>
    public string Path { get; }

    /// <summary>
    /// The user's agent, as ssh finds it: <c>SSH_AUTH_SOCK</c>, or on Windows the OpenSSH agent service's pipe when that is not set. Null
    /// when there is none to try. Whether an agent is actually running shows on the first request.
    /// </summary>
    public static SshAgent? FromEnvironment() =>
        FromSocketVariable(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK"), OperatingSystem.IsWindows());

    internal static SshAgent? FromSocketVariable(string? socket, bool windows) =>
        !string.IsNullOrEmpty(socket) ? new SshAgent(socket) : windows ? new SshAgent(WindowsPipe) : null;

    /// <summary>
    /// The keys the agent holds, ready for <see cref="SshClientOptions.PrivateKeys"/>. Keys of types SshSharp cannot authenticate with
    /// (DSA, for example) are left out.
    /// </summary>
    /// <exception cref="SshException">The agent is not running or did not answer as expected (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public async Task<IReadOnlyList<SshPrivateKey>> GetKeysAsync(CancellationToken cancellationToken = default)
    {
        var reply = await RequestAsync(new byte[] { RequestIdentities }, cancellationToken).ConfigureAwait(false);
        try
        {
            var reader = new SshReader(reply);
            if (reader.ReadByte() != IdentitiesAnswer)
            {
                throw new SshException(SshFailureReason.AgentFailed, "The agent refused to list its keys.");
            }

            var count = reader.ReadUInt32();
            if (count > MaxKeys)
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The agent listed {count} keys; at most {MaxKeys} are accepted.");
            }

            var keys = new List<SshPrivateKey>();
            for (var i = 0; i < count; i++)
            {
                var blob = reader.ReadString().ToArray();
                var comment = reader.ReadUtf8String();
                if (AgentKey.TryCreate(this, blob, comment) is { } key)
                {
                    keys.Add(key);
                }
            }

            return keys;
        }
        catch (SshProtocolException ex)
        {
            throw new SshException(SshFailureReason.AgentFailed, "The agent's key list is malformed.", ex);
        }
    }

    /// <summary>Asks the agent to sign <paramref name="data"/> with the key <paramref name="blob"/>, returning the SSH signature blob.</summary>
    internal async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> blob, string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        uint flags = algorithm switch
        {
            SshAlgorithms.RsaSha2_256 => RsaSha2_256,
            SshAlgorithms.RsaSha2_512 => RsaSha2_512,
            _ => 0,
        };
        var request = new ArrayBufferWriter<byte>(blob.Length + data.Length + 32);
        var writer = new SshWriter(request);
        writer.WriteByte(SignRequest);
        writer.WriteString(blob.Span);
        writer.WriteString(data.Span);
        writer.WriteUInt32(flags);

        var reply = await RequestAsync(request.WrittenMemory, cancellationToken).ConfigureAwait(false);
        try
        {
            var reader = new SshReader(reply);
            var type = reader.ReadByte();
            if (type == Failure)
            {
                // The key is gone, or the user declined a confirmation prompt (ssh-add -c).
                throw new SshException(SshFailureReason.AgentFailed, "The agent refused to sign.");
            }

            if (type != SignResponse)
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The agent answered a signing request with message {type}.");
            }

            var signature = reader.ReadString().ToArray();

            // An agent that ignores the flags signs RSA with SHA-1; the server would reject it, so say so here.
            var signed = new SshReader(signature).ReadUtf8String();
            if (signed != algorithm)
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The agent signed with {signed} instead of {algorithm}.");
            }

            return signature;
        }
        catch (SshProtocolException ex)
        {
            throw new SshException(SshFailureReason.AgentFailed, "The agent's signature is malformed.", ex);
        }
    }

    /// <summary>One request and its reply over a fresh connection, each framed as <c>uint32 length || message</c>.</summary>
    private async Task<byte[]> RequestAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        Stream stream;
        try
        {
            stream = await _connect(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or TimeoutException)
        {
            throw new SshException(SshFailureReason.AgentFailed, $"Could not reach the SSH agent: {ex.Message}", ex);
        }

        await using (stream.ConfigureAwait(false))
        {
            try
            {
                var frame = new byte[4 + message.Length];
                BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)message.Length);
                message.CopyTo(frame.AsMemory(4));
                await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                var header = new byte[4];
                await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadUInt32BigEndian(header);
                if (length is 0 or > MaxMessageLength)
                {
                    throw new SshException(SshFailureReason.AgentFailed, $"The agent sent a message of {length} bytes.");
                }

                var reply = new byte[length];
                await stream.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
                return reply;
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The connection to the SSH agent failed: {ex.Message}", ex);
            }
        }
    }

    private static async ValueTask<Stream> ConnectAsync(string path, CancellationToken cancellationToken)
    {
        if (path.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase))
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new IOException("Named pipes are a Windows agent transport.");
            }

            // Connecting waits for a pipe that does not exist yet, so a stopped agent service would stall every connection; look first.
            var name = path[PipePrefix.Length..];
            if (!Directory.EnumerateFiles(PipePrefix, name).Any())
            {
                throw new IOException($"No agent is listening on {path}.");
            }

            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(5000, cancellationToken).ConfigureAwait(false);
                return pipe;
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        UnixDomainSocketEndPoint endPoint;
        try
        {
            endPoint = new UnixDomainSocketEndPoint(path);
        }
        catch (ArgumentException ex)
        {
            // Longer than the platform allows (104 bytes on macOS, 108 on Linux): no agent can listen there.
            throw new IOException($"'{path}' cannot be a socket path here: {ex.Message}", ex);
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
