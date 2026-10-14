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
/// <remarks>
/// Each request opens a new connection to the agent, so an agent restarted between connections is picked up. Signatures for
/// authentication are made on a connection bound to the SSH session (<c>session-bind@openssh.com</c>), so keys added with destination
/// constraints (<c>ssh-add -h</c>) work as they do with <c>ssh</c>.
/// </remarks>
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
    private const byte Success = 6;
    private const byte Extension = 27;
    private const byte ExtensionFailure = 28;
    private const byte ExtensionResponse = 29;
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
    /// The user's agent, as ssh finds it: <c>SSH_AUTH_SOCK</c>; on Windows, when that is not set, the OpenSSH agent service's pipe, or
    /// PuTTY's Pageant (0.75 and later) when only Pageant is running. Null when there is none to try. Whether an agent is actually running
    /// shows on the first request.
    /// </summary>
    public static SshAgent? FromEnvironment()
    {
        if (Environment.GetEnvironmentVariable("SSH_AUTH_SOCK") is { Length: > 0 } socket || !OperatingSystem.IsWindows())
        {
            return FromSocketVariable(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK"), windows: false);
        }

        // The OpenSSH agent service first, as ssh does; Pageant only when that is not running and Pageant is.
        return !PipeExists(WindowsPipe[PipePrefix.Length..]) && Pageant() is { } pageant ? pageant : new SshAgent(WindowsPipe);
    }

    internal static SshAgent? FromSocketVariable(string? socket, bool windows) =>
        !string.IsNullOrEmpty(socket) ? new SshAgent(socket) : windows ? new SshAgent(WindowsPipe) : null;

    /// <summary>
    /// PuTTY's Pageant (0.75 and later), on the named pipe it creates for the current user (<c>\\.\pipe\pageant.&lt;user&gt;.&lt;hash&gt;</c>),
    /// or null when Pageant is not running or this is not Windows. Its keys work like any agent's.
    /// </summary>
    public static SshAgent? Pageant() =>
        OperatingSystem.IsWindows() && PageantPipe.Name() is { } name && PipeExists(name) ? new SshAgent(PipePrefix + name) : null;

    /// <summary>Whether a named pipe exists, by listing the pipes (opening one would take one of its instances).</summary>
    private static bool PipeExists(string name)
    {
        try
        {
            var listing = Task.Run(() => Directory.EnumerateFiles(PipePrefix, name).Any());
            return listing.Wait(PipeListingTimeout) && listing.Result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or AggregateException)
        {
            return false;
        }
    }

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

    /// <summary>
    /// The protocol extensions the agent supports (RFC 9987's <c>query</c> extension), for example <c>session-bind@openssh.com</c>. An
    /// agent that does not implement <c>query</c> yields an empty list.
    /// </summary>
    /// <exception cref="SshException">The agent is not running or sent a malformed reply (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public async Task<IReadOnlyList<string>> QueryExtensionsAsync(CancellationToken cancellationToken = default)
    {
        var request = SshPrivateKey.Encode(w =>
        {
            w.WriteByte(Extension);
            w.WriteString("query");
        });
        var reply = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
        try
        {
            var reader = new SshReader(reply);
            var type = reader.ReadByte();
            if (type is Failure or ExtensionFailure)
            {
                return []; // the agent does not implement query (MUST reply with SSH_AGENT_FAILURE)
            }

            // RFC 9987 answers with SSH_AGENT_EXTENSION_RESPONSE; SSH_AGENT_SUCCESS is also a valid success reply (older OpenSSH agents).
            if (type is not (ExtensionResponse or Success))
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The agent answered the query with message {type}.");
            }

            if (reader.IsEmpty)
            {
                return [];
            }

            if (reader.ReadUtf8String() != "query")
            {
                throw new SshException(SshFailureReason.AgentFailed, "The agent answered a different extension than the query.");
            }

            var names = new List<string>();
            while (!reader.IsEmpty && names.Count < MaxKeys)
            {
                names.Add(reader.ReadUtf8String());
            }

            return names;
        }
        catch (SshProtocolException ex)
        {
            throw new SshException(SshFailureReason.AgentFailed, "The agent's extension list is malformed.", ex);
        }
    }

    /// <summary>Asks the agent to sign <paramref name="data"/> with the key <paramref name="blob"/>, returning the SSH signature blob.</summary>
    internal async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> blob, string algorithm, ReadOnlyMemory<byte> data, AgentBinding? binding, CancellationToken cancellationToken)
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

        var reply = await RequestAsync(request.WrittenMemory, cancellationToken, binding).ConfigureAwait(false);
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

    /// <summary>A raw connection to the agent, for agent forwarding (the server speaks the agent protocol itself).</summary>
    internal async ValueTask<Stream> OpenStreamAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _connect(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or TimeoutException)
        {
            throw new SshException(SshFailureReason.AgentFailed, $"Could not reach the SSH agent: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// One request and its reply over a fresh connection, each framed as <c>uint32 length || message</c>. With
    /// <paramref name="binding"/>, the connection is first bound to the SSH session (<c>session-bind@openssh.com</c>), so the agent can
    /// apply destination constraints (<c>ssh-add -h</c>) to the request; an agent that does not know the extension just refuses the
    /// binding, and the request goes ahead as before.
    /// </summary>
    private async Task<byte[]> RequestAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken, AgentBinding? binding = null)
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
                if (binding is not null)
                {
                    await BindAsync(stream, binding, forwarding: false, cancellationToken).ConfigureAwait(false);
                }

                return await ExchangeAsync(stream, message, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                throw new SshException(SshFailureReason.AgentFailed, $"The connection to the SSH agent failed: {ex.Message}", ex);
            }
        }
    }

    /// <summary>
    /// Binds an agent connection to an SSH session (PROTOCOL.agent, <c>session-bind@openssh.com</c>): the server's host key, the session
    /// identifier and the host key's signature over it, which the agent verifies. <paramref name="forwarding"/> marks a connection the
    /// server reaches through agent forwarding, as <c>ssh -A</c> does. Returns whether the agent accepted the binding; agents that do not
    /// implement it (older OpenSSH, other agents) refuse, which is not an error.
    /// </summary>
    internal static async Task<bool> BindAsync(Stream stream, AgentBinding binding, bool forwarding, CancellationToken cancellationToken)
    {
        var request = SshPrivateKey.Encode(w =>
        {
            w.WriteByte(Extension);
            w.WriteString("session-bind@openssh.com");
            w.WriteString(binding.HostKey.Span);
            w.WriteString(binding.SessionId.Span);
            w.WriteString(binding.Signature.Span);
            w.WriteBoolean(forwarding);
        });
        var reply = await ExchangeAsync(stream, request, cancellationToken).ConfigureAwait(false);
        return reply[0] == Success;
    }

    /// <summary>Sends one framed message on an open agent connection and reads one framed reply.</summary>
    private static async Task<byte[]> ExchangeAsync(Stream stream, ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
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

    /// <summary>
    /// Whether the pipe is listed under <c>\\.\pipe\</c>. Listing the pipes is synchronous and has been seen to stall for minutes (CI, with
    /// many pipes coming and going), so it runs off the caller's thread, bounded and cancellable: when it does not answer in time, the
    /// pipe may exist, and the connect's own timeout decides.
    /// </summary>
    private static async ValueTask<bool> PipeMayExistAsync(string name, CancellationToken cancellationToken)
    {
        var listing = Task.Run(() => Directory.EnumerateFiles(PipePrefix, name).Any(), CancellationToken.None);
        try
        {
            return await listing.WaitAsync(PipeListingTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _ = listing.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            return true;
        }
    }

    private static readonly TimeSpan PipeListingTimeout = TimeSpan.FromSeconds(2);

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
            if (!await PipeMayExistAsync(name, cancellationToken).ConfigureAwait(false))
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

/// <summary>
/// What binds an agent connection to an SSH session (PROTOCOL.agent, <c>session-bind@openssh.com</c>): the host key the server
/// presented, the session identifier, and the host key's signature over it from the first key exchange.
/// </summary>
internal sealed record AgentBinding(ReadOnlyMemory<byte> HostKey, ReadOnlyMemory<byte> SessionId, ReadOnlyMemory<byte> Signature);
