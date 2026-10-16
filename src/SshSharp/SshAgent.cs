using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Principal;
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
    private const byte AddIdentity = 17;
    private const byte RemoveIdentity = 18;
    private const byte RemoveAllIdentities = 19;
    private const byte Lock = 22;
    private const byte Unlock = 23;
    private const byte AddIdConstrained = 25;
    private const byte ConstrainLifetime = 1;
    private const byte ConstrainConfirm = 2;
    private const byte ConstrainExtension = 255;
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
    public static SshAgent? FromEnvironment() => FromEnvironmentAsync().AsTask().GetAwaiter().GetResult();

    /// <summary>
    /// <see cref="FromEnvironment"/> without blocking a thread while Windows lists its pipes (up to <see cref="PipeListingTimeout"/>
    /// each), for the asynchronous connect path.
    /// </summary>
    internal static async ValueTask<SshAgent?> FromEnvironmentAsync()
    {
        var socket = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        if (!string.IsNullOrEmpty(socket) || !OperatingSystem.IsWindows())
        {
            return FromSocketVariable(socket, windows: false);
        }

        // The OpenSSH agent service first, as ssh does; Pageant only when that is surely not running (a listing that takes too long
        // proves nothing) and Pageant is.
        return await PipeListedAsync(WindowsPipe[PipePrefix.Length..]).ConfigureAwait(false) == false && await PageantAsync().ConfigureAwait(false) is { } pageant
            ? pageant
            : new SshAgent(WindowsPipe);
    }

    internal static SshAgent? FromSocketVariable(string? socket, bool windows) =>
        !string.IsNullOrEmpty(socket) ? new SshAgent(socket) : windows ? new SshAgent(WindowsPipe) : null;

    /// <summary>
    /// PuTTY's Pageant (0.75 and later), on the named pipe it creates for the current user (<c>\\.\pipe\pageant.&lt;user&gt;.&lt;hash&gt;</c>),
    /// or null when Pageant is not running or this is not Windows. Its keys work like any agent's.
    /// </summary>
    public static SshAgent? Pageant() => PageantAsync().AsTask().GetAwaiter().GetResult();

    private static async ValueTask<SshAgent?> PageantAsync() =>
        OperatingSystem.IsWindows() && PageantPipe.Name() is { } name && await PipeListedAsync(name).ConfigureAwait(false) == true
            ? new SshAgent(PipePrefix + name)
            : null;

    /// <summary>
    /// Whether a named pipe exists, by listing the pipes (opening one would take one of its instances); null when the listing took too
    /// long to tell. The listing runs on the thread pool and is awaited, not waited for.
    /// </summary>
    private static async ValueTask<bool?> PipeListedAsync(string name)
    {
        var listing = Task.Run(() => Directory.EnumerateFiles(PipePrefix, name).Any());
        try
        {
            return await listing.WaitAsync(PipeListingTimeout).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _ = listing.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
            or System.Security.SecurityException)
        {
            // A listing that fails (a pipe name that is not a valid pattern, a platform without it, no access) means "not listed".
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

    /// <summary>
    /// Adds <paramref name="key"/> to the agent, as <c>ssh-add</c> does, optionally with <paramref name="constraints"/> (a lifetime, or a
    /// confirmation for each use). A key paired with a certificate is added with it. Adding a key the agent already holds replaces its
    /// constraints.
    /// </summary>
    /// <exception cref="NotSupportedException">The key's private material is not here: it is held by an agent already.</exception>
    /// <exception cref="SshException">The agent is not running or refused the key (<see cref="SshFailureReason.AgentFailed"/>), for example
    /// a key type or constraint it does not support, or a locked agent.</exception>
    public async Task AddKeyAsync(SshPrivateKey key, SshAgentKeyConstraints? constraints = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.HeldByAgent)
        {
            throw new NotSupportedException("This key is held by an agent; only a key loaded from a file or generated here can be added.");
        }

        var constrained = constraints is { Lifetime: not null } or { Confirm: true } or { Destinations.Count: > 0 };
        using var message = new ZeroingBufferWriter(4096);
        var writer = new SshWriter(message);
        writer.WriteByte(constrained ? AddIdConstrained : AddIdentity);
        key.WriteAgentIdentity(writer);
        writer.WriteString(key.Comment ?? string.Empty);
        if (constraints is { Lifetime: { } lifetime })
        {
            writer.WriteByte(ConstrainLifetime);
            writer.WriteUInt32((uint)Math.Clamp(Math.Ceiling(lifetime.TotalSeconds), 1, uint.MaxValue));
        }

        if (constraints is { Confirm: true })
        {
            writer.WriteByte(ConstrainConfirm);
        }

        if (constraints is { Destinations.Count: > 0 } restricted)
        {
            writer.WriteByte(ConstrainExtension);
            writer.WriteString("restrict-destination-v00@openssh.com");
            writer.WriteString(EncodeDestinations(restricted.Destinations));
        }

        await ExpectSuccessAsync(message.WrittenSpan.ToArray(), "add the key", clear: true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>restrict-destination-v00@openssh.com</c> constraint body (PROTOCOL.agent, as ssh-add encodes it): each destination as a
    /// string holding its from hop, its to hop and a reserved string; each hop as a string holding the user, the host name, a reserved
    /// string, then every host key as a string and an is-CA byte.
    /// </summary>
    internal static byte[] EncodeDestinations(IReadOnlyList<SshAgentDestination> destinations) => SshPrivateKey.Encode(all =>
    {
        foreach (var destination in destinations)
        {
            all.WriteString(SshPrivateKey.Encode(constraint =>
            {
                constraint.WriteString(EncodeHop(destination.From));
                constraint.WriteString(EncodeHop(destination.To));
                constraint.WriteString(ReadOnlySpan<byte>.Empty);
            }));
        }
    });

    private static byte[] EncodeHop(SshAgentHost? host) => SshPrivateKey.Encode(hop =>
    {
        hop.WriteString(host?.UserName ?? string.Empty);
        hop.WriteString(host?.HostName ?? string.Empty);
        hop.WriteString(ReadOnlySpan<byte>.Empty);
        foreach (var key in host?.HostKeys ?? [])
        {
            hop.WriteString(key.PublicKey.Span);
            hop.WriteBoolean(key.IsCertificateAuthority);
        }
    });

    /// <summary>Removes one key from the agent (<c>ssh-add -d</c>): one from <see cref="GetKeysAsync"/>, or the key a file holds.</summary>
    /// <exception cref="SshException">The agent is not running or does not hold the key (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public Task RemoveKeyAsync(SshPrivateKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        var publicKey = key.PublicKey;
        return ExpectSuccessAsync(SshPrivateKey.Encode(w =>
        {
            w.WriteByte(RemoveIdentity);
            w.WriteString(publicKey.Span);
        }), "remove the key", clear: false, cancellationToken);
    }

    /// <summary>Removes every key from the agent (<c>ssh-add -D</c>).</summary>
    /// <exception cref="SshException">The agent is not running or refused (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public Task RemoveAllKeysAsync(CancellationToken cancellationToken = default) =>
        ExpectSuccessAsync([RemoveAllIdentities], "remove all keys", clear: false, cancellationToken);

    /// <summary>
    /// Locks the agent with <paramref name="passphrase"/> (<c>ssh-add -x</c>): until <see cref="UnlockAsync"/>, it lists no keys and signs
    /// nothing.
    /// </summary>
    /// <exception cref="SshException">The agent is not running or is locked already (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public Task LockAsync(string passphrase, CancellationToken cancellationToken = default) => LockOrUnlockAsync(Lock, passphrase, "lock", cancellationToken);

    /// <summary>Unlocks an agent locked with <see cref="LockAsync"/> (<c>ssh-add -X</c>).</summary>
    /// <exception cref="SshException">The agent is not running, or the passphrase is wrong (<see cref="SshFailureReason.AgentFailed"/>).</exception>
    public Task UnlockAsync(string passphrase, CancellationToken cancellationToken = default) => LockOrUnlockAsync(Unlock, passphrase, "unlock", cancellationToken);

    private async Task LockOrUnlockAsync(byte type, string passphrase, string what, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        var secret = System.Text.Encoding.UTF8.GetBytes(passphrase);
        try
        {
            // Built in a buffer that is wiped, as an added key is: an ordinary growing buffer would leave copies of the passphrase behind.
            using var message = new ZeroingBufferWriter(secret.Length + 16);
            var writer = new SshWriter(message);
            writer.WriteByte(type);
            writer.WriteString(secret);
            await ExpectSuccessAsync(message.WrittenSpan.ToArray(), what + " the agent", clear: true, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>Sends a request whose answer is SUCCESS or FAILURE; <paramref name="clear"/> wipes the request afterwards (it holds a secret).</summary>
    private async Task ExpectSuccessAsync(byte[] request, string what, bool clear, CancellationToken cancellationToken)
    {
        byte[] reply;
        try
        {
            reply = await RequestAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (clear)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(request);
            }
        }

        if (reply[0] != Success)
        {
            throw new SshException(SshFailureReason.AgentFailed, $"The agent refused to {what}.");
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
        try
        {
            await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(frame); // it may carry a private key (ADD_IDENTITY) or passphrase
        }

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

    /// <summary>
    /// Whether the pipe's server is someone the user can trust with keys: any user can create a pipe under a name nobody holds yet, so
    /// another user who creates the agent's pipe first (a stopped agent service, or Pageant's name, which every process can derive) would
    /// otherwise receive sign requests and added keys. PuTTY refuses a Pageant pipe not owned by the user for the same reason.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool IsTrustedPipeOwner(NamedPipeClientStream pipe)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner &&
                (owner == identity.User ||
                 owner.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                 owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        }
        catch (SystemException) // no READ_CONTROL on the pipe, or a security descriptor that cannot be read: not trusted
        {
            return false;
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
            if (!await PipeMayExistAsync(name, cancellationToken).ConfigureAwait(false))
            {
                throw new IOException($"No agent is listening on {path}.");
            }

            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(5000, cancellationToken).ConfigureAwait(false);
                if (!IsTrustedPipeOwner(pipe))
                {
                    throw new IOException($"The pipe {path} is not owned by the current user, SYSTEM or Administrators; it is not used as an agent.");
                }

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
