using System.Buffers;
using System.Buffers.Binary;
using Microsoft.Extensions.Logging;
using SshSharp.Keys;

namespace SshSharp.Protocol;

/// <summary>A key an agent lists: its blob (a key or a certificate) and its comment.</summary>
internal sealed record AgentIdentity(byte[] Blob, string Comment);

/// <summary>Where an <see cref="AgentServer"/>'s requests are answered: keys in this process, or a real agent behind a filter.</summary>
internal abstract class AgentBackend
{
    /// <summary>The keys, or null when the agent refused to list them.</summary>
    public abstract ValueTask<IReadOnlyList<AgentIdentity>?> ListAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Answers a signing request the server has checked: <paramref name="message"/> is the request as it came, and the other arguments are
    /// what it holds. Returns the reply message.
    /// </summary>
    public abstract ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, byte[] blob, byte[] data, uint flags, SignedData signed,
        CancellationToken cancellationToken);

    /// <summary>Answers a session binding the server has verified and recorded; returns the reply message.</summary>
    public abstract ValueTask<byte[]> BindAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken);
}

/// <summary>
/// What data to be signed is, as its form shows: a login request, an SSH signature over a file, a certificate, or (a null purpose) none of
/// these, such as pam_ssh_agent_auth's challenge.
/// </summary>
internal sealed record SignedData(SshSignaturePurpose? Purpose, string? Namespace = null, string? UserName = null, byte[]? SessionId = null,
    byte[]? HostKey = null);

/// <summary>
/// The agent protocol (RFC 9987, OpenSSH's PROTOCOL.agent) served for one agent connection: a forwarded agent channel, or one request
/// to an in-process agent. It is read-only: it lists keys, signs, binds the connection to sessions (<c>session-bind@openssh.com</c>) and
/// answers <c>query</c>; adding, removing and locking are refused, and RSA never signs with SHA-1. With a filter, every listed key and
/// every signature is the filter's to allow, including signatures over data of a form it does not recognise.
/// </summary>
/// <remarks>
/// Every request is parsed in full before anything is done with it, and a malformed one is answered with <c>SSH_AGENT_FAILURE</c>: a
/// program on the server, which may be hostile, never gets more than that. Requests on one connection are answered in order.
/// </remarks>
internal sealed class AgentServer
{
    internal const byte Failure = 5;
    internal const byte Success = 6;
    internal const byte RequestIdentities = 11;
    internal const byte IdentitiesAnswer = 12;
    internal const byte SignRequest = 13;
    internal const byte SignResponse = 14;
    internal const byte Extension = 27;
    internal const byte ExtensionResponse = 29;
    internal const uint RsaSha2_256 = 2;
    internal const uint RsaSha2_512 = 4;

    /// <summary>The most session bindings one connection records (OpenSSH's AGENT_MAX_SESSION_IDS).</summary>
    internal const int MaxBindings = 16;

    /// <summary>The longest session identifier accepted (OpenSSH's AGENT_MAX_SID_LEN); a SHA-512 exchange hash is 64 bytes.</summary>
    internal const int MaxSessionIdLength = 128;

    internal const string SessionBind = "session-bind@openssh.com";
    internal const string Query = "query";

    private const string Hostbound = "publickey-hostbound-v00@openssh.com";

    private static readonly byte[] FailureReply = [Failure];

    private readonly AgentBackend _backend;
    private readonly Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? _filter;
    private readonly ILogger _logger;
    private readonly List<Binding> _bindings = [];

    // The comments the last listing gave, so the filter sees a key's comment when it is asked to sign with it.
    private IReadOnlyList<AgentIdentity> _listed = [];

    public AgentServer(AgentBackend backend, Func<SshAgentRequest, CancellationToken, ValueTask<bool>>? filter, ILogger logger)
    {
        _backend = backend;
        _filter = filter;
        _logger = logger;
    }

    /// <summary>One session the connection is bound to: the host key and its signature over the session identifier verified.</summary>
    private sealed record Binding(byte[] HostKeyBlob, SshPublicKey HostKey, byte[] SessionId, bool IsForwarding);

    /// <summary>
    /// Records this client's own session as the first forwarding hop (what it sends a real agent as <c>session-bind</c> with
    /// <c>is_forwarding</c>). It is this process's own key exchange, so it is not verified again.
    /// </summary>
    public void AddForwardingHop(AgentBinding binding)
    {
        if (ReadHostKey(binding.HostKey.Span) is { } key)
        {
            _bindings.Add(new Binding(binding.HostKey.ToArray(), SshPublicKey.FromVerifyingKey(key), binding.SessionId.ToArray(), IsForwarding: true));
        }
    }

    /// <summary>Answers one request (without its length prefix) with one reply.</summary>
    public async ValueTask<byte[]> HandleAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        if (message.IsEmpty)
        {
            return FailureReply;
        }

        try
        {
            switch (message.Span[0])
            {
                case RequestIdentities:
                    return await ListAsync(cancellationToken).ConfigureAwait(false);
                case SignRequest:
                    return await SignAsync(message, cancellationToken).ConfigureAwait(false);
                case Extension:
                    return await ExtensionAsync(message, cancellationToken).ConfigureAwait(false);
                default:
                    // Adding, removing, locking and unlocking (and the SSH1 requests): a forwarded agent is read-only.
                    return FailureReply;
            }
        }
        catch (SshProtocolException)
        {
            return FailureReply;
        }
    }

    private async ValueTask<byte[]> ListAsync(CancellationToken cancellationToken)
    {
        if (await _backend.ListAsync(cancellationToken).ConfigureAwait(false) is not { } identities)
        {
            return FailureReply;
        }

        _listed = identities;
        // Without a filter every key is listed; with one, each is asked about (asynchronously, so not a LINQ Where).
        var allowed = new List<AgentIdentity>(identities.Count);
        if (_filter is null)
        {
            allowed.AddRange(identities);
        }
        else
        {
            var destination = AuthenticationBinding()?.HostKey;
            foreach (var identity in identities)
            {
                var allow = await AllowAsync(SshAgentOperation.ListKeys, identity.Blob, identity.Comment, signed: null, destination, cancellationToken)
                    .ConfigureAwait(false);
                if (allow)
                {
                    allowed.Add(identity);
                }
            }
        }

        return Encode(w =>
        {
            w.WriteByte(IdentitiesAnswer);
            w.WriteUInt32((uint)allowed.Count);
            foreach (var identity in allowed)
            {
                w.WriteString(identity.Blob);
                w.WriteString(identity.Comment);
            }
        });
    }

    private async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        var (blob, data, flags) = ReadSignRequest(message.Span);

        // An RSA signature without a SHA-2 flag would be SHA-1 ssh-rsa, which SshSharp never makes.
        var keyType = new SshReader(blob).ReadUtf8String();
        if (SshCertificate.BaseAlgorithm(keyType) == "ssh-rsa" && (flags & (RsaSha2_256 | RsaSha2_512)) == 0)
        {
            return FailureReply;
        }

        var signed = Classify(data);

        SshPublicKey? destination = null;
        if (signed.Purpose == SshSignaturePurpose.Authentication && AuthenticationBinding() is { } bound)
        {
            // The connection was bound to the session being logged in to: the request must be for that session, and a host-bound request
            // must name that session's host key (as ssh-agent checks for destination-constrained keys).
            if (!bound.SessionId.AsSpan().SequenceEqual(signed.SessionId) ||
                (signed.HostKey is { } named && !named.AsSpan().SequenceEqual(bound.HostKeyBlob)))
            {
                return FailureReply;
            }

            destination = bound.HostKey;
        }

        if (_filter is not null && !await AllowAsync(SshAgentOperation.Sign, blob, CommentOf(blob), signed, destination, cancellationToken).ConfigureAwait(false))
        {
            return FailureReply;
        }

        return await _backend.SignAsync(message, blob, data, flags, signed, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<byte[]> ExtensionAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        var name = ReadExtensionName(message.Span, out var bodyOffset);
        switch (name)
        {
            case Query:
                // RFC 9987: the extensions this agent implements, in SSH_AGENT_EXTENSION_RESPONSE.
                return Encode(w =>
                {
                    w.WriteByte(ExtensionResponse);
                    w.WriteString(Query);
                    w.WriteString(Query);
                    w.WriteString(SessionBind);
                });

            case SessionBind:
                return Bind(message.Span[bodyOffset..]) ? await _backend.BindAsync(message, cancellationToken).ConfigureAwait(false) : FailureReply;

            default:
                return FailureReply;
        }
    }

    /// <summary>
    /// Verifies and records a session binding (PROTOCOL.agent): the host key, the session identifier, the host key's signature over it,
    /// and whether the connection is being forwarded. As ssh-agent does, a connection bound for authentication takes no further
    /// binding, the same session binds again only to the same host key, and at most <see cref="MaxBindings"/> are kept.
    /// </summary>
    private bool Bind(ReadOnlySpan<byte> body)
    {
        var reader = new SshReader(body);
        var hostKeyBlob = reader.ReadString().ToArray();
        var sessionId = reader.ReadString().ToArray();
        var signature = reader.ReadString();
        var forwarding = reader.ReadBoolean();
        if (!reader.IsEmpty || sessionId.Length is 0 or > MaxSessionIdLength || ReadHostKey(hostKeyBlob) is not { } hostKey)
        {
            return false;
        }

        string algorithm;
        try
        {
            algorithm = new SshReader(signature).ReadUtf8String();
        }
        catch (SshProtocolException)
        {
            return false;
        }

        if (!hostKey.VerifySignature(algorithm, signature, sessionId))
        {
            return false;
        }

        foreach (var binding in _bindings)
        {
            if (!binding.IsForwarding)
            {
                return false; // bound for an authentication attempt already
            }

            if (binding.SessionId.AsSpan().SequenceEqual(sessionId))
            {
                return binding.HostKeyBlob.AsSpan().SequenceEqual(hostKeyBlob);
            }
        }

        if (_bindings.Count >= MaxBindings)
        {
            return false;
        }

        _bindings.Add(new Binding(hostKeyBlob, SshPublicKey.FromVerifyingKey(hostKey), sessionId, forwarding));
        return true;
    }

    /// <summary>The binding for the session the connection authenticates to: the last one, when it is not a forwarding one.</summary>
    private Binding? AuthenticationBinding() => _bindings.Count > 0 && !_bindings[^1].IsForwarding ? _bindings[^1] : null;

    private string? CommentOf(byte[] blob)
    {
        foreach (var identity in _listed)
        {
            if (identity.Blob.AsSpan().SequenceEqual(blob))
            {
                return identity.Comment;
            }
        }

        return null;
    }

    /// <summary>
    /// Asks the filter. A key it cannot be shown (a type <see cref="SshPublicKey"/> does not read) is refused, and so is anything the
    /// filter throws: a request is allowed only when the filter says so.
    /// </summary>
    private async ValueTask<bool> AllowAsync(SshAgentOperation operation, byte[] blob, string? comment, SignedData? signed, SshPublicKey? destination,
        CancellationToken cancellationToken)
    {
        if (Describe(blob, comment) is not { } described)
        {
            return false;
        }

        var (key, certificate) = described;

        var request = new SshAgentRequest(operation, key, certificate, [.. _bindings.Where(b => b.IsForwarding).Select(b => b.HostKey)], destination)
        {
            Purpose = signed?.Purpose,
            Namespace = signed?.Namespace,
            UserName = signed?.UserName,
        };

        bool allowed;
        try
        {
            allowed = await _filter!(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The filter is the application's code; whatever it throws, the request is refused and the channel carries on.
            SshLog.AgentFilterFailed(_logger, ex.GetType().Name);
            return false;
        }

        if (!allowed)
        {
            SshLog.ForwardedAgentRequestRefused(_logger, operation, key.Fingerprint);
        }

        return allowed;
    }

    /// <summary>A listed blob as the filter sees it: the key, and the certificate when it is one; null when it cannot be read.</summary>
    internal static (SshPublicKey Key, SshCertificate? Certificate)? Describe(byte[] blob, string? comment)
    {
        comment = string.IsNullOrEmpty(comment) || comment.AsSpan().IndexOfAny('\r', '\n') >= 0 ? null : comment;
        try
        {
            if (SshCertificate.IsCertificateAlgorithm(new SshReader(blob).ReadUtf8String()))
            {
                var certificate = SshCertificate.FromBlob(blob, comment);
                return (SshPublicKey.FromVerifyingKey(certificate.Key, comment), certificate);
            }

            return (SshPublicKey.FromBlob(blob, comment), null);
        }
        catch (Exception ex) when (ex is SshProtocolException or FormatException)
        {
            return null;
        }
    }

    /// <summary>A host key (or host certificate's key) to verify a session binding with, or null when it cannot be read.</summary>
    private static VerifyingKey? ReadHostKey(ReadOnlySpan<byte> blob)
    {
        try
        {
            return SshCertificate.IsCertificateAlgorithm(new SshReader(blob).ReadUtf8String())
                ? SshCertificate.FromBlob(blob).Key
                : VerifyingKey.Parse(blob);
        }
        catch (Exception ex) when (ex is SshProtocolException or FormatException)
        {
            return null;
        }
    }

    /// <summary>SSH_AGENTC_SIGN_REQUEST: the type, the key blob, the data and the flags, and nothing after them.</summary>
    internal static (byte[] Blob, byte[] Data, uint Flags) ReadSignRequest(ReadOnlySpan<byte> message)
    {
        var reader = new SshReader(message);
        reader.ReadByte();
        var blob = reader.ReadString().ToArray();
        var data = reader.ReadString().ToArray();
        var flags = reader.ReadUInt32();
        if (!reader.IsEmpty)
        {
            throw new SshProtocolException("Data after the signing request.");
        }

        return (blob, data, flags);
    }

    private static string ReadExtensionName(ReadOnlySpan<byte> message, out int bodyOffset)
    {
        var reader = new SshReader(message);
        reader.ReadByte();
        var name = reader.ReadUtf8String();
        bodyOffset = message.Length - reader.Remaining.Length;
        return name;
    }

    /// <summary>
    /// What the data to sign is: an SSH signature (<c>SSHSIG</c>, PROTOCOL.sshsig), a public key login request (RFC 4252 section 7, or
    /// OpenSSH's host-bound form, which ends with the server's host key), an OpenSSH certificate without its signature
    /// (PROTOCOL.certkeys), or, with a null purpose, something else: other programs sign their own formats through agents
    /// (pam_ssh_agent_auth, for one), and whether to sign those is the filter's decision.
    /// </summary>
    internal static SignedData Classify(ReadOnlySpan<byte> data) => Recognize(data) ?? Unrecognized;

    private static readonly SignedData Unrecognized = new(Purpose: null);

    private static SignedData? Recognize(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith("SSHSIG"u8))
        {
            try
            {
                var sshsig = new SshReader(data[6..]);
                var name = sshsig.ReadUtf8String();
                sshsig.ReadString(); // reserved
                sshsig.ReadUtf8String(); // hash algorithm
                sshsig.ReadString(); // the message's hash
                return sshsig.IsEmpty && name.Length > 0 ? new SignedData(SshSignaturePurpose.FileSignature, Namespace: name) : null;
            }
            catch (SshProtocolException)
            {
                return null;
            }
        }

        if (ReadLoginRequest(data) is { } login)
        {
            return login;
        }

        try
        {
            return SshCertificate.IsCertificateAlgorithm(new SshReader(data).ReadUtf8String()) ? new SignedData(SshSignaturePurpose.Certificate) : null;
        }
        catch (SshProtocolException)
        {
            return null;
        }
    }

    private static SignedData? ReadLoginRequest(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new SshReader(data);
            var sessionId = reader.ReadString().ToArray();
            if (sessionId.Length is 0 or > MaxSessionIdLength || reader.ReadByte() != SshMessage.UserAuthRequest)
            {
                return null;
            }

            var user = reader.ReadUtf8String();
            reader.ReadString(); // the service
            var method = reader.ReadUtf8String();
            if (method is not ("publickey" or Hostbound) || !reader.ReadBoolean())
            {
                return null;
            }

            reader.ReadString(); // the algorithm
            reader.ReadString(); // the key
            var hostKey = method == Hostbound ? reader.ReadString().ToArray() : null;
            return reader.IsEmpty ? new SignedData(SshSignaturePurpose.Authentication, UserName: user, SessionId: sessionId, HostKey: hostKey) : null;
        }
        catch (SshProtocolException)
        {
            return null;
        }
    }

    internal static byte[] Encode(Action<SshWriter> write) => SshPrivateKey.Encode(write);
}

/// <summary>The keys of an in-process agent (<see cref="SshAgent.FromKeys"/>), signing with them here.</summary>
internal sealed class AgentKeyring : AgentBackend
{
    private readonly IReadOnlyList<(AgentIdentity Identity, SshPrivateKey Key)> _keys;
    private readonly IReadOnlyList<AgentIdentity> _identities;

    public AgentKeyring(IEnumerable<SshPrivateKey> keys)
    {
        // A key paired with a certificate is listed twice, as ssh-add adds it: the plain key, then the certificate. A key given twice is
        // listed once.
        var list = new List<(AgentIdentity, SshPrivateKey)>();
        foreach (var key in keys)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(keys));
            var comment = key.Comment ?? string.Empty;
            if (key.Certificate is { } certificate)
            {
                Add(certificate.PublicKey.ToArray(), comment, key);
            }

            Add(key.PublicKey.ToArray(), comment, key);
        }

        _keys = list;
        _identities = [.. list.Select(k => k.Item1)];

        void Add(byte[] blob, string comment, SshPrivateKey key)
        {
            if (!list.Any(k => k.Item1.Blob.AsSpan().SequenceEqual(blob)))
            {
                list.Add((new AgentIdentity(blob, comment), key));
            }
        }
    }

    public override ValueTask<IReadOnlyList<AgentIdentity>?> ListAsync(CancellationToken cancellationToken) => ValueTask.FromResult<IReadOnlyList<AgentIdentity>?>(_identities);

    public override async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, byte[] blob, byte[] data, uint flags, SignedData signed,
        CancellationToken cancellationToken)
    {
        var key = _keys.FirstOrDefault(k => k.Identity.Blob.AsSpan().SequenceEqual(blob)).Key;
        if (key is null || Algorithm(key, flags) is not { } algorithm)
        {
            return [AgentServer.Failure];
        }

        byte[] signature;
        try
        {
            // Data of a form not recognised reaches a signer as Other, so a signer whose policy allows logins only still refuses it.
            var request = new SshSignRequest(algorithm, data, signed.Purpose ?? SshSignaturePurpose.Other) { Namespace = signed.Namespace };
            signature = await key.SignAsync(request, binding: null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A signer that refuses (its policy, a key service that is down, a disposed key) is a refused request, as an agent whose user
            // declines a confirmation answers; nothing it throws reaches the server's side.
            return [AgentServer.Failure];
        }

        return AgentServer.Encode(w =>
        {
            w.WriteByte(AgentServer.SignResponse);
            w.WriteString(signature);
        });
    }

    public override ValueTask<byte[]> BindAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken) =>
        ValueTask.FromResult<byte[]>([AgentServer.Success]);

    /// <summary>
    /// The algorithm to sign with, as the key names it (a certificate's algorithms carry its suffix), or null when the key cannot sign
    /// as asked. RSA follows the flags as ssh-agent does (SHA-256 when both are set); other keys sign with their one algorithm.
    /// </summary>
    internal static string? Algorithm(SshPrivateKey key, uint flags)
    {
        var supported = key.SignatureAlgorithms;
        var first = SshCertificate.BaseAlgorithm(supported[0]);
        var wanted = first.StartsWith("rsa-sha2-", StringComparison.Ordinal)
            ? (flags & AgentServer.RsaSha2_256) != 0 ? SshAlgorithms.RsaSha2_256 : (flags & AgentServer.RsaSha2_512) != 0 ? SshAlgorithms.RsaSha2_512 : null
            : first;
        return supported.FirstOrDefault(a => SshCertificate.BaseAlgorithm(a) == wanted);
    }
}

/// <summary>A real agent behind a filter: requests the server has allowed are relayed to it on one connection, as they came.</summary>
internal sealed class RelayedAgent(Stream stream) : AgentBackend
{
    public override async ValueTask<IReadOnlyList<AgentIdentity>?> ListAsync(CancellationToken cancellationToken)
    {
        var reply = await SshAgent.ExchangeAsync(stream, new byte[] { AgentServer.RequestIdentities }, cancellationToken).ConfigureAwait(false);
        return ReadIdentities(reply);
    }

    /// <summary>An SSH_AGENT_IDENTITIES_ANSWER's keys, or null for any other reply; a malformed one throws <see cref="SshProtocolException"/>.</summary>
    internal static IReadOnlyList<AgentIdentity>? ReadIdentities(ReadOnlySpan<byte> reply)
    {
        var reader = new SshReader(reply);
        if (reader.ReadByte() != AgentServer.IdentitiesAnswer)
        {
            return null;
        }

        var count = reader.ReadUInt32();
        if (count > SshAgent.MaxKeys)
        {
            throw new SshProtocolException($"The agent listed {count} keys.");
        }

        var identities = new List<AgentIdentity>((int)count);
        for (var i = 0; i < count; i++)
        {
            identities.Add(new AgentIdentity(reader.ReadString().ToArray(), reader.ReadUtf8String()));
        }

        return identities;
    }

    public override async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, byte[] blob, byte[] data, uint flags, SignedData signed,
        CancellationToken cancellationToken) =>
        await SshAgent.ExchangeAsync(stream, message, cancellationToken).ConfigureAwait(false);

    public override async ValueTask<byte[]> BindAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken) =>
        await SshAgent.ExchangeAsync(stream, message, cancellationToken).ConfigureAwait(false);
}

/// <summary>
/// Serves a forwarded agent channel with an <see cref="AgentServer"/>: reads framed requests (<c>uint32 length || message</c>), answers
/// each, and closes the channel when the server's side ends it, sends a message that is empty or larger than OpenSSH's limit (256 KiB),
/// or the agent behind it fails.
/// </summary>
internal static class AgentChannelServer
{
    public static async Task RunAsync(SshChannel channel, AgentServer server, CancellationToken stop)
    {
        var buffer = new byte[4096];
        var count = 0;
        try
        {
            while (await channel.ReadAsync(stop).ConfigureAwait(false) is { } chunk)
            {
                using (chunk)
                {
                    var data = chunk.Data.Span;
                    if (count + data.Length > buffer.Length)
                    {
                        // Bounded: at most one message (checked against the limit below) and one channel packet are ever held.
                        Array.Resize(ref buffer, Math.Max(buffer.Length * 2, count + data.Length));
                    }

                    data.CopyTo(buffer.AsSpan(count));
                    count += data.Length;
                }

                while (count >= 4)
                {
                    var length = BinaryPrimitives.ReadUInt32BigEndian(buffer);
                    if (length is 0 or > SshAgent.MaxMessageLength)
                    {
                        return;
                    }

                    var frame = 4 + (int)length;
                    if (count < frame)
                    {
                        break;
                    }

                    var reply = await server.HandleAsync(buffer.AsMemory(4, (int)length), stop).ConfigureAwait(false);
                    var framed = new byte[4 + reply.Length];
                    BinaryPrimitives.WriteUInt32BigEndian(framed, (uint)reply.Length);
                    reply.CopyTo(framed, 4);
                    await channel.SendDataAsync(framed, stop).ConfigureAwait(false);

                    buffer.AsSpan(frame, count - frame).CopyTo(buffer);
                    count -= frame;
                }
            }
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // The channel closed, the connection ended, or the agent behind the filter went away.
        }
        finally
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            channel.DiscardUnread();
        }
    }
}
