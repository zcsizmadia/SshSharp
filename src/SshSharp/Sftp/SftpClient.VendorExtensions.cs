using SshSharp.Protocol;

namespace SshSharp.Sftp;

public sealed partial class SftpClient
{
    /// <summary>What <see cref="GetFileHashAsync"/> asks for when the caller names no algorithms: SHA-2 only, the most common first.</summary>
    private static readonly string[] DefaultHashAlgorithms = ["sha256", "sha512", "sha384", "sha224"];

    /// <summary>The names under which a server announces check-file: the extension, or its two requests.</summary>
    private static readonly string[] CheckFileNames = [SftpProtocol.CheckFileExtension, SftpProtocol.CheckFileNameRequest, SftpProtocol.CheckFileHandleRequest];

    /// <summary>The largest payload <see cref="SendExtendedRequestAsync"/> sends, so the request fits the 256 KiB packet OpenSSH accepts.</summary>
    internal const int MaxExtendedPayload = 255 * 1024;

    /// <summary>
    /// Whether the server announces a file hash extension, so <see cref="GetFileHashAsync"/> can work: <c>check-file</c> (or its request
    /// names <c>check-file-name</c> and <c>check-file-handle</c>), as ProFTPD, Bitvise and Tectia announce it, or the older
    /// <c>md5-hash</c>, which hashes with MD5 only. OpenSSH has neither.
    /// </summary>
    public bool SupportsFileHash => HasCheckFile || HasMd5Hash;

    private bool HasCheckFile =>
        Extensions.ContainsKey(SftpProtocol.CheckFileExtension) || Extensions.ContainsKey(SftpProtocol.CheckFileNameRequest)
        || Extensions.ContainsKey(SftpProtocol.CheckFileHandleRequest);

    private bool HasMd5Hash => Extensions.ContainsKey(SftpProtocol.Md5HashRequest) || Extensions.ContainsKey(SftpProtocol.Md5HashHandleRequest);

    /// <summary>
    /// Asks the server for a hash of <paramref name="path"/>, or of the range from <paramref name="offset"/> of
    /// <paramref name="length"/> bytes, which it computes where the file is (<c>check-file</c>): to check a transfer without reading
    /// the file back. Compare it with a hash of the local copy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The server picks the first of <paramref name="algorithms"/> it supports. By default they are SHA-2 only (<c>sha256</c>,
    /// <c>sha512</c>, <c>sha384</c>, <c>sha224</c>). <c>md5</c>, <c>sha1</c> and <c>crc32</c> are used only when named: they are kept
    /// for servers that offer nothing better, and catch accidental damage (a truncated or corrupted file), not a deliberate change.
    /// A server with only <c>md5-hash</c> is used when <c>md5</c> is named.
    /// </para>
    /// <para>
    /// The hash is what the server says it is: it shows that the server holds the bytes it was sent, as far as the server can be trusted
    /// to compute it. It does not protect against a server that lies.
    /// </para>
    /// <para>
    /// ProFTPD's mod_sftp (1.3.9) hashes a range on to the end of the file unless <paramref name="length"/> is a multiple of its read
    /// size (four file system blocks, 16 KiB on most file systems), so ask it for the whole file, or for a multiple of 64 KiB.
    /// </para>
    /// </remarks>
    /// <param name="path">The remote file.</param>
    /// <param name="algorithms">The hash algorithms to accept, in order of preference, by their <c>check-file</c> names (<c>sha256</c>, <c>sha512</c>, ...); null for SHA-2 only.</param>
    /// <param name="offset">Where the range starts.</param>
    /// <param name="length">The range's length; null to the end of the file.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The algorithm the server used and the hash.</returns>
    /// <exception cref="NotSupportedException">The server announces no file hash extension, or none of <paramref name="algorithms"/> among those it lists.</exception>
    /// <exception cref="SftpException">The server refused: the file does not exist, or the server cannot hash with any of <paramref name="algorithms"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="algorithms"/> is empty or has a name that is not an algorithm name.</exception>
    public async Task<SftpFileHash> GetFileHashAsync(string path, IReadOnlyList<string>? algorithms = null, long offset = 0, long? length = null,
        CancellationToken cancellationToken = default)
    {
        CheckPath(path);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (length is { } count)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count, nameof(length));
        }

        var wanted = algorithms is null ? DefaultHashAlgorithms : CheckAlgorithms(algorithms);
        if (HasCheckFile)
        {
            if (AnnouncedHashAlgorithms() is { } announced && !wanted.Any(announced.Contains))
            {
                throw new NotSupportedException(
                    $"The server cannot hash with {string.Join(", ", wanted)} (it offers {string.Join(", ", announced)} with check-file).");
            }

            var reply = Extensions.ContainsKey(SftpProtocol.CheckFileExtension) || Extensions.ContainsKey(SftpProtocol.CheckFileNameRequest)
                ? await CheckFileAsync(path, wanted, offset, length, cancellationToken).ConfigureAwait(false)
                : null;

            // A server that announces only check-file-handle, or a plain check-file that turns out not to take paths, gets the handle.
            if (reply is null || (!Extensions.ContainsKey(SftpProtocol.CheckFileNameRequest) && IsUnsupported(reply)))
            {
                reply = await WithReadHandleAsync(path, handle => CheckFileAsync(handle, wanted, offset, length, cancellationToken), cancellationToken).ConfigureAwait(false);
            }

            if (reply.Type != SftpProtocol.ExtendedReply)
            {
                ThrowStatus(reply, "Hashing", path);
            }

            var (algorithm, hash) = Parse(reply, (ref SshReader r) => SftpExtensionReplies.ParseCheckFile(ref r, wanted));
            return new SftpFileHash(algorithm, hash);
        }

        if (HasMd5Hash && wanted.Contains("md5"))
        {
            var reply = Extensions.ContainsKey(SftpProtocol.Md5HashRequest)
                ? await Md5HashAsync(SftpProtocol.Md5HashRequest, path, offset, length, cancellationToken).ConfigureAwait(false)
                : await WithReadHandleAsync(path, handle => Md5HashAsync(SftpProtocol.Md5HashHandleRequest, handle, offset, length, cancellationToken), cancellationToken).ConfigureAwait(false);
            if (reply.Type != SftpProtocol.ExtendedReply)
            {
                ThrowStatus(reply, "Hashing", path);
            }

            return new SftpFileHash("md5", Parse(reply, static (ref SshReader r) => SftpExtensionReplies.ParseMd5Hash(ref r)));
        }

        throw new NotSupportedException(HasMd5Hash
            ? "The server hashes files with MD5 only (md5-hash): name \"md5\" in the algorithms to use it."
            : "The server cannot hash files (it lacks check-file).");
    }

    /// <summary>The caller's algorithm names, checked: at least one, each a name the protocol can carry (it is sent in a comma-separated list).</summary>
    private static string[] CheckAlgorithms(IReadOnlyList<string> algorithms)
    {
        if (algorithms.Count == 0)
        {
            throw new ArgumentException("Name at least one hash algorithm.", nameof(algorithms));
        }

        foreach (var name in algorithms)
        {
            if (name is null || !SftpExtensionReplies.IsAlgorithmName(name))
            {
                throw new ArgumentException($"'{name}' is not a hash algorithm name (lower case, such as sha256).", nameof(algorithms));
            }
        }

        return [.. algorithms.Distinct(StringComparer.Ordinal)];
    }

    /// <summary>The algorithms the server lists with its check-file announcement, if it lists them.</summary>
    private IReadOnlyList<string>? AnnouncedHashAlgorithms()
    {
        foreach (var name in CheckFileNames)
        {
            if (Extensions.TryGetValue(name, out var data) && SftpExtensionReplies.AnnouncedAlgorithms(data) is { } announced)
            {
                return announced;
            }
        }

        return null;
    }

    private static bool IsUnsupported(SftpResponse reply) =>
        reply.Type == SftpProtocol.Status && reply.Packet.Length >= 9 && reply.Body.ReadUInt32() == (uint)SftpStatusCode.OperationUnsupported;

    /// <summary>Opens <paramref name="path"/> for reading, runs <paramref name="request"/> on its handle, and closes it.</summary>
    private async Task<SftpResponse> WithReadHandleAsync(string path, Func<byte[], Task<SftpResponse>> request, CancellationToken cancellationToken)
    {
        var (handle, _) = await OpenHandleAsync(path, FileMode.Open, FileAccess.Read, cancellationToken).ConfigureAwait(false);
        try
        {
            return await request(handle).ConfigureAwait(false);
        }
        finally
        {
            await CloseHandleAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>check-file-name (a path) or check-file-handle: one hash of the range (block size 0).</summary>
    private Task<SftpResponse> CheckFileAsync(object target, string[] algorithms, long offset, long? length, CancellationToken cancellationToken) =>
        _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            if (target is string path)
            {
                w.WriteString(SftpProtocol.CheckFileNameRequest);
                w.WriteString(path);
            }
            else
            {
                w.WriteString(SftpProtocol.CheckFileHandleRequest);
                w.WriteString((byte[])target);
            }

            w.WriteString(string.Join(',', algorithms));
            w.WriteUInt64((ulong)offset);
            w.WriteUInt64((ulong)(length ?? 0)); // 0: to the end of the file
            w.WriteUInt32(0); // block size 0: one hash for the whole range
        }, cancellationToken);

    /// <summary>md5-hash (a path) or md5-hash-handle, without a quick-check hash (so the server always answers with the hash).</summary>
    private Task<SftpResponse> Md5HashAsync(string request, object target, long offset, long? length, CancellationToken cancellationToken) =>
        _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(request);
            if (target is string path)
            {
                w.WriteString(path);
            }
            else
            {
                w.WriteString((byte[])target);
            }

            w.WriteUInt64((ulong)offset);
            w.WriteUInt64((ulong)(length ?? 0)); // 0: to the end of the file
            w.WriteString(ReadOnlySpan<byte>.Empty); // no quick-check hash
        }, cancellationToken);

    /// <summary>
    /// Sends an <c>SSH_FXP_EXTENDED</c> request named <paramref name="name"/> with <paramref name="data"/> after the name, and returns
    /// the server's reply as it is: for vendor extensions this client has no method for. <see cref="Extensions"/> lists what the server
    /// announces.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="data"/> is the request's fields after its name, encoded as the extension defines them (SSH strings are a big-endian
    /// <c>uint32</c> length and the bytes). The reply is usually <c>SSH_FXP_EXTENDED_REPLY</c> (<see cref="SftpExtendedReply.IsExtendedReply"/>,
    /// with the extension's fields in <see cref="SftpExtendedReply.Data"/>) or <c>SSH_FXP_STATUS</c> (<see cref="SftpExtendedReply.Status"/>);
    /// most servers answer <see cref="SftpStatusCode.OperationUnsupported"/> to a request they do not know. A server error is returned,
    /// not thrown: call <see cref="SftpExtendedReply.EnsureSuccess"/> to throw it.
    /// </para>
    /// <para>
    /// Some servers end the whole SFTP session on a request they do not know instead (Erlang/OTP's <c>ssh_sftpd</c> does), which fails
    /// this call and every other request on the session with an <see cref="SshException"/> (<see cref="SshFailureReason.ChannelClosed"/>).
    /// Send only extensions the server announces in <see cref="Extensions"/>.
    /// </para>
    /// <para>
    /// The request goes to the server as given: an extension that changes files does so, and one that opens a handle leaves it to the
    /// caller to close (with a raw <c>SSH_FXP_CLOSE</c> it cannot send through this method; such extensions are best avoided). The
    /// server's reply is untrusted data: parse it defensively.
    /// </para>
    /// </remarks>
    /// <param name="name">The extension's request name, for example <c>space-available</c> or <c>vendor@example.com</c>.</param>
    /// <param name="data">The request's fields after the name, at most 255 KiB; empty for none.</param>
    /// <param name="cancellationToken">Stops waiting for the reply (the server may still carry the request out).</param>
    /// <returns>The reply's packet type and fields, and its status when it is a status.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is empty or contains NUL.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="data"/> is longer than 255 KiB.</exception>
    public async Task<SftpExtendedReply> SendExtendedRequestAsync(string name, ReadOnlyMemory<byte> data = default, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.Contains('\0'))
        {
            throw new ArgumentException("An extension name must not contain NUL.", nameof(name));
        }

        ArgumentOutOfRangeException.ThrowIfGreaterThan(data.Length, MaxExtendedPayload, nameof(data));
        using var reply = await _channel.RequestAsync(SftpProtocol.Extended, w =>
        {
            w.WriteString(name);
            w.WriteBytes(data.Span);
        }, cancellationToken).ConfigureAwait(false);
        return ToExtendedReply(name, reply);
    }

    /// <summary>A reply as <see cref="SftpExtendedReply"/>: its fields copied out (a DATA reply's buffer goes back to the pool), a status parsed.</summary>
    internal static SftpExtendedReply ToExtendedReply(string name, SftpResponse reply)
    {
        var fields = reply.Packet.Length < 5 ? [] : reply.Packet[5..].ToArray();
        if (reply.Type != SftpProtocol.Status)
        {
            return new SftpExtendedReply(name, reply.Type, fields, null, null);
        }

        var (status, message) = Parse(reply, static (ref SshReader r) => SftpExtensionReplies.ParseStatus(ref r));
        return new SftpExtendedReply(name, reply.Type, fields, status, SanitizedMessage(message));
    }
}

/// <summary>A hash of a remote file, or of a range of it, as the server computed it (<see cref="SftpClient.GetFileHashAsync"/>).</summary>
public sealed class SftpFileHash
{
    private readonly byte[] _hash;

    internal SftpFileHash(string algorithm, byte[] hash)
    {
        Algorithm = algorithm;
        _hash = hash;
    }

    /// <summary>The algorithm the server used, by its <c>check-file</c> name (<c>sha256</c>, <c>sha512</c>, <c>md5</c>, ...): one of those asked for.</summary>
    public string Algorithm { get; }

    /// <summary>The hash (digest) the server sent.</summary>
    public ReadOnlyMemory<byte> Hash => _hash;

    /// <summary>Whether <paramref name="hash"/>, computed locally with <see cref="Algorithm"/>, is this hash.</summary>
    /// <param name="hash">A digest of the local copy.</param>
    public bool Matches(ReadOnlySpan<byte> hash) => hash.SequenceEqual(_hash);
}

/// <summary>The server's reply to <see cref="SftpClient.SendExtendedRequestAsync"/>, as it came.</summary>
public sealed class SftpExtendedReply
{
    private readonly string _name;
    private readonly byte[] _data;

    internal SftpExtendedReply(string name, byte packetType, byte[] data, SftpStatusCode? status, string? statusMessage)
    {
        _name = name;
        PacketType = packetType;
        _data = data;
        Status = status;
        StatusMessage = statusMessage;
    }

    /// <summary>
    /// The reply's SFTP packet type: 201 (<c>SSH_FXP_EXTENDED_REPLY</c>), 101 (<c>SSH_FXP_STATUS</c>), or another reply type an
    /// extension answers with, such as 104 (<c>SSH_FXP_NAME</c>) or 102 (<c>SSH_FXP_HANDLE</c>).
    /// </summary>
    public byte PacketType { get; }

    /// <summary>Whether this is an <c>SSH_FXP_EXTENDED_REPLY</c>, the extension's own reply.</summary>
    public bool IsExtendedReply => PacketType == SftpProtocol.ExtendedReply;

    /// <summary>The reply's fields after its request id, as the server sent them (for a status: its code, message and language tag).</summary>
    public ReadOnlyMemory<byte> Data => _data;

    /// <summary>The status, when the reply is an <c>SSH_FXP_STATUS</c>; null otherwise.</summary>
    public SftpStatusCode? Status { get; }

    /// <summary>The status message, when the reply is an <c>SSH_FXP_STATUS</c>, without control characters and at most 200 characters; null otherwise.</summary>
    public string? StatusMessage { get; }

    /// <summary>Throws when the reply is a status other than <see cref="SftpStatusCode.Ok"/>; returns this reply otherwise.</summary>
    /// <returns>This reply.</returns>
    /// <exception cref="SftpException">The server answered with an error status.</exception>
    public SftpExtendedReply EnsureSuccess()
    {
        if (Status is { } status && status != SftpStatusCode.Ok)
        {
            var reason = StatusMessage is { Length: > 0 } said ? said : status.ToString();
            throw new SftpException(status, $"The extended request '{_name}' failed: {reason}.");
        }

        return this;
    }
}
