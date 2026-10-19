using SshSharp.Config;

namespace SshSharp;

/// <summary>
/// A list of revoked keys, as sshd's <c>RevokedKeys</c> and ssh's <c>RevokedHostKeys</c> read it: an OpenSSH Key Revocation List (KRL,
/// the binary file <c>ssh-keygen -k</c> writes), or a text file of public keys, one per line. Check a user's key or certificate against it
/// before trusting it, as <c>ssh-keygen -Q</c> does.
/// </summary>
/// <remarks>
/// <para>
/// A KRL revokes plain keys (explicitly, or by SHA-1 or SHA-256 fingerprint) and certificates (by serial number, serial range or key
/// id, for one certificate authority or for any). A certificate is also revoked when its certified key or its authority's key is.
/// Serial 0, which a certificate carries when its authority assigned none, is never revoked by serial. In a text file of keys, lines
/// that do not parse are skipped, as in OpenSSH, and a certificate line revokes the key it certifies.
/// </para>
/// <para>
/// A KRL's signature sections are read but not verified: OpenSSH checks a signature only against the key the KRL itself carries, which
/// proves nothing about who wrote the file. The file is trusted as local configuration, so protect it as such. Immutable and
/// thread-safe once read.
/// </para>
/// </remarks>
public sealed class SshKeyRevocationList
{
    private readonly RevokedKeyList _list;

    private SshKeyRevocationList(RevokedKeyList list) => _list = list;

    /// <summary>Whether the data was a KRL; false for a text file of public keys.</summary>
    public bool IsKrl => _list.IsKrl;

    /// <summary>
    /// Reads a KRL, or, when <paramref name="data"/> does not start with the KRL header (<c>SSHKRL</c>), a text file of public keys in
    /// UTF-8, as OpenSSH tells them apart.
    /// </summary>
    /// <param name="data">The file's contents.</param>
    /// <exception cref="FormatException">The data is a malformed KRL, or uses a section or critical extension this library does not know
    /// (a KRL is refused rather than read in part, since a part could leave a revoked key out).</exception>
    public static SshKeyRevocationList Parse(ReadOnlySpan<byte> data) => new(RevokedKeyList.Parse(data));

    /// <summary>Reads a revoked keys file, as <see cref="Parse"/> does.</summary>
    /// <param name="path">The file.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <exception cref="FormatException">The file is a malformed KRL, or uses a KRL feature this library does not know.</exception>
    /// <exception cref="IOException">The file cannot be read, or is larger than 16 MiB.</exception>
    public static async Task<SshKeyRevocationList> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new(await RevokedKeyList.LoadAsync(path, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Whether <paramref name="key"/> is revoked: listed, or listed by its SHA-1 or SHA-256 fingerprint.</summary>
    /// <param name="key">The key, for example a user's from an <c>authorized_keys</c> line.</param>
    public bool IsRevoked(SshPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return _list.IsRevoked(key.Blob.Span, certificate: null);
    }

    /// <summary>
    /// Whether <paramref name="certificate"/> is revoked: by its serial number or key id (for its authority, or for any), or because its
    /// certified key or its authority's key is.
    /// </summary>
    /// <param name="certificate">The certificate, a user's or a host's.</param>
    public bool IsRevoked(SshCertificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return _list.IsRevoked(certificate.PublicKey.Span, certificate);
    }
}
