namespace SshSharp;

/// <summary>A private key file format to write with <see cref="SshPrivateKey.SaveAsync(string, SshPrivateKeyFormat, string?, System.Threading.CancellationToken)"/>.</summary>
public enum SshPrivateKeyFormat
{
    /// <summary>
    /// The OpenSSH private key format (<c>BEGIN OPENSSH PRIVATE KEY</c>), as <c>ssh-keygen</c> writes by default; see
    /// <see cref="SshPrivateKey.ToOpenSshPrivateKey"/>. It keeps the comment, and every key type can be encrypted.
    /// </summary>
    OpenSsh,

    /// <summary>
    /// PKCS#8 PEM (<c>BEGIN PRIVATE KEY</c>, or <c>BEGIN ENCRYPTED PRIVATE KEY</c> with a passphrase), which OpenSSL and the .NET
    /// cryptography APIs read; see <see cref="SshPrivateKey.ToPkcs8PrivateKey"/>. It has no comment, and an Ed25519 key cannot be
    /// encrypted.
    /// </summary>
    Pkcs8,

    /// <summary>
    /// A PuTTY version 3 key file (<c>.ppk</c>), as PuTTYgen 0.75 and later writes it; see <see cref="SshPrivateKey.ToPuttyPrivateKey"/>.
    /// </summary>
    Putty,
}
