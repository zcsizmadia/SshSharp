using System.Diagnostics;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// A private key given as a value, for <see cref="SshEndpointOptions.PrivateKeys"/>: the key text itself rather than a file, as containers
/// and secret stores supply it (an environment variable, a mounted Kubernetes secret bound through configuration, Key Vault, user
/// secrets). Mutable, so configuration can bind to it (<c>Ssh:Deploy:PrivateKeys:0:Key</c>). Neither the key nor the passphrase appears in
/// <see cref="ToString"/> or in the debugger.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public sealed class SshEndpointPrivateKey
{
    /// <summary>
    /// The private key's text, as a key file holds it: OpenSSH (<c>-----BEGIN OPENSSH PRIVATE KEY-----</c>), PEM (PKCS#8, PKCS#1 or SEC1)
    /// or PuTTY (<c>.ppk</c>), as <see cref="SshPrivateKey.Parse"/> reads it. Bind it from a secret store, never from a checked-in file.
    /// </summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? Key { get; set; }

    /// <summary>The passphrase of an encrypted <see cref="Key"/>; ignored for an unencrypted one.</summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? Passphrase { get; set; }

    /// <summary>Describes the entry without its secrets: whether a key and a passphrase are set, never their values.</summary>
    public override string ToString() =>
        $"{nameof(SshEndpointPrivateKey)} {{ Key = {(string.IsNullOrEmpty(Key) ? "(not set)" : "(redacted)")}, " +
        $"Passphrase = {(string.IsNullOrEmpty(Passphrase) ? "(not set)" : "(redacted)")} }}";
}
