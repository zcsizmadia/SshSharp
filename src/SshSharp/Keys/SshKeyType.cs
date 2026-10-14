namespace SshSharp;

/// <summary>A key type to generate with <see cref="SshPrivateKey.Generate"/>.</summary>
public enum SshKeyType
{
    /// <summary><c>ssh-ed25519</c>: small, fast, and the default of current OpenSSH.</summary>
    Ed25519,

    /// <summary><c>ecdsa-sha2-nistp256</c>.</summary>
    EcdsaNistp256,

    /// <summary><c>ecdsa-sha2-nistp384</c>.</summary>
    EcdsaNistp384,

    /// <summary><c>ecdsa-sha2-nistp521</c>.</summary>
    EcdsaNistp521,

    /// <summary><c>ssh-rsa</c>, signing with <c>rsa-sha2-256</c> or <c>rsa-sha2-512</c>.</summary>
    Rsa,
}
