namespace SshSharp;

/// <summary>What became of one authentication attempt (see <see cref="SshAuthenticationException.Attempts"/>).</summary>
public enum SshAuthenticationOutcome
{
    /// <summary>The server refused it (<c>SSH_MSG_USERAUTH_FAILURE</c> without partial success): a wrong password, a key it does not know.</summary>
    Rejected,

    /// <summary>The server accepted it, but requires another method too (sshd's <c>AuthenticationMethods</c>).</summary>
    PartialSuccess,

    /// <summary>
    /// The credentials for the method were set, but the server did not offer it (for example keys, and a server that takes only
    /// passwords). Nothing was sent.
    /// </summary>
    NotOffered,

    /// <summary>
    /// The key has no signature algorithm the server accepts (its <c>server-sig-algs</c>), for example an RSA key and a server that
    /// lists no <c>rsa-sha2-*</c>. The key was not offered.
    /// </summary>
    NoAcceptedAlgorithm,

    /// <summary>
    /// The server would accept the key, but the agent did not sign with it: the agent no longer holds it, or the user declined to
    /// confirm (<c>ssh-add -c</c>).
    /// </summary>
    SigningFailed,

    /// <summary>
    /// This side gave up: <see cref="SshClientOptions.KeyboardInteractive"/> or <see cref="SshClientOptions.PasswordProvider"/> returned
    /// null, or the server's keyboard-interactive questions were not a single password prompt that <see cref="SshClientOptions.Password"/>
    /// could answer.
    /// </summary>
    Declined,

    /// <summary>
    /// The password was right but has expired, and was not changed: <see cref="SshClientOptions.ChangePassword"/> is not set or returned
    /// null, or the server refused every new password it was given.
    /// </summary>
    PasswordChangeRequired,

    /// <summary>The method could not be used on this side: no Kerberos ticket, or no GSS-API library or .NET 10 for <c>gssapi-with-mic</c>.</summary>
    Unavailable,
}

/// <summary>
/// One authentication attempt and what became of it, listed by <see cref="SshAuthenticationException.Attempts"/>. It names the method
/// and, for a key, its fingerprint: never a password, an answer or the user name.
/// </summary>
/// <param name="Method">The method: <c>gssapi-with-mic</c>, <c>publickey</c>, <c>keyboard-interactive</c> or <c>password</c>.</param>
/// <param name="Outcome">What became of it.</param>
/// <param name="KeyFingerprint">For <c>publickey</c>, the key's SHA-256 fingerprint (<c>SHA256:...</c>), as <see cref="SshPrivateKey.Fingerprint"/>; otherwise null.</param>
public sealed record SshAuthenticationAttempt(string Method, SshAuthenticationOutcome Outcome, string? KeyFingerprint = null)
{
    /// <summary>The method, the key's fingerprint if any, and the outcome, for example <c>publickey SHA256:... (Rejected)</c>.</summary>
    public override string ToString() => KeyFingerprint is null ? $"{Method} ({Outcome})" : $"{Method} {KeyFingerprint} ({Outcome})";
}
