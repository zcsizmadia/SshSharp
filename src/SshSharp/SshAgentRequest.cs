namespace SshSharp;

/// <summary>What a program on the server asks of a forwarded agent (<see cref="SshAgentRequest.Operation"/>).</summary>
public enum SshAgentOperation
{
    /// <summary>
    /// Listing the agent's keys (<c>SSH_AGENTC_REQUEST_IDENTITIES</c>, what <c>ssh-add -l</c> and <c>ssh</c> ask first): the filter is
    /// asked once for each key, and a key it refuses is left out of the list.
    /// </summary>
    ListKeys,

    /// <summary>Signing with one key (<c>SSH_AGENTC_SIGN_REQUEST</c>): a key the filter refuses does not sign.</summary>
    Sign,
}

/// <summary>
/// One request that a program on the server makes of a forwarded agent, as <see cref="SshClientOptions.ForwardAgentFilter"/> sees it:
/// which key, what for, and what is known of where the signature goes.
/// </summary>
/// <remarks>
/// <para>
/// Everything here comes from the server's side except <see cref="ForwardingHostKeys"/>' first key, which is the host key of the server
/// this client forwarded the agent to. <see cref="DestinationHostKey"/> and the other forwarding hops are host keys whose signatures
/// over their sessions the agent protocol's session binding (<c>session-bind@openssh.com</c>) proved; <see cref="UserName"/> and
/// <see cref="Namespace"/> are whatever the request says.
/// </para>
/// </remarks>
public sealed class SshAgentRequest
{
    internal SshAgentRequest(SshAgentOperation operation, SshPublicKey key, SshCertificate? certificate, IReadOnlyList<SshPublicKey> forwardingHostKeys,
        SshPublicKey? destinationHostKey)
    {
        Operation = operation;
        Key = key;
        Certificate = certificate;
        ForwardingHostKeys = forwardingHostKeys;
        DestinationHostKey = destinationHostKey;
    }

    /// <summary>Listing the keys, or signing with one.</summary>
    public SshAgentOperation Operation { get; }

    /// <summary>The key: the agent's key itself, or for a certificate (<see cref="Certificate"/>) the key it certifies.</summary>
    public SshPublicKey Key { get; }

    /// <summary>The certificate when the agent's identity is one (a key paired with it, <see cref="SshPrivateKey.WithCertificate"/>); otherwise null.</summary>
    public SshCertificate? Certificate { get; }

    /// <summary>
    /// For <see cref="SshAgentOperation.Sign"/>, what the signature is for, as the data to sign shows it: logging in to a server
    /// (<see cref="SshSignaturePurpose.Authentication"/>), an SSH signature over a file or commit (<see cref="SshSignaturePurpose.FileSignature"/>,
    /// with its <see cref="Namespace"/>), or issuing a certificate (<see cref="SshSignaturePurpose.Certificate"/>). Null for a listing.
    /// Data that is none of these is refused before the filter is asked.
    /// </summary>
    public SshSignaturePurpose? Purpose { get; internal init; }

    /// <summary>For a <see cref="SshSignaturePurpose.FileSignature"/>, its namespace (for example <c>git</c> or <c>file</c>); otherwise null.</summary>
    public string? Namespace { get; internal init; }

    /// <summary>For an <see cref="SshSignaturePurpose.Authentication"/> signature, the user name the program on the server logs in as; otherwise null.</summary>
    public string? UserName { get; internal init; }

    /// <summary>
    /// The host key of the server the program on the server is logging in to, when the agent connection was bound to that session
    /// (<c>session-bind@openssh.com</c>, which OpenSSH 8.9 and later send) and the host key's signature over the session verified; null
    /// when it is not known. For <see cref="SshAgentOperation.Sign"/> the signed login request must be for that same session, or the
    /// request is refused before the filter is asked.
    /// </summary>
    public SshPublicKey? DestinationHostKey { get; }

    /// <summary>
    /// The host keys of the servers the agent was forwarded through, in order: first the server this client connected to, then each
    /// further hop that forwarded it on and bound its connection (<c>ssh -A</c> from OpenSSH 8.9 and later). Empty when not known.
    /// </summary>
    public IReadOnlyList<SshPublicKey> ForwardingHostKeys { get; }
}
