using SshSharp.Config;

namespace SshSharp;

/// <summary>
/// A host in an agent destination constraint (<see cref="SshAgentDestination"/>): its name, the user (for the destination only), and the
/// host keys that identify it, or certificate authorities whose host certificates do.
/// </summary>
/// <param name="HostName">The host name, as the agent's session binding reports it (the name used to connect).</param>
/// <param name="HostKeys">The keys that prove the host's identity; at least one.</param>
public sealed record SshAgentHost(string HostName, IReadOnlyList<SshAgentHostKey> HostKeys)
{
    /// <summary>The keys that prove the host's identity (a copy of the list given).</summary>
    public IReadOnlyList<SshAgentHostKey> HostKeys { get; init; } = [.. HostKeys ?? throw new ArgumentNullException(nameof(HostKeys))];

    /// <summary>The user the key may sign in as on this host; null for any user. Only a destination's <see cref="SshAgentDestination.To"/> may name one.</summary>
    public string? UserName { get; init; }

    /// <summary>Equal when the name, the user and the keys (in order) are.</summary>
    public bool Equals(SshAgentHost? other) =>
        other is not null && HostName == other.HostName && UserName == other.UserName && HostKeys.SequenceEqual(other.HostKeys);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(HostName, UserName, HostKeys.Count);
}

/// <summary>A host key in a destination constraint, in SSH wire format; with <paramref name="IsCertificateAuthority"/>, a CA key whose host certificates count.</summary>
public sealed record SshAgentHostKey(ReadOnlyMemory<byte> PublicKey, bool IsCertificateAuthority = false)
{
    /// <summary>Equal when the key bytes and <see cref="IsCertificateAuthority"/> are.</summary>
    public bool Equals(SshAgentHostKey? other) =>
        other is not null && IsCertificateAuthority == other.IsCertificateAuthority && PublicKey.Span.SequenceEqual(other.PublicKey.Span);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(PublicKey.Span);
        hash.Add(IsCertificateAuthority);
        return hash.ToHashCode();
    }
}

/// <summary>
/// One destination constraint on an agent key (OpenSSH's <c>restrict-destination-v00@openssh.com</c>, <c>ssh-add -h</c>): the key may be
/// used to authenticate to <see cref="To"/> when reached from <see cref="From"/>; from this machine when <see cref="From"/> is null. A key
/// used through agent forwarding needs a constraint for each hop: <c>ssh-add -h jump -h "jump&gt;dest"</c> is two destinations. The agent
/// enforces them through the session binding (<c>session-bind@openssh.com</c>) that ssh and SshSharp send.
/// </summary>
public sealed record SshAgentDestination
{
    /// <summary>The host the connection comes from (no user); null for this machine.</summary>
    public SshAgentHost? From { get; init; }

    /// <summary>The host the key may sign in to, optionally as one user.</summary>
    public required SshAgentHost To { get; init; }

    /// <summary>
    /// A destination as <c>ssh-add -h</c> takes it: <c>[user@]host</c>, or <c>from&gt;[user@]host</c> for a hop from another host. Host keys
    /// come from <paramref name="knownHosts"/>, as ssh-add looks them up: each matching key, and <c>@cert-authority</c> keys as authorities;
    /// <c>@revoked</c> keys are left out.
    /// </summary>
    /// <exception cref="FormatException">The specification is malformed, or a host has no keys in <paramref name="knownHosts"/>.</exception>
    public static SshAgentDestination Parse(string specification, params KnownHostsFile[] knownHosts)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(specification);
        ArgumentNullException.ThrowIfNull(knownHosts);
        var parts = specification.Split('>');
        if (parts.Length > 2)
        {
            throw new FormatException($"'{specification}' has more than one '>': give each hop as its own destination.");
        }

        SshAgentHost? from = null;
        if (parts.Length == 2)
        {
            from = Host(parts[0], knownHosts);
            if (from.UserName is not null)
            {
                throw new FormatException($"The host a hop comes from ('{parts[0]}') cannot name a user.");
            }
        }

        return new SshAgentDestination { From = from, To = Host(parts[^1], knownHosts) };
    }

    private static SshAgentHost Host(string text, KnownHostsFile[] knownHosts)
    {
        var at = text.LastIndexOf('@');
        var user = at > 0 ? text[..at] : null;
        var host = text[(at + 1)..];
        if (host.Length == 0 || at == 0)
        {
            throw new FormatException($"'{text}' is not [user@]host.");
        }

        var keys = knownHosts.SelectMany(file => file.Find(host))
            .Where(entry => entry.Marker != KnownHostsMarker.Revoked)
            .Select(entry => new SshAgentHostKey(entry.PublicKey, entry.Marker == KnownHostsMarker.CertAuthority))
            .ToList();
        if (keys.Count == 0)
        {
            throw new FormatException($"No host keys for '{host}' in known_hosts: the agent needs them to tell the host apart.");
        }

        return new SshAgentHost(host, keys) { UserName = user };
    }
}
