namespace SshSharp;

/// <summary>Limits on a key added to an agent (<see cref="SshAgent.AddKeyAsync"/>), as <c>ssh-add -t</c> and <c>ssh-add -c</c> set them.</summary>
public sealed record SshAgentKeyConstraints
{
    /// <summary>How long the agent keeps the key (<c>ssh-add -t</c>); null for as long as the agent runs. Whole seconds, at least one.</summary>
    public TimeSpan? Lifetime
    {
        get;
        init
        {
            if (value is { } lifetime && lifetime <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), value, "A lifetime must be positive.");
            }

            field = value;
        }
    }

    /// <summary>Whether the agent asks the user to confirm each use of the key (<c>ssh-add -c</c>; OpenSSH's agent runs ssh-askpass).</summary>
    public bool Confirm { get; init; }

    /// <summary>
    /// Where the key may be used (<c>ssh-add -h</c>, OpenSSH 8.9 and later): only to authenticate to these hosts, reached as listed.
    /// Empty (the default) for anywhere. The agent refuses the key elsewhere, including over agent forwarding to an unlisted host.
    /// </summary>
    public IReadOnlyList<SshAgentDestination> Destinations
    {
        get;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            foreach (var destination in value)
            {
                if (destination.To.HostKeys.Count == 0 || destination.From is { HostKeys.Count: 0 })
                {
                    throw new ArgumentException("Every host in a destination constraint needs at least one host key.", nameof(value));
                }

                if (destination.From is { UserName: not null })
                {
                    throw new ArgumentException("The host a hop comes from cannot name a user.", nameof(value));
                }
            }

            field = [.. value]; // a copy: changing the caller's list later does not change the constraint
        }
    } = [];
}
