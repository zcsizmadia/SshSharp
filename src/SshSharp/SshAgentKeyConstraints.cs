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
}
