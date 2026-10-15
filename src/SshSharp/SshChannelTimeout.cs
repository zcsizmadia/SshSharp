namespace SshSharp;

/// <summary>
/// A channel idle timeout, as OpenSSH's <c>ChannelTimeout</c> sets one (<c>type=interval</c>): channels of <see cref="ChannelType"/> with
/// no data in either direction for <see cref="Timeout"/> are closed by the client. See <see cref="SshClientOptions.ChannelTimeouts"/>.
/// </summary>
/// <remarks>
/// <see cref="ChannelType"/> is an OpenSSH channel type name, or a pattern of them (<c>*</c> and <c>?</c>, case-sensitive):
/// <c>session</c> (commands, shells, subsystems and SFTP), <c>direct-tcpip</c> (TCP tunnels and local or dynamic forwarding),
/// <c>direct-streamlocal@openssh.com</c> (Unix-socket tunnels), <c>forwarded-tcpip</c> and <c>forwarded-streamlocal@openssh.com</c> (remote
/// forwarding), <c>agent-connection</c> (agent forwarding), or <c>*</c> for all of them. The first entry whose pattern matches a channel
/// applies; <see cref="TimeSpan.Zero"/> means no timeout for that type.
/// </remarks>
public sealed record SshChannelTimeout
{
    /// <summary>A timeout of <paramref name="timeout"/> for channels whose OpenSSH type matches <paramref name="channelType"/>.</summary>
    /// <exception cref="ArgumentException">The type is empty or contains white space.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout is negative.</exception>
    public SshChannelTimeout(string channelType, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        if (channelType.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("A channel type pattern contains no white space.", nameof(channelType));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(timeout, TimeSpan.Zero);
        ChannelType = channelType;
        Timeout = timeout;
    }

    /// <summary>The OpenSSH channel type, or a pattern (<c>*</c>, <c>?</c>) of them.</summary>
    public string ChannelType { get; }

    /// <summary>How long a matching channel may go without data; zero for no limit.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>The timeout for a channel of <paramref name="type"/> under <paramref name="timeouts"/>: the first match, or null for none.</summary>
    internal static TimeSpan? For(IReadOnlyList<SshChannelTimeout> timeouts, string type)
    {
        foreach (var entry in timeouts)
        {
            if (Config.Glob.IsMatch(entry.ChannelType, type, ignoreCase: false))
            {
                return entry.Timeout > TimeSpan.Zero ? entry.Timeout : null;
            }
        }

        return null;
    }
}
