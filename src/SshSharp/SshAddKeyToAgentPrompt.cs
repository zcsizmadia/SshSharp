namespace SshSharp;

/// <summary>
/// A key about to be added to the agent under ssh_config's <c>AddKeysToAgent ask</c>, passed to
/// <see cref="SshConfigConnectOptions.ConfirmAddKeyToAgent"/>. It carries what ssh's prompt shows ("Add key <c>file</c>
/// (<c>comment</c>) to agent?"), and the key's fingerprint.
/// </summary>
public sealed class SshAddKeyToAgentPrompt
{
    internal SshAddKeyToAgentPrompt(string identityFile, string fingerprint, string? comment, string host)
    {
        IdentityFile = identityFile;
        Fingerprint = fingerprint;
        Comment = comment;
        Host = host;
    }

    /// <summary>The path of the <c>IdentityFile</c> the key was loaded from.</summary>
    public string IdentityFile { get; }

    /// <summary>The key's SHA-256 fingerprint, as <c>ssh-add -l</c> shows it (<c>SHA256:...</c>).</summary>
    public string Fingerprint { get; }

    /// <summary>The key's comment from the file, or null when it has none.</summary>
    public string? Comment { get; }

    /// <summary>The host the key was just accepted by (its <c>HostName</c>).</summary>
    public string Host { get; }
}
