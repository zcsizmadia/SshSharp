using SshSharp.Config;

namespace SshSharp;

/// <summary>Why a <see cref="KnownHostsVerifier"/> in <see cref="StrictHostKeyChecking.Ask"/> mode is asking.</summary>
public sealed class SshHostKeyPrompt
{
    internal SshHostKeyPrompt(SshHostKeyContext context, IReadOnlyList<string> knownKeyTypes)
    {
        Context = context;
        KnownKeyTypes = knownKeyTypes;
    }

    /// <summary>The host and the key it presented.</summary>
    public SshHostKeyContext Context { get; }

    /// <summary>
    /// Key types already recorded for this host (none for a host seen for the first time). When this is not empty, the server is
    /// presenting a different kind of key than before, which can also mean an attacker who lacks the recorded key: say so to the user.
    /// </summary>
    public IReadOnlyList<string> KnownKeyTypes { get; }
}

/// <summary>
/// Verifies host keys against OpenSSH <c>known_hosts</c> files, with <c>StrictHostKeyChecking</c> semantics:
/// <list type="bullet">
/// <item>A recorded key that matches is trusted; one listed as <c>@revoked</c> is always refused.</item>
/// <item>A different key of a recorded type ("the host key has changed") is refused, except with <see cref="StrictHostKeyChecking.No"/>.</item>
/// <item>An unknown key is refused (<see cref="StrictHostKeyChecking.Yes"/>), offered to <see cref="Ask"/>, or recorded and trusted
/// (<see cref="StrictHostKeyChecking.AcceptNew"/>, <see cref="StrictHostKeyChecking.No"/>). AcceptNew refuses it when keys of other types
/// are already recorded for the host, so a man in the middle cannot get a weaker key type accepted silently.</item>
/// </list>
/// New keys are appended to the first user file; nothing is ever rewritten.
/// </summary>
public sealed class KnownHostsVerifier : SshHostKeyVerifier
{
    private readonly IReadOnlyList<string> _userFiles;
    private readonly IReadOnlyList<string> _globalFiles;

    /// <summary>Creates a verifier.</summary>
    /// <param name="userKnownHostsFiles">The user's files; new keys are recorded in the first one. May be empty (nothing is recorded).</param>
    /// <param name="globalKnownHostsFiles">System-wide files, read only.</param>
    public KnownHostsVerifier(IReadOnlyList<string> userKnownHostsFiles, IReadOnlyList<string>? globalKnownHostsFiles = null)
    {
        ArgumentNullException.ThrowIfNull(userKnownHostsFiles);
        _userFiles = [.. userKnownHostsFiles];
        _globalFiles = [.. globalKnownHostsFiles ?? []];
    }

    /// <summary>How unknown and changed keys are handled. Default <see cref="StrictHostKeyChecking.Ask"/>, as in OpenSSH.</summary>
    public StrictHostKeyChecking Policy { get; init; } = StrictHostKeyChecking.Ask;

    /// <summary>Record new hosts hashed (<c>|1|salt|hash</c>), like <c>HashKnownHosts yes</c>.</summary>
    public bool HashNewEntries { get; init; }

    /// <summary>
    /// Asks the user whether to trust an unknown key in <see cref="StrictHostKeyChecking.Ask"/> mode; true trusts and records it.
    /// Without it, Ask behaves like <see cref="StrictHostKeyChecking.Yes"/>.
    /// </summary>
    public Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? Ask { get; init; }

    /// <summary>The user's <c>~/.ssh/known_hosts</c> and <c>known_hosts2</c>, plus the system-wide files, as <c>ssh</c> uses by default.</summary>
    public static KnownHostsVerifier ForCurrentUser(StrictHostKeyChecking policy = StrictHostKeyChecking.Ask)
    {
        var defaults = SshConfig.Parse(string.Empty).Resolve("localhost");
        return new KnownHostsVerifier(defaults.UserKnownHostsFiles, defaults.GlobalKnownHostsFiles) { Policy = policy };
    }

    /// <summary>The files, policy and hashing from a resolved <c>ssh_config</c> (<c>UserKnownHostsFile</c>, <c>GlobalKnownHostsFile</c>,
    /// <c>StrictHostKeyChecking</c>, <c>HashKnownHosts</c>).</summary>
    public static KnownHostsVerifier FromConfig(SshHostConfig config) => FromConfig(config, ask: null);

    internal static KnownHostsVerifier FromConfig(SshHostConfig config, Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? ask)
    {
        ArgumentNullException.ThrowIfNull(config);
        var hash = config.Options.TryGetValue("hashknownhosts", out var value) && value.Count > 0
            && value[0].ToLowerInvariant() is "yes" or "true";
        // UpdateHostKeys "ask" needs a person to confirm each key; a library treats it like "no".
        var update = config.Options.TryGetValue("updatehostkeys", out var updateValue) && updateValue.Count > 0
            && updateValue[0].ToLowerInvariant() is "yes" or "true";
        return new KnownHostsVerifier(config.UserKnownHostsFiles, config.GlobalKnownHostsFiles)
        {
            Policy = config.StrictHostKeyChecking,
            HashNewEntries = hash,
            Ask = ask,
            UpdateHostKeys = update,
        };
    }

    /// <summary>
    /// Record new host keys a server announces after authentication, once it has proven it holds them (OpenSSH's <c>UpdateHostKeys</c>).
    /// This lets a server rotate its keys without users seeing "host key changed". Keys are only added, to the first user file;
    /// connections authenticated with a host certificate are not used for updates. Default false (<c>UpdateHostKeys yes</c> in
    /// ssh_config turns it on through <see cref="FromConfig(SshHostConfig)"/>).
    /// </summary>
    public bool UpdateHostKeys { get; init; }

    /// <summary>The announced keys that known_hosts does not yet hold for this host (the ones worth proving).</summary>
    internal async ValueTask<List<byte[]>> UnknownHostKeysAsync(string name, int port, IReadOnlyList<byte[]> announced, CancellationToken cancellationToken)
    {
        var files = new List<KnownHostsFile>();
        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            files.Add(await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false));
        }

        return [.. announced.Where(blob =>
        {
            var keyType = new Protocol.SshReader(blob).ReadUtf8String();
            return !files.Any(f => f.Check(name, port, keyType, blob) is KnownHostsCheckResult.Match or KnownHostsCheckResult.Revoked);
        })];
    }

    /// <summary>Appends keys the server has proven it holds.</summary>
    internal async ValueTask RecordProvenAsync(string name, int port, IEnumerable<byte[]> keys, CancellationToken cancellationToken)
    {
        if (_userFiles.Count == 0)
        {
            return;
        }

        foreach (var blob in keys)
        {
            var keyType = new Protocol.SshReader(blob).ReadUtf8String();
            await KnownHostsFile.AppendAsync(_userFiles[0], name, port, keyType, blob, HashNewEntries, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>The clock for certificate validity; replaceable in tests.</summary>
    internal TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <inheritdoc/>
    internal override async ValueTask<bool> PrefersCertificatesAsync(string? host, int port, string? hostKeyAlias, CancellationToken cancellationToken)
    {
        var lookup = hostKeyAlias is not null ? (hostKeyAlias, 22) : host is not null ? (host, port) : default((string, int)?);
        if (lookup is not var (name, lookupPort))
        {
            return false;
        }

        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            var file = await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false);
            if (file.FindCertificateAuthorities(name, lookupPort).Any())
            {
                return true;
            }
        }

        return false;
    }

    /// <inheritdoc/>
    public override async ValueTask<SshHostKeyVerdict> VerifyAsync(SshHostKeyContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.KnownHostsLookup is not var (name, port))
        {
            return SshHostKeyVerdict.Reject("There is no host name to look up in known_hosts; set SshClientOptions.HostKeyAlias when connecting over a stream.");
        }

        if (context.HostKey.Certificate is { } certificate
            && await VerifyCertificateAsync(certificate, name, port, cancellationToken).ConfigureAwait(false) is { } certificateVerdict)
        {
            return certificateVerdict;
        }

        // No trusted authority for the certificate: like ssh, check the certified key as a plain key.
        var key = context.HostKey;
        var revoked = false;
        var matched = false;
        var changed = false;
        var knownTypes = new List<string>();
        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            var file = await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false);
            switch (file.Check(name, port, key.KeyType, key.PublicKey.Span))
            {
                case KnownHostsCheckResult.Revoked:
                    revoked = true;
                    break;
                case KnownHostsCheckResult.Match:
                    matched = true;
                    break;
                case KnownHostsCheckResult.Changed:
                    changed = true;
                    break;
            }

            knownTypes.AddRange(file.Find(name, port).Where(e => e.Marker == KnownHostsMarker.None).Select(e => e.KeyType));
        }

        if (revoked)
        {
            return SshHostKeyVerdict.Reject($"The host key {key.Fingerprint} is marked @revoked in known_hosts.");
        }

        if (matched)
        {
            return SshHostKeyVerdict.Accept();
        }

        if (changed)
        {
            return Policy == StrictHostKeyChecking.No
                ? SshHostKeyVerdict.Accept()
                : SshHostKeyVerdict.Reject(
                    $"The {key.KeyType} host key has changed to {key.Fingerprint}. Someone could be intercepting the connection, or the host key was "
                    + "replaced; if the change is expected, remove the old entry from known_hosts.");
        }

        IReadOnlyList<string> otherTypes = [.. knownTypes.Distinct(StringComparer.Ordinal)];
        switch (Policy)
        {
            case StrictHostKeyChecking.Yes:
                return SshHostKeyVerdict.Reject($"The host key {key.Fingerprint} is not in known_hosts, and StrictHostKeyChecking is yes.");

            case StrictHostKeyChecking.AcceptNew when otherTypes.Count > 0:
                return SshHostKeyVerdict.Reject(
                    $"The server presented a {key.KeyType} key ({key.Fingerprint}), but known_hosts has only {string.Join(", ", otherTypes)} keys "
                    + "for it. AcceptNew does not record a new key type for a known host.");

            case StrictHostKeyChecking.Ask:
                if (Ask is null || !await Ask(new SshHostKeyPrompt(context, otherTypes), cancellationToken).ConfigureAwait(false))
                {
                    return SshHostKeyVerdict.Reject($"The host key {key.Fingerprint} is not in known_hosts and was not accepted.");
                }

                break;
        }

        return await RecordAsync(name, port, key, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Checks a host certificate against the <c>@cert-authority</c> lines for the host. Returns null when no listed authority signed it
    /// (the caller then falls back to the plain key), or the verdict: trusted, or refused with the reason.
    /// </summary>
    private async ValueTask<SshHostKeyVerdict?> VerifyCertificateAsync(SshCertificate certificate, string name, int port, CancellationToken cancellationToken)
    {
        var trusted = false;
        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            var file = await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false);
            foreach (var entry in file.Find(name, port))
            {
                var isAuthority = entry.PublicKey.Span.SequenceEqual(certificate.AuthorityKey.Span);
                if (entry.Marker == KnownHostsMarker.Revoked && (isAuthority || entry.PublicKey.Span.SequenceEqual(certificate.PublicKey.Span)))
                {
                    return SshHostKeyVerdict.Reject($"The host certificate's {(isAuthority ? "authority" : "key")} is marked @revoked in known_hosts.");
                }

                trusted |= entry.Marker == KnownHostsMarker.CertAuthority && isAuthority;
            }
        }

        if (!trusted)
        {
            return null;
        }

        return certificate.CheckForHost(name, Clock.GetUtcNow()) is { } problem
            ? SshHostKeyVerdict.Reject($"The host certificate (key id '{certificate.KeyId}', authority {certificate.AuthorityFingerprint}) is not acceptable: {problem}.")
            : SshHostKeyVerdict.Accept();
    }

    private async ValueTask<SshHostKeyVerdict> RecordAsync(string name, int port, SshHostKey key, CancellationToken cancellationToken)
    {
        if (_userFiles.Count > 0)
        {
            await KnownHostsFile.AppendAsync(_userFiles[0], name, port, key.KeyType, key.PublicKey, HashNewEntries, cancellationToken).ConfigureAwait(false);
        }

        return SshHostKeyVerdict.Accept();
    }
}
