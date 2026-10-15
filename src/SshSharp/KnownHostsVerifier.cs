using SshSharp.Config;

namespace SshSharp;

/// <summary>A change to known_hosts that <see cref="KnownHostsVerifier.UpdateHostKeys"/> is about to make, for <see cref="KnownHostsVerifier.ConfirmHostKeyUpdate"/>.</summary>
public sealed class SshHostKeyUpdate
{
    internal SshHostKeyUpdate(string host, int port, IReadOnlyList<string> added, IReadOnlyList<string> removed)
    {
        Host = host;
        Port = port;
        Added = added;
        Removed = removed;
    }

    /// <summary>The host (or <c>HostKeyAlias</c>) the keys are recorded under.</summary>
    public string Host { get; }

    /// <summary>The port the keys are recorded for.</summary>
    public int Port { get; }

    /// <summary>The keys to add (type and SHA-256 fingerprint, as <c>ssh-keygen -l</c> prints them), each proven by the server.</summary>
    public IReadOnlyList<string> Added { get; }

    /// <summary>The keys to remove, which the server no longer announces.</summary>
    public IReadOnlyList<string> Removed { get; }
}

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
/// New keys are appended to the first user file. The file is rewritten only by <see cref="UpdateHostKeys"/>, to remove keys the server no longer announces.
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
    /// A file of host keys never to accept, as <c>RevokedHostKeys</c> in ssh_config: an OpenSSH Key Revocation List (<c>ssh-keygen -k</c>),
    /// or a list of public keys, one per line. A revoked key is refused whatever known_hosts says, and so is a host certificate whose
    /// key, authority, serial number or key id is revoked. As with ssh, a file that cannot be read or is a malformed KRL refuses every
    /// host key: a revocation list that cannot be checked must not let a revoked key through. A KRL's signatures are not verified.
    /// </summary>
    public string? RevokedHostKeys { get; init; }

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
    public static KnownHostsVerifier FromConfig(SshHostConfig config) => FromConfig(config, ask: null, confirmUpdate: null);

    internal static KnownHostsVerifier FromConfig(SshHostConfig config, Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? ask,
        Func<SshHostKeyUpdate, CancellationToken, ValueTask<bool>>? confirmUpdate, bool allowKnownHostsCommand = false)
    {
        ArgumentNullException.ThrowIfNull(config);
        var hash = config.Options.TryGetValue("hashknownhosts", out var value) && value.Count > 0
            && value[0].ToLowerInvariant() is "yes" or "true";

        // UpdateHostKeys "ask" needs someone to confirm: it is on only when there is a callback to ask.
        var setting = config.Options.TryGetValue("updatehostkeys", out var updateValue) && updateValue.Count > 0 ? updateValue[0].ToLowerInvariant() : "no";
        var update = setting is "yes" or "true" || (setting == "ask" && confirmUpdate is not null);
        return new KnownHostsVerifier(config.UserKnownHostsFiles, config.GlobalKnownHostsFiles)
        {
            Policy = config.StrictHostKeyChecking,
            HashNewEntries = hash,
            RevokedHostKeys = config.RevokedHostKeys,
            Ask = ask,
            UpdateHostKeys = update,
            ConfirmHostKeyUpdate = setting == "ask" ? confirmUpdate : null,
            Command = allowKnownHostsCommand && config.KnownHostsCommand is { } command && config.Tokens is { } tokens
                ? (name, port, reason, key, asCertificate, ct) => KnownHostsCommandRunner.RunAsync(command, tokens, name, port, reason, key, asCertificate, ct)
                : null,
        };
    }

    /// <summary>
    /// <c>KnownHostsCommand</c> (only through <see cref="SshConfigConnectOptions.AllowKnownHostsCommand"/>): host keys from a command,
    /// read after the files, for the name and port looked up, the reason (<c>HOSTNAME</c> or <c>ORDER</c>) and the presented key: as its
    /// certificate when the lookup is for the certificate (<c>asCertificate</c>), as ssh passes the certificate while checking it and the
    /// plain key when it falls back to that.
    /// </summary>
    internal Func<string, int, string, SshHostKey?, bool, CancellationToken, Task<KnownHostsFile>>? Command { get; init; }

    /// <summary>The known_hosts sources in order: the user's files, the global files, then the command's output.</summary>
    private async IAsyncEnumerable<KnownHostsFile> SourcesAsync(string name, int port, string reason, SshHostKey? key, bool asCertificate,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            yield return await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false);
        }

        if (Command is { } command)
        {
            yield return await command(name, port, reason, key, asCertificate, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Keep known_hosts in step with the host keys a server announces after authentication (OpenSSH's <c>UpdateHostKeys</c>): new keys are
    /// added once the server has proven it holds them, and this host's keys it no longer announces are removed. This lets a server rotate
    /// its keys without users seeing "host key changed". Only the first user file changes, only lines for exactly this host (not wildcard
    /// lines, not <c>@cert-authority</c> or <c>@revoked</c> ones), and connections authenticated with a host certificate are not used.
    /// Default false (<c>UpdateHostKeys yes</c> in ssh_config turns it on through <see cref="FromConfig(SshHostConfig)"/>; see
    /// <see cref="ConfirmHostKeyUpdate"/> for <c>ask</c>).
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

        // Like ssh, keys in the RevokedHostKeys file are never learned (and an unreadable file learns none).
        RevokedKeyList? revokedList = null;
        if (RevokedHostKeys is { } revokedPath)
        {
            try
            {
                revokedList = await RevokedKeyList.LoadAsync(revokedPath, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
            {
                return [];
            }
        }

        return [.. announced.Where(blob =>
        {
            var keyType = new Protocol.SshReader(blob).ReadUtf8String();
            return revokedList?.IsRevoked(blob, certificate: null) != true
                && !files.Any(f => f.Check(name, port, keyType, blob) is KnownHostsCheckResult.Match or KnownHostsCheckResult.Revoked);
        })];
    }

    /// <summary>
    /// This host's keys in the first user file that the server no longer announces: plain entries for exactly this host (lines matched
    /// only through a wildcard, global files and marked lines are left alone), of key types this client understands.
    /// </summary>
    internal async ValueTask<List<byte[]>> StaleHostKeysAsync(string name, int port, IReadOnlyList<byte[]> announced, CancellationToken cancellationToken)
    {
        if (_userFiles.Count == 0)
        {
            return [];
        }

        var file = await KnownHostsFile.LoadAsync(_userFiles[0], cancellationToken).ConfigureAwait(false);
        var host = KnownHostsEntry.FormatHost(name, port);
        return [.. file.Find(name, port)
            .Where(e => e.Marker == KnownHostsMarker.None && (e.IsHashed || e.HostPatterns.Split(',').Contains(host, StringComparer.OrdinalIgnoreCase)))
            .Where(e => SshClient.IsSupportedKey(e.PublicKey.ToArray()) && !announced.Any(a => a.AsSpan().SequenceEqual(e.PublicKey.Span)))
            .Select(e => e.PublicKey.ToArray())];
    }

    /// <summary>Appends keys the server has proven it holds, then removes the ones it no longer announces.</summary>
    internal async ValueTask ApplyHostKeyUpdateAsync(string name, int port, IReadOnlyList<byte[]> added, IReadOnlyList<byte[]> removed, CancellationToken cancellationToken)
    {
        if (_userFiles.Count == 0)
        {
            return;
        }

        foreach (var blob in added)
        {
            var keyType = new Protocol.SshReader(blob).ReadUtf8String();
            await KnownHostsFile.AppendAsync(_userFiles[0], name, port, keyType, blob, HashNewEntries, cancellationToken).ConfigureAwait(false);
        }

        if (removed.Count > 0)
        {
            var file = await KnownHostsFile.LoadAsync(_userFiles[0], cancellationToken).ConfigureAwait(false);
            if (file.Remove(name, port, e => removed.Any(r => r.AsSpan().SequenceEqual(e.PublicKey.Span))) > 0)
            {
                await file.SaveAsync(_userFiles[0], cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Asked before known_hosts is changed by <see cref="UpdateHostKeys"/> (ssh's <c>UpdateHostKeys ask</c>): return true to apply the
    /// update. Without it, updates are applied without asking (<c>UpdateHostKeys yes</c>).
    /// </summary>
    public Func<SshHostKeyUpdate, CancellationToken, ValueTask<bool>>? ConfirmHostKeyUpdate { get; init; }

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

        await foreach (var file in SourcesAsync(name, lookupPort, "ORDER", null, asCertificate: false, cancellationToken).ConfigureAwait(false))
        {
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

        // As ssh's verify_host_key: the revocation file first, before anything that could trust the key.
        if (RevokedHostKeys is { } revokedPath && await CheckRevokedAsync(revokedPath, context.HostKey, cancellationToken).ConfigureAwait(false) is { } refusal)
        {
            return refusal;
        }

        if (context.HostKey.Certificate is { } certificate
            && await VerifyCertificateAsync(certificate, context.HostKey, name, port, cancellationToken).ConfigureAwait(false) is { } certificateVerdict)
        {
            return certificateVerdict;
        }

        // No trusted authority for the certificate: like ssh, check the certified key as a plain key.
        var key = context.HostKey;
        var revoked = false;
        var matched = false;
        var changed = false;
        var knownTypes = new List<string>();
        await foreach (var file in SourcesAsync(name, port, "HOSTNAME", key, asCertificate: false, cancellationToken).ConfigureAwait(false))
        {
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
    private async ValueTask<SshHostKeyVerdict?> VerifyCertificateAsync(SshCertificate certificate, SshHostKey presented, string name, int port,
        CancellationToken cancellationToken)
    {
        var trusted = false;
        await foreach (var file in SourcesAsync(name, port, "HOSTNAME", presented, asCertificate: true, cancellationToken).ConfigureAwait(false))
        {
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

    /// <summary>
    /// The refusal when <paramref name="key"/> is revoked by the file, or when the file cannot be checked (ssh: "Error checking host key ...
    /// in revoked keys file"); null when the key is not revoked.
    /// </summary>
    private static async ValueTask<SshHostKeyVerdict?> CheckRevokedAsync(string path, SshHostKey key, CancellationToken cancellationToken)
    {
        RevokedKeyList list;
        try
        {
            list = await RevokedKeyList.LoadAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return SshHostKeyVerdict.Reject($"Error checking host key {key.KeyType} {key.Fingerprint} in revoked keys file {path}: {ex.Message}");
        }

        return list.IsRevoked(key.PublicKey.Span, key.Certificate)
            ? SshHostKeyVerdict.Reject($"Host key {key.KeyType} {key.Fingerprint} revoked by file {path}.")
            : null;
    }

    private async ValueTask<SshHostKeyVerdict> RecordAsync(string name, int port, SshHostKey key, CancellationToken cancellationToken)
    {
        if (!KnownHostsEntry.IsLiteralHost(name))
        {
            // Recorded as is, the name would be a pattern (or extra hosts or lines) trusting this key for other hosts.
            return SshHostKeyVerdict.Reject("The host name cannot be recorded in known_hosts (it contains white space, ',', '*', '?' or '!').");
        }

        if (_userFiles.Count > 0)
        {
            await KnownHostsFile.AppendAsync(_userFiles[0], name, port, key.KeyType, key.PublicKey, HashNewEntries, cancellationToken).ConfigureAwait(false);
        }

        return SshHostKeyVerdict.Accept();
    }
}
