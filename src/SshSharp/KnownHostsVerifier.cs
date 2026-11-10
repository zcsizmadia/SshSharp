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
/// <item>A different key of a recorded type ("the host key has changed") is refused, except with <see cref="StrictHostKeyChecking.No"/>,
/// which accepts it as ssh does: the connection goes on, but password and keyboard-interactive authentication, agent forwarding and
/// port forwarding are disabled on it, so a man in the middle gets no password and no access to this side.</item>
/// <item>An unknown key is refused (<see cref="StrictHostKeyChecking.Yes"/>), offered to <see cref="AskHostKey"/>, or recorded and trusted
/// (<see cref="StrictHostKeyChecking.AcceptNew"/>, <see cref="StrictHostKeyChecking.No"/>). AcceptNew refuses it when keys of other types
/// are already recorded for the host, so a man in the middle cannot get a weaker key type accepted silently.</item>
/// <item>A host certificate from an <c>@cert-authority</c> for the host is trusted while it is valid for the host. One that cannot be used
/// (expired, not yet valid, not issued for the name connected to, or signed with an algorithm <c>CASignatureAlgorithms</c> leaves out)
/// is logged as a warning, and its key is then checked as a plain key by the rules above, as ssh does; so is a certificate from no listed
/// authority. A certificate whose key or authority is <c>@revoked</c> is refused.</item>
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
    public Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? AskHostKey { get; init; }

    /// <summary>The user's <c>~/.ssh/known_hosts</c> and <c>known_hosts2</c>, plus the system-wide files, as <c>ssh</c> uses by default.</summary>
    public static KnownHostsVerifier ForCurrentUser(StrictHostKeyChecking policy = StrictHostKeyChecking.Ask)
    {
        var defaults = SshConfig.Parse(string.Empty).Resolve("localhost");
        return new KnownHostsVerifier(defaults.UserKnownHostsFiles, defaults.GlobalKnownHostsFiles) { Policy = policy };
    }

    /// <summary>The files, policy and hashing from a resolved <c>ssh_config</c> (<c>UserKnownHostsFile</c>, <c>GlobalKnownHostsFile</c>,
    /// <c>StrictHostKeyChecking</c>, <c>HashKnownHosts</c>), and the CA signature algorithms it trusts host certificates from
    /// (<c>CASignatureAlgorithms</c>, which can only narrow SshSharp's set; see <see cref="SshClientOptions.CASignatureAlgorithms"/>).</summary>
    /// <exception cref="SshException"><c>CASignatureAlgorithms</c> leaves no CA signature algorithm that SshSharp accepts
    /// (<see cref="SshFailureReason.ConnectFailed"/>).</exception>
    public static KnownHostsVerifier FromConfig(SshHostConfig config) => FromConfig(config, ask: null, confirmUpdate: null);

    internal static KnownHostsVerifier FromConfig(SshHostConfig config, Func<SshHostKeyPrompt, CancellationToken, ValueTask<bool>>? ask,
        Func<SshHostKeyUpdate, CancellationToken, ValueTask<bool>>? confirmUpdate, bool allowKnownHostsCommand = false)
    {
        ArgumentNullException.ThrowIfNull(config);
        // UpdateHostKeys "ask" needs someone to confirm: it is on only when there is a callback to ask.
        var update = config.UpdateHostKeys == Config.UpdateHostKeys.Yes || (config.UpdateHostKeys == Config.UpdateHostKeys.Ask && confirmUpdate is not null);
        return new KnownHostsVerifier(config.UserKnownHostsFiles, config.GlobalKnownHostsFiles)
        {
            Policy = config.StrictHostKeyChecking,
            HashNewEntries = config.HashKnownHosts,
            RevokedHostKeys = config.RevokedHostKeys,
            CASignatureAlgorithms = Protocol.AlgorithmPreferences.CASignaturesFromConfig(config.CASignatureAlgorithms),
            AskHostKey = ask,
            UpdateHostKeys = update,
            ConfirmHostKeyUpdate = config.UpdateHostKeys == Config.UpdateHostKeys.Ask ? confirmUpdate : null,
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
    /// its keys without users seeing "host key changed". Only the first user file changes, and connections authenticated with a host
    /// certificate are not used. As ssh, nothing changes when the connection's key was not already in a user file (a global file,
    /// <c>KnownHostsCommand</c>, or <see cref="StrictHostKeyChecking.AcceptNew"/> on first contact), when a wildcard,
    /// <c>@cert-authority</c> or <c>@revoked</c> line or one naming more than <c>host,address</c> applies to the host, or when a key
    /// involved is also recorded under another name.
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
                && !files.Any(f => f.Check(name, port, keyType, blob) is KnownHostsCheckResult.Match or KnownHostsCheckResult.Revoked)
                && !files.Any(f => RevokedWithoutPort(f, name, port, key => key.Span.SequenceEqual(blob)) is not null);
        })];
    }

    /// <summary>
    /// The <c>@revoked</c> line written without a port that revokes a key <paramref name="revokes"/> accepts, or null. Like ssh, such a
    /// line applies to the host on every port and wins over any other match. On port 22 the ordinary lookup already reads it, and an alias
    /// is always looked up on port 22, so this adds nothing there (ssh does not apply it to an alias either).
    /// </summary>
    private static KnownHostsEntry? RevokedWithoutPort(KnownHostsFile file, string name, int port, Func<ReadOnlyMemory<byte>, bool> revokes) =>
        port == 22 ? null : file.Find(name, 22).FirstOrDefault(e => e.Marker == KnownHostsMarker.Revoked && revokes(e.PublicKey));

    /// <summary>
    /// <see cref="RevokedWithoutPort"/> over the user's and the global files. Like ssh, not over the KnownHostsCommand output, which is
    /// produced for this host and port.
    /// </summary>
    private async ValueTask<KnownHostsEntry?> RevokedWithoutPortAsync(string name, int port, Func<ReadOnlyMemory<byte>, bool> revokes,
        CancellationToken cancellationToken)
    {
        if (port == 22)
        {
            return null;
        }

        foreach (var path in _userFiles.Concat(_globalFiles))
        {
            if (RevokedWithoutPort(await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false), name, port, revokes) is { } entry)
            {
                return entry;
            }
        }

        return null;
    }

    /// <summary>
    /// ssh's checks before an update (OpenSSH's <c>client_input_hostkeys</c>), over all the user files: the reason to leave them alone, or
    /// else this host's keys in the first user file that the server no longer announces (of key types this client understands).
    /// </summary>
    internal async ValueTask<(string? Skip, List<byte[]> Stale)> CheckHostKeyUpdateAsync(string name, int port, byte[] current, IReadOnlyList<byte[]> announced,
        CancellationToken cancellationToken)
    {
        var files = new List<KnownHostsFile>();
        foreach (var path in _userFiles)
        {
            files.Add(await KnownHostsFile.LoadAsync(path, cancellationToken).ConfigureAwait(false));
        }

        static bool Same(KnownHostsEntry entry, byte[] key) => entry.PublicKey.Span.SequenceEqual(key);

        // Only a connection whose key a user file holds may update it: not one trusted through a global file or KnownHostsCommand, and
        // not a changed key let through by StrictHostKeyChecking no (the server is then unauthenticated).
        if (!files.Any(f => f.Find(name, port).Any(e => e.Marker == KnownHostsMarker.None && Same(e, current))))
        {
            return ("the connection's host key is not in a user known_hosts file", []);
        }

        List<byte[]> stale = [];
        for (var i = 0; i < files.Count; i++)
        {
            foreach (var entry in files[i].Entries)
            {
                if (!entry.Matches(name, port))
                {
                    // The same key under another name or address: changing this host's lines would make the names disagree.
                    if (announced.Any(key => Same(entry, key)))
                    {
                        return ("an announced key is also recorded under another name", []);
                    }

                    continue;
                }

                // Lines ssh never writes, which may stand for other hosts too: the user wrote them, so they are not edited.
                if (entry.Marker != KnownHostsMarker.None)
                {
                    return ("a @cert-authority or @revoked line applies to the host", []);
                }

                if (IsComplexHostSpec(entry))
                {
                    return ("a wildcard line, or a line naming more than a host and its address, applies to the host", []);
                }

                if (i == 0 && !announced.Any(key => Same(entry, key)) && SshClient.IsSupportedKey(entry.PublicKey.ToArray()))
                {
                    stale.Add(entry.PublicKey.ToArray());
                }
            }
        }

        // Removing a key that another name still uses would leave the names of one host with different keys.
        if (stale.Any(key => files.Any(f => f.Entries.Any(e => !e.Matches(name, port) && Same(e, key)))))
        {
            return ("a key to remove is also recorded under another name", []);
        }

        return (null, stale);
    }

    /// <summary>A wildcard, or more host names than ssh writes (<c>host[,address]</c>); as OpenSSH's <c>hostspec_is_complex</c>.</summary>
    private static bool IsComplexHostSpec(KnownHostsEntry entry) =>
        !entry.IsHashed && (entry.HostPatterns.AsSpan().IndexOfAny('*', '?') >= 0 || entry.HostPatterns.AsSpan().Count(',') > 1);

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

    /// <summary>
    /// The CA signature algorithms of the configuration the verifier was made from (<see cref="FromConfig(SshHostConfig)"/>), or null. A
    /// host certificate is trusted only when its authority signed it with one this list and the connection's
    /// (<see cref="SshClientOptions.CASignatureAlgorithms"/>) both allow: each can only narrow what the other allows.
    /// </summary>
    internal IReadOnlyList<string>? CASignatureAlgorithms { get; init; }

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

        string? unusable = null;
        if (context.HostKey.Certificate is { } certificate)
        {
            var (certificateVerdict, problem) = await VerifyCertificateAsync(certificate, context, name, port, cancellationToken).ConfigureAwait(false);
            if (certificateVerdict is { } verdict)
            {
                return verdict;
            }

            if (problem is not null)
            {
                // As ssh's check_host_key ("No matching CA found. Retry with plain key"): a trusted authority's certificate that cannot be
                // used (expired, not issued for this name, or signed with a CA signature algorithm not allowed) is not a refusal, only a
                // certificate that proves nothing. The key it certifies is checked as a plain key below, and the problem is said when that
                // refuses it too.
                SshLog.HostCertificateUnusable(context.Logger, context.HostKey.Fingerprint, certificate.AuthorityFingerprint, problem);
                unusable = $"The host certificate (key id '{certificate.KeyId}', authority {certificate.AuthorityFingerprint}) could not be used either: {problem}.";
            }
        }

        var plain = await VerifyPlainKeyAsync(context, name, port, cancellationToken).ConfigureAwait(false);
        return plain.IsAccepted || unusable is null ? plain : SshHostKeyVerdict.Reject($"{plain.Reason} {unusable}");
    }

    /// <summary>
    /// Checks the key as a plain key, with the <c>StrictHostKeyChecking</c> policy: a host key, or the key a host certificate certifies
    /// when no listed authority signed the certificate or the certificate cannot be used. Like ssh, that key (never the certificate) is
    /// what an accepted unknown key records.
    /// </summary>
    private async ValueTask<SshHostKeyVerdict> VerifyPlainKeyAsync(SshHostKeyContext context, string name, int port, CancellationToken cancellationToken)
    {
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

        revoked = revoked || await RevokedWithoutPortAsync(name, port, k => k.Span.SequenceEqual(key.PublicKey.Span), cancellationToken).ConfigureAwait(false) is not null;
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
            // As ssh, No lets the connection go on, but the key proves nothing about the server: the connection must not send it
            // anything a man in the middle could use (see SshHostKeyVerdict.IsUntrusted).
            return Policy == StrictHostKeyChecking.No
                ? SshHostKeyVerdict.AcceptUntrusted()
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
                if (AskHostKey is null || !await AskHostKey(new SshHostKeyPrompt(context, otherTypes), cancellationToken).ConfigureAwait(false))
                {
                    return SshHostKeyVerdict.Reject($"The host key {key.Fingerprint} is not in known_hosts and was not accepted.");
                }

                break;
        }

        return await RecordAsync(name, port, key, confirmed: Policy == StrictHostKeyChecking.Ask, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Checks a host certificate against the <c>@cert-authority</c> and <c>@revoked</c> lines for the host. Returns the verdict when there
    /// is one: trusted, or refused because the certificate's key or authority is revoked. Otherwise the caller falls back to the plain key,
    /// as ssh does: when no listed authority signed the certificate, or when one did but the certificate cannot be used (the problem, which
    /// does not name the host). As ssh's <c>sshkey_cert_check_host</c>, a CA signature algorithm that is not allowed is such a problem.
    /// </summary>
    private async ValueTask<(SshHostKeyVerdict? Verdict, string? Problem)> VerifyCertificateAsync(SshCertificate certificate, SshHostKeyContext context,
        string name, int port, CancellationToken cancellationToken)
    {
        if (await RevokedWithoutPortAsync(name, port,
            k => k.Span.SequenceEqual(certificate.AuthorityKey.Span) || k.Span.SequenceEqual(certificate.PublicKey.Span), cancellationToken).ConfigureAwait(false) is { } revokedEverywhere)
        {
            var isAuthority = revokedEverywhere.PublicKey.Span.SequenceEqual(certificate.AuthorityKey.Span);
            return (SshHostKeyVerdict.Reject($"The host certificate's {(isAuthority ? "authority" : "key")} is marked @revoked in known_hosts."), null);
        }

        var trusted = false;
        await foreach (var file in SourcesAsync(name, port, "HOSTNAME", context.HostKey, asCertificate: true, cancellationToken).ConfigureAwait(false))
        {
            foreach (var entry in file.Find(name, port))
            {
                var isAuthority = entry.PublicKey.Span.SequenceEqual(certificate.AuthorityKey.Span);
                if (entry.Marker == KnownHostsMarker.Revoked && (isAuthority || entry.PublicKey.Span.SequenceEqual(certificate.PublicKey.Span)))
                {
                    return (SshHostKeyVerdict.Reject($"The host certificate's {(isAuthority ? "authority" : "key")} is marked @revoked in known_hosts."), null);
                }

                trusted |= entry.Marker == KnownHostsMarker.CertAuthority && isAuthority;
            }
        }

        if (!trusted)
        {
            return (null, null);
        }

        IReadOnlyList<string> allowed = CASignatureAlgorithms is { } configured
            ? [.. context.CASignatureAlgorithms.Where(configured.Contains)]
            : context.CASignatureAlgorithms;
        return certificate.CheckForHost(name, Clock.GetUtcNow(), allowed) is { } problem ? (null, problem) : (SshHostKeyVerdict.Accept(), null);
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
            return SshHostKeyVerdict.Reject($"Error checking host key {key.KeyType} {key.Fingerprint} in the revoked keys file (RevokedHostKeys): {RevokedFileProblem(ex)}.");
        }

        // The path stays out of the message, as with known_hosts: it comes from ssh_config, often with %h or %u expanded into it, or the
        // home directory, which holds the user's name.
        return list.IsRevoked(key.PublicKey.Span, key.Certificate)
            ? SshHostKeyVerdict.Reject($"Host key {key.KeyType} {key.Fingerprint} revoked by file (RevokedHostKeys).")
            : null;
    }

    /// <summary>
    /// Why the revoked keys file could not be checked, without its path: a system error's message quotes it, so only the kind of error
    /// is given. The list's own errors (a malformed KRL, a file too large) say nothing of the path, and are given as they are.
    /// </summary>
    private static string RevokedFileProblem(Exception ex) => ex switch
    {
        FormatException => ex.Message.TrimEnd('.'),
        IOException { Message: RevokedKeyList.TooLargeMessage } => ex.Message.TrimEnd('.'),
        FileNotFoundException or DirectoryNotFoundException => "the file does not exist",
        UnauthorizedAccessException => "access to the file is denied",
        _ => ex.GetType().Name,
    };

    private async ValueTask<SshHostKeyVerdict> RecordAsync(string name, int port, SshHostKey key, bool confirmed, CancellationToken cancellationToken)
    {
        if (!KnownHostsEntry.IsLiteralHost(name))
        {
            // Recorded as is, the name would be a pattern (or extra hosts or lines) trusting this key for other hosts.
            return SshHostKeyVerdict.Reject("The host name cannot be recorded in known_hosts (it contains white space, ',', '*', '?' or '!', or starts with '@' or '#').");
        }

        if (_userFiles.Count > 0)
        {
            await KnownHostsFile.AppendAsync(_userFiles[0], name, port, key.KeyType, key.PublicKey, HashNewEntries, cancellationToken).ConfigureAwait(false);
        }

        return SshHostKeyVerdict.Accept() with { Learned = !confirmed };
    }
}
