using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshSharp.Config;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>The names registered with <c>AddSshClient</c>, so an unknown name fails clearly instead of connecting with empty settings.</summary>
internal sealed class SshEndpointRegistry
{
    private readonly HashSet<string> _names = new(StringComparer.Ordinal);

    public void Add(string name)
    {
        lock (_names)
        {
            _names.Add(name);
        }
    }

    public bool Contains(string name)
    {
        lock (_names)
        {
            return _names.Contains(name);
        }
    }

    public void ThrowIfUnknown(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (!Contains(name))
        {
            throw new InvalidOperationException($"No SSH endpoint is registered as '{name}': call services.AddSshClient(\"{name}\").");
        }
    }
}

internal sealed partial class SshClientFactory(
    IServiceProvider services, SshEndpointRegistry registry, IOptionsMonitor<SshEndpointOptions> endpoints, ILoggerFactory? loggerFactory = null)
    : ISshClientFactory
{
    private readonly ILogger? _logger = loggerFactory?.CreateLogger("SshSharp");

    public SshEndpointRegistry Registry => registry;

    private IServiceProvider Services => services;

    /// <summary>The endpoint's settings, validated (an invalid one throws <see cref="OptionsValidationException"/>).</summary>
    public SshEndpointOptions Endpoint(string name)
    {
        registry.ThrowIfUnknown(name);
        return endpoints.Get(name);
    }

    public async Task<SshClient> ConnectAsync(string name, CancellationToken cancellationToken = default)
    {
        var endpoint = Endpoint(name);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(endpoint.ConnectTimeout);
        try
        {
            return endpoint.ConfigAlias is { Length: > 0 } alias
                ? await SshClient.ConnectAsync(alias, new SshConfigConnectOptions
                {
                    Password = endpoint.Password,
                    Logger = _logger,
                    AddressFamily = endpoint.AddressFamily,
                    Compression = endpoint.Compression,
                    // Null leaves the agent to ssh_config, as before UseAgent existed; true prefers an agent the application registered.
                    UseAgent = endpoint.UseAgent ?? true,
                    Agent = endpoint.UseAgent == true ? services.GetService<SshAgent>() : null,
                }, timeout.Token).ConfigureAwait(false)
                : await ConnectDirectAsync(name, endpoint, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"Connecting to the SSH endpoint '{name}' took longer than {endpoint.ConnectTimeout}.", ex);
        }
    }

    private async Task<SshClient> ConnectDirectAsync(string name, SshEndpointOptions endpoint, CancellationToken cancellationToken)
    {
        // Every key loaded for this connection, the jump hosts' included, disposed once it has authenticated.
        var owned = new List<SshPrivateKey>();
        var agent = new AgentKeys(this);
        try
        {
            var keys = await LoadKeysAsync(endpoint.PrivateKeyFiles, endpoint.PrivateKeyPassphrase, endpoint.PrivateKeys,
                endpoint.UseAgent == true ? agent : null, owned, cancellationToken).ConfigureAwait(false);
            var jumpHosts = new List<SshJumpHost>(endpoint.JumpHosts.Count);
            foreach (var hop in endpoint.JumpHosts)
            {
                jumpHosts.Add(await JumpHostAsync(endpoint, hop, agent, owned, cancellationToken).ConfigureAwait(false));
            }

            var options = new SshClientOptions
            {
                UserName = endpoint.UserName!,
                Password = endpoint.Password,
                PrivateKeys = keys,
                HostKeyVerifier = HostKeyVerifier(endpoint.HostKeyFingerprints, endpoint.KnownHostsFiles, endpoint.AcceptNewHostKeys),
                Proxy = endpoint.Proxy is { Length: > 0 } proxy ? SshEndpointOptionsValidator.ParseProxy(proxy) : null,
                JumpHosts = jumpHosts,
                KeepAliveInterval = endpoint.KeepAliveInterval,
                ConnectTimeout = endpoint.ConnectTimeout,
                AddressFamily = endpoint.AddressFamily ?? SshAddressFamily.Any,
                Compression = endpoint.Compression ?? false,
                Logger = _logger,
            };
            if (endpoint.ConfigureClientOptions is { } configure)
            {
                options = configure(services, options);
            }

            try
            {
                return await SshClient.ConnectAsync(endpoint.Host!, endpoint.Port, options, cancellationToken).ConfigureAwait(false);
            }
            catch (SshException ex) when (ex is { Reason: SshFailureReason.Timeout, InnerException: TimeoutException })
            {
                // The client's ConnectTimeout passed (perhaps one ConfigureClientOptions shortened): reported as this endpoint's timeout, as
                // the factory's own limit is. A proxy's handshake timeout has no TimeoutException inside and stays an SshException.
                throw new TimeoutException($"Connecting to the SSH endpoint '{name}' took longer than {options.ConnectTimeout}.", ex);
            }
        }
        finally
        {
            // Keys are needed only to authenticate; the connected client does not keep them.
            foreach (var key in owned)
            {
                key.Dispose();
            }
        }
    }

    /// <summary>
    /// One of <see cref="SshEndpointOptions.JumpHosts"/>, with only its own credentials. Its host key is checked against its own pins or
    /// files, or else against the endpoint's known_hosts files (validation has rejected a hop without either behind a pinned endpoint).
    /// </summary>
    private async Task<SshJumpHost> JumpHostAsync(SshEndpointOptions endpoint, SshEndpointJumpHost hop, AgentKeys agent, List<SshPrivateKey> owned,
        CancellationToken cancellationToken)
    {
        var keys = await LoadKeysAsync(hop.PrivateKeyFiles, hop.PrivateKeyPassphrase, hop.PrivateKeys, hop.UseAgent ? agent : null, owned,
            cancellationToken).ConfigureAwait(false);
        var ownHostKeys = hop.HostKeyFingerprints.Count > 0 || hop.KnownHostsFiles.Count > 0;
        return new SshJumpHost(hop.Host!.Trim(), hop.Port, new SshClientOptions
        {
            UserName = hop.UserName!,
            Password = hop.Password,
            PrivateKeys = keys,
            HostKeyVerifier = ownHostKeys
                ? HostKeyVerifier(hop.HostKeyFingerprints, hop.KnownHostsFiles, hop.AcceptNewHostKeys)
                : HostKeyVerifier([], endpoint.KnownHostsFiles, hop.AcceptNewHostKeys || endpoint.AcceptNewHostKeys),
            KeepAliveInterval = endpoint.KeepAliveInterval,
            ConnectTimeout = endpoint.ConnectTimeout,
            Logger = _logger,
        });
    }

    /// <summary>Key files, then keys given as values, then (when <paramref name="agent"/> is given) the agent's keys.</summary>
    private static async Task<List<SshPrivateKey>> LoadKeysAsync(IList<string> files, string? passphrase, IList<SshEndpointPrivateKey> values,
        AgentKeys? agent, List<SshPrivateKey> owned, CancellationToken cancellationToken)
    {
        var keys = new List<SshPrivateKey>();
        foreach (var file in files)
        {
            var key = await SshPrivateKey.LoadAsync(ExpandHome(file), passphrase, cancellationToken).ConfigureAwait(false);
            owned.Add(key);
            keys.Add(key);
        }

        // Keys given as values come after the files. Validation has parsed each already, so a failure here is not expected; they are
        // read again for each connection, as the files are, so no decrypted key outlives its authentication.
        foreach (var entry in values)
        {
            var key = SshPrivateKey.Parse(entry.Key!, entry.Passphrase);
            owned.Add(key);
            keys.Add(key);
        }

        if (agent is not null)
        {
            keys.AddRange(await agent.GetAsync(owned, cancellationToken).ConfigureAwait(false));
        }

        return keys;
    }

    /// <summary>
    /// Pinned keys when there are any (validation has rejected known_hosts files and accept-new alongside them), otherwise the known_hosts
    /// files (default <c>~/.ssh/known_hosts</c>).
    /// </summary>
    private static SshHostKeyVerifier HostKeyVerifier(IList<string> pins, IList<string> knownHostsFiles, bool acceptNew)
    {
        if (pins.Count > 0)
        {
            return SshHostKeyVerifier.Pinned([.. pins.Select(p => SshEndpointOptionsValidator.ParsePin(p, out _)!)]);
        }

        string[] knownHosts = knownHostsFiles.Count > 0
            ? [.. knownHostsFiles.Select(ExpandHome)]
            : [Path.Combine(Home(), ".ssh", "known_hosts")];
        return new KnownHostsVerifier(knownHosts)
        {
            Policy = acceptNew ? StrictHostKeyChecking.AcceptNew : StrictHostKeyChecking.Yes,
        };
    }

    private static string Home() => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string ExpandHome(string path) =>
        path == "~" ? Home() : path.StartsWith("~/", StringComparison.Ordinal) ? Path.Combine(Home(), path[2..]) : path;

    [LoggerMessage(EventId = 1001, Level = LogLevel.Debug, Message = "The SSH agent is not available ({Reason}); connecting without its keys")]
    private static partial void AgentUnavailable(ILogger logger, SshFailureReason reason);

    /// <summary>
    /// The agent's keys, listed once per connection however many hops use them: the agent registered in the container, or else the
    /// environment's. An agent that is not running gives none, as with ssh.
    /// </summary>
    private sealed class AgentKeys(SshClientFactory factory)
    {
        private IReadOnlyList<SshPrivateKey>? _keys;

        public async Task<IReadOnlyList<SshPrivateKey>> GetAsync(List<SshPrivateKey> owned, CancellationToken cancellationToken)
        {
            if (_keys is not null)
            {
                return _keys;
            }

            var agent = factory.Services.GetService<SshAgent>() ?? await SshAgent.FromEnvironmentAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _keys = agent is null ? [] : await agent.GetKeysAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SshException ex) when (ex.Reason == SshFailureReason.AgentFailed)
            {
                // Only the reason: the agent's message can name its socket, which can hold the user's name.
                if (factory._logger is { } logger)
                {
                    AgentUnavailable(logger, ex.Reason);
                }

                _keys = [];
            }

            owned.AddRange(_keys);
            return _keys;
        }
    }
}

/// <summary>Checks an endpoint's settings when they are first read (or at start, with <c>ValidateOnStart</c>).</summary>
internal sealed class SshEndpointOptionsValidator(SshEndpointRegistry registry) : IValidateOptions<SshEndpointOptions>
{
    public ValidateOptionsResult Validate(string? name, SshEndpointOptions options)
    {
        if (name is null || !registry.Contains(name))
        {
            return ValidateOptionsResult.Skip;
        }

        var failures = new List<string>();
        if (!string.IsNullOrEmpty(options.ConfigAlias))
        {
            // ssh_config decides keys, host keys, proxies and jump hosts for an alias: one set here would otherwise be silently unused.
            string[] unused =
            [
                .. options.HostKeyFingerprints.Count > 0 ? [nameof(options.HostKeyFingerprints)] : Array.Empty<string>(),
                .. options.PrivateKeys.Count > 0 ? [nameof(options.PrivateKeys)] : Array.Empty<string>(),
                .. !string.IsNullOrEmpty(options.Proxy) ? [nameof(options.Proxy)] : Array.Empty<string>(),
                .. options.JumpHosts.Count > 0 ? [nameof(options.JumpHosts)] : Array.Empty<string>(),
            ];
            if (unused.Length > 0)
            {
                failures.Add($"SSH endpoint '{name}': {string.Join(", ", unused)} cannot be combined with ConfigAlias, whose ssh_config decides them.");
            }
        }
        else
        {
            ValidateServer(failures, $"SSH endpoint '{name}'", options.Host, options.UserName, options.Port, "set Host, or ConfigAlias to connect through ssh_config.");
        }

        if (options.ConnectTimeout <= TimeSpan.Zero)
        {
            failures.Add($"SSH endpoint '{name}': ConnectTimeout must be positive.");
        }

        if (options.ReconnectDelay <= TimeSpan.Zero || options.MaxReconnectDelay < options.ReconnectDelay)
        {
            failures.Add($"SSH endpoint '{name}': ReconnectDelay must be positive, and MaxReconnectDelay at least as long.");
        }

        ValidateHostKeys(failures, $"SSH endpoint '{name}'", options.HostKeyFingerprints, options.KnownHostsFiles, options.AcceptNewHostKeys);
        ValidatePrivateKeys(failures, $"SSH endpoint '{name}'", options.PrivateKeys);
        if (!string.IsNullOrEmpty(options.Proxy) && ParseProxy(options.Proxy) is null)
        {
            // The value is not shown: it may hold the proxy's password.
            failures.Add($"SSH endpoint '{name}': Proxy is not a proxy URI (http, socks5, socks5h, socks4 or socks4a, then a host and an " +
                "optional port and user, as in http://proxy.example.com:3128).");
        }

        ValidateJumpHosts(failures, name, options);
        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }

    /// <summary>The proxy a <see cref="SshEndpointOptions.Proxy"/> URI names, or null when it does not name one.</summary>
    internal static SshProxy? ParseProxy(string value)
    {
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            return null;
        }

        try
        {
            return SshProxy.FromUri(uri);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <paramref name="value"/> is an OpenSSH SHA-256 fingerprint: <c>SHA256:</c> and the hash in unpadded base64, written as
    /// OpenSSH writes it (so that the ordinal comparison <see cref="SshHostKeyVerifier.Pinned(string[])"/> makes can match).
    /// </summary>
    internal static bool IsSha256Fingerprint(string value)
    {
        const string Prefix = "SHA256:";
        if (!value.StartsWith(Prefix, StringComparison.Ordinal) || value.Length != Prefix.Length + 43)
        {
            return false;
        }

        Span<byte> hash = stackalloc byte[33];
        return Convert.TryFromBase64String(value[Prefix.Length..] + "=", hash, out var written) && written == 32
            && string.Equals(Convert.ToBase64String(hash[..32]).TrimEnd('='), value[Prefix.Length..], StringComparison.Ordinal);
    }

    /// <summary>
    /// The SHA-256 fingerprint a <see cref="SshEndpointOptions.HostKeyFingerprints"/> entry pins: the entry itself when it is one, or the
    /// fingerprint of the key in a public key line or a known_hosts line. Null when it is none of them, with the reason in
    /// <paramref name="problem"/> (never the entry's text: a key line's comment is often a user and host name).
    /// </summary>
    internal static string? ParsePin(string? value, out string? problem)
    {
        const string Unreadable = "is not an OpenSSH SHA-256 fingerprint ('SHA256:' and 43 base64 characters, as ssh-keygen -lf prints), a " +
            "public key line (as a .pub file holds) or a known_hosts line";
        problem = null;
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            problem = Unreadable;
            return null;
        }

        if (IsSha256Fingerprint(text))
        {
            return text;
        }

        if (text.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            problem = "holds more than one line; give each key as an entry of its own";
            return null;
        }

        if (SshPublicKey.TryParse(text, out var key))
        {
            return key.Fingerprint;
        }

        if (text.StartsWith('@'))
        {
            // A certificate authority or a revoked key is not a key to trust: pinning either would turn its meaning around.
            problem = "is a marked known_hosts line (@cert-authority or @revoked), which cannot be pinned";
            return null;
        }

        var file = KnownHostsFile.Parse(text);
        if (file.Entries is [{ Marker: KnownHostsMarker.None } entry] && file.InvalidLineCount == 0)
        {
            try
            {
                return entry.GetPublicKey().Fingerprint;
            }
            catch (FormatException)
            {
                // Not a key of a supported type: reported below as any other unreadable entry.
            }
        }

        problem = Unreadable;
        return null;
    }

    private static void ValidateServer(List<string> failures, string subject, string? host, string? userName, int port, string missingHost)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            failures.Add($"{subject}: {missingHost}");
        }

        if (string.IsNullOrEmpty(userName))
        {
            failures.Add($"{subject}: set UserName.");
        }

        if (port is < 1 or > 65535)
        {
            failures.Add($"{subject}: Port must be between 1 and 65535.");
        }
    }

    private static void ValidateHostKeys(List<string> failures, string subject, IList<string> pins, IList<string> knownHostsFiles, bool acceptNew)
    {
        if (pins.Count == 0)
        {
            return;
        }

        for (var i = 0; i < pins.Count; i++)
        {
            if (ParsePin(pins[i], out var problem) is null)
            {
                failures.Add($"{subject}: HostKeyFingerprints[{i}] {problem}.");
            }
        }

        // Pinned keys replace known_hosts. Accepting a key either list allows would widen what is trusted to the larger of the two,
        // requiring both would bring back the file that pinning removes, and ignoring one silently would hide a mistake: so neither mixes.
        if (knownHostsFiles.Count > 0)
        {
            failures.Add($"{subject}: set HostKeyFingerprints or KnownHostsFiles, not both; pinned fingerprints replace known_hosts.");
        }

        if (acceptNew)
        {
            failures.Add($"{subject}: AcceptNewHostKeys cannot be combined with HostKeyFingerprints, which trust only the pinned keys.");
        }
    }

    private static void ValidatePrivateKeys(List<string> failures, string subject, IList<SshEndpointPrivateKey> keys)
    {
        for (var i = 0; i < keys.Count; i++)
        {
            if (keys[i] is not { Key: { } text } entry || string.IsNullOrWhiteSpace(text))
            {
                failures.Add($"{subject}: PrivateKeys[{i}] has no Key (the private key's text).");
                continue;
            }

            // Parsed here so a bad key or passphrase fails at start (with ValidateOnStart), not at the first connection. The parser's
            // messages describe the problem (the format, a wrong or missing passphrase) and never hold key material.
            try
            {
                SshPrivateKey.Parse(text, entry.Passphrase).Dispose();
            }
            catch (FormatException ex)
            {
                failures.Add($"{subject}: PrivateKeys[{i}] could not be read: {ex.Message}");
            }
        }
    }

    /// <summary>Each hop as the endpoint itself is checked, and a hop behind a pinned endpoint must say how its own key is checked.</summary>
    private static void ValidateJumpHosts(List<string> failures, string name, SshEndpointOptions options)
    {
        for (var i = 0; i < options.JumpHosts.Count; i++)
        {
            var subject = $"SSH endpoint '{name}': JumpHosts[{i}]";
            if (options.JumpHosts[i] is not { } hop)
            {
                failures.Add($"{subject} is empty.");
                continue;
            }

            ValidateServer(failures, subject, hop.Host, hop.UserName, hop.Port, "set Host.");
            ValidateHostKeys(failures, subject, hop.HostKeyFingerprints, hop.KnownHostsFiles, hop.AcceptNewHostKeys);
            ValidatePrivateKeys(failures, subject, hop.PrivateKeys);
            if (options.HostKeyFingerprints.Count > 0 && hop.HostKeyFingerprints.Count == 0 && hop.KnownHostsFiles.Count == 0)
            {
                // The endpoint's pins are the destination's keys; the hop would otherwise fall back to known_hosts files a pinned
                // deployment does not have.
                failures.Add($"{subject}: set HostKeyFingerprints or KnownHostsFiles for the jump host; the endpoint's pinned fingerprints " +
                    "are the destination's.");
            }
        }
    }
}
