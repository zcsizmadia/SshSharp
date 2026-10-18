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

internal sealed class SshClientFactory(
    IServiceProvider services, SshEndpointRegistry registry, IOptionsMonitor<SshEndpointOptions> endpoints, ILoggerFactory? loggerFactory = null)
    : ISshClientFactory
{
    private readonly ILogger? _logger = loggerFactory?.CreateLogger("SshSharp");

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
                ? await SshClient.ConnectAsync(alias, new SshConfigConnectOptions { Password = endpoint.Password, Logger = _logger }, timeout.Token)
                    .ConfigureAwait(false)
                : await ConnectDirectAsync(name, endpoint, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"Connecting to the SSH endpoint '{name}' took longer than {endpoint.ConnectTimeout}.", ex);
        }
    }

    private async Task<SshClient> ConnectDirectAsync(string name, SshEndpointOptions endpoint, CancellationToken cancellationToken)
    {
        var keys = new List<SshPrivateKey>();
        try
        {
            foreach (var file in endpoint.PrivateKeyFiles)
            {
                keys.Add(await SshPrivateKey.LoadAsync(ExpandHome(file), endpoint.PrivateKeyPassphrase, cancellationToken).ConfigureAwait(false));
            }

            // Keys given as values come after the files. Validation has parsed each already, so a failure here is not expected; they are
            // read again for each connection, as the files are, so no decrypted key outlives its authentication.
            foreach (var entry in endpoint.PrivateKeys)
            {
                keys.Add(SshPrivateKey.Parse(entry.Key!, entry.Passphrase));
            }

            var options = new SshClientOptions
            {
                UserName = endpoint.UserName!,
                Password = endpoint.Password,
                PrivateKeys = keys,
                HostKeyVerifier = HostKeyVerifier(endpoint),
                Proxy = endpoint.Proxy is { Length: > 0 } proxy ? SshEndpointOptionsValidator.ParseProxy(proxy) : null,
                KeepAliveInterval = endpoint.KeepAliveInterval,
                ConnectTimeout = endpoint.ConnectTimeout,
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
            foreach (var key in keys)
            {
                key.Dispose();
            }
        }
    }

    /// <summary>
    /// Pinned fingerprints when the endpoint has them (validation has rejected known_hosts files and accept-new alongside them), otherwise
    /// its known_hosts files.
    /// </summary>
    private static SshHostKeyVerifier HostKeyVerifier(SshEndpointOptions endpoint)
    {
        if (endpoint.HostKeyFingerprints.Count > 0)
        {
            return SshHostKeyVerifier.Pinned([.. endpoint.HostKeyFingerprints.Select(f => f.Trim())]);
        }

        string[] knownHosts = endpoint.KnownHostsFiles.Count > 0
            ? [.. endpoint.KnownHostsFiles.Select(ExpandHome)]
            : [Path.Combine(Home(), ".ssh", "known_hosts")];
        return new KnownHostsVerifier(knownHosts)
        {
            Policy = endpoint.AcceptNewHostKeys ? StrictHostKeyChecking.AcceptNew : StrictHostKeyChecking.Yes,
        };
    }

    private static string Home() => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static string ExpandHome(string path) =>
        path == "~" ? Home() : path.StartsWith("~/", StringComparison.Ordinal) ? Path.Combine(Home(), path[2..]) : path;
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
            // ssh_config decides keys, host keys and proxies for an alias: a pin or key set here would otherwise be silently unused.
            string[] unused =
            [
                .. options.HostKeyFingerprints.Count > 0 ? [nameof(options.HostKeyFingerprints)] : Array.Empty<string>(),
                .. options.PrivateKeys.Count > 0 ? [nameof(options.PrivateKeys)] : Array.Empty<string>(),
                .. !string.IsNullOrEmpty(options.Proxy) ? [nameof(options.Proxy)] : Array.Empty<string>(),
            ];
            if (unused.Length > 0)
            {
                failures.Add($"SSH endpoint '{name}': {string.Join(", ", unused)} cannot be combined with ConfigAlias, whose ssh_config decides them.");
            }
        }
        else
        {
            if (string.IsNullOrEmpty(options.Host))
            {
                failures.Add($"SSH endpoint '{name}': set Host, or ConfigAlias to connect through ssh_config.");
            }

            if (string.IsNullOrEmpty(options.UserName))
            {
                failures.Add($"SSH endpoint '{name}': set UserName.");
            }

            if (options.Port is < 1 or > 65535)
            {
                failures.Add($"SSH endpoint '{name}': Port must be between 1 and 65535.");
            }
        }

        if (options.ConnectTimeout <= TimeSpan.Zero)
        {
            failures.Add($"SSH endpoint '{name}': ConnectTimeout must be positive.");
        }

        if (options.ReconnectDelay <= TimeSpan.Zero || options.MaxReconnectDelay < options.ReconnectDelay)
        {
            failures.Add($"SSH endpoint '{name}': ReconnectDelay must be positive, and MaxReconnectDelay at least as long.");
        }

        ValidateHostKeyFingerprints(name, options, failures);
        ValidatePrivateKeys(name, options, failures);
        if (!string.IsNullOrEmpty(options.Proxy) && ParseProxy(options.Proxy) is null)
        {
            // The value is not shown: it may hold the proxy's password.
            failures.Add($"SSH endpoint '{name}': Proxy is not a proxy URI (http, socks5, socks5h, socks4 or socks4a, then a host and an " +
                "optional port and user, as in http://proxy.example.com:3128).");
        }

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
    /// OpenSSH writes it (so that the ordinal comparison <see cref="SshHostKeyVerifier.Pinned"/> makes can match).
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

    private static void ValidateHostKeyFingerprints(string name, SshEndpointOptions options, List<string> failures)
    {
        if (options.HostKeyFingerprints.Count == 0)
        {
            return;
        }

        for (var i = 0; i < options.HostKeyFingerprints.Count; i++)
        {
            if (options.HostKeyFingerprints[i] is not { } fingerprint || !IsSha256Fingerprint(fingerprint.Trim()))
            {
                failures.Add($"SSH endpoint '{name}': HostKeyFingerprints[{i}] is not an OpenSSH SHA-256 fingerprint ('SHA256:' and 43 base64 " +
                    "characters, as ssh-keygen -lf prints).");
            }
        }

        // Pinned fingerprints replace known_hosts. Accepting a key either list allows would widen what is trusted to the larger of the two,
        // requiring both would bring back the file that pinning removes, and ignoring one silently would hide a mistake: so neither mixes.
        if (options.KnownHostsFiles.Count > 0)
        {
            failures.Add($"SSH endpoint '{name}': set HostKeyFingerprints or KnownHostsFiles, not both; pinned fingerprints replace known_hosts.");
        }

        if (options.AcceptNewHostKeys)
        {
            failures.Add($"SSH endpoint '{name}': AcceptNewHostKeys cannot be combined with HostKeyFingerprints, which trust only the pinned keys.");
        }
    }

    private static void ValidatePrivateKeys(string name, SshEndpointOptions options, List<string> failures)
    {
        for (var i = 0; i < options.PrivateKeys.Count; i++)
        {
            if (options.PrivateKeys[i] is not { Key: { } text } entry || string.IsNullOrWhiteSpace(text))
            {
                failures.Add($"SSH endpoint '{name}': PrivateKeys[{i}] has no Key (the private key's text).");
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
                failures.Add($"SSH endpoint '{name}': PrivateKeys[{i}] could not be read: {ex.Message}");
            }
        }
    }
}
