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

            string[] knownHosts = endpoint.KnownHostsFiles.Count > 0
                ? [.. endpoint.KnownHostsFiles.Select(ExpandHome)]
                : [Path.Combine(Home(), ".ssh", "known_hosts")];
            var options = new SshClientOptions
            {
                UserName = endpoint.UserName!,
                Password = endpoint.Password,
                PrivateKeys = keys,
                HostKeyVerifier = new KnownHostsVerifier(knownHosts)
                {
                    Policy = endpoint.AcceptNewHostKeys ? StrictHostKeyChecking.AcceptNew : StrictHostKeyChecking.Yes,
                },
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
        if (string.IsNullOrEmpty(options.ConfigAlias))
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

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
