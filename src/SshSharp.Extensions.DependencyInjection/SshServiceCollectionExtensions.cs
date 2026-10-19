using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SshSharp;
using SshSharp.Extensions.DependencyInjection;

// In the namespace of IServiceCollection, as Microsoft's own AddX methods are, so they are found without another using.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers SSH endpoints with a service collection.</summary>
public static class SshServiceCollectionExtensions
{
    /// <summary>
    /// Registers the SSH endpoint <paramref name="name"/>, with <see cref="ISshClientFactory"/> and <see cref="ISshConnectionProvider"/>,
    /// and <see cref="ISshEndpoint"/> keyed by <paramref name="name"/> (<c>[FromKeyedServices("deploy")] ISshEndpoint deploy</c>).
    /// Configure it through the returned builder, for example <c>.BindConfiguration("Ssh:Deploy")</c> or <c>.Configure(o => ...)</c>,
    /// and add <c>.ValidateOnStart()</c> to check its settings when the host starts.
    /// </summary>
    /// <returns>The named options builder for the endpoint's <see cref="SshEndpointOptions"/>.</returns>
    public static OptionsBuilder<SshEndpointOptions> AddSshClient(this IServiceCollection services, string name)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(name);

        // One registry per collection, shared by every AddSshClient call on it.
        if (services.FirstOrDefault(d => d.ServiceType == typeof(SshEndpointRegistry))?.ImplementationInstance is not SshEndpointRegistry registry)
        {
            registry = new SshEndpointRegistry();
            services.AddSingleton(registry);
        }

        registry.Add(name);

        // Keyed by the name, a view of the shared provider and factory for that name (not a client: resolving a service cannot wait for
        // a connection without blocking a thread).
        services.TryAddKeyedSingleton<ISshEndpoint>(name, (sp, _) => new SshEndpoint(
            name, sp.GetRequiredService<ISshConnectionProvider>(), sp.GetRequiredService<ISshClientFactory>()));
        services.TryAddSingleton(sp => new SshClientFactory(
            sp, registry, sp.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>(), sp.GetService<ILoggerFactory>()));
        services.TryAddSingleton<ISshClientFactory>(sp => sp.GetRequiredService<SshClientFactory>());
        services.TryAddSingleton(sp => new SshConnectionProvider(sp.GetRequiredService<SshClientFactory>(), sp.GetService<TimeProvider>()));
        services.TryAddSingleton<ISshConnectionProvider>(sp => sp.GetRequiredService<SshConnectionProvider>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SshEndpointOptions>, SshEndpointOptionsValidator>(
            _ => new SshEndpointOptionsValidator(registry)));
        return services.AddOptions<SshEndpointOptions>(name);
    }

    /// <summary>Registers the SSH endpoint <paramref name="name"/>, configured by <paramref name="configure"/>.</summary>
    /// <returns>The named options builder for the endpoint's <see cref="SshEndpointOptions"/>.</returns>
    public static OptionsBuilder<SshEndpointOptions> AddSshClient(this IServiceCollection services, string name, Action<SshEndpointOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return services.AddSshClient(name).Configure(configure);
    }

    /// <summary>
    /// Adds a health check for the SSH endpoint <paramref name="name"/>: healthy when its shared connection
    /// (<see cref="ISshConnectionProvider"/>) is up, or can be opened, and answers a ping.
    /// </summary>
    /// <param name="builder">The health checks builder.</param>
    /// <param name="name">The endpoint, as registered with <c>AddSshClient</c>.</param>
    /// <param name="checkName">The check's name (default <c>ssh-</c> and the endpoint's name).</param>
    /// <param name="failureStatus">The status reported when the check fails (default <see cref="HealthStatus.Unhealthy"/>).</param>
    /// <param name="tags">Tags to filter checks by.</param>
    /// <param name="timeout">How long the check may take (default: the health check service's).</param>
    public static IHealthChecksBuilder AddSsh(this IHealthChecksBuilder builder, string name, string? checkName = null, HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);
        return builder.Add(new HealthCheckRegistration(
            checkName ?? "ssh-" + name, sp => new SshHealthCheck(name, sp.GetRequiredService<ISshConnectionProvider>()), failureStatus, tags, timeout));
    }
}
