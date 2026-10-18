using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SshSharp;
using SshSharp.Extensions.DependencyInjection;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/aspnetcore-and-di.md.</summary>
internal static class DependencyInjection
{
    public static void Register(WebApplicationBuilder builder)
    {
        // <register>
        // Program.cs
        builder.Services.AddSshClient("deploy")
            .BindConfiguration("Ssh:Deploy")   // appsettings.json, environment variables, user secrets, Key Vault ...
            .ValidateOnStart();                // a missing Host or UserName fails at startup, not on the first request

        builder.Services.AddSshClient("db", o => o.ConfigAlias = "prod-db");   // everything from ~/.ssh/config

        builder.Services.AddHealthChecks().AddSsh("deploy", tags: ["ready"]);
        // </register>
    }

    public static void MapEndpoints(WebApplication app)
    {
        // <endpoint>
        app.MapGet("/uptime", async (ISshConnectionProvider connections, CancellationToken cancellationToken) =>
        {
            var client = await connections.GetClientAsync("deploy", cancellationToken);   // shared: do not dispose
            var result = await client.RunCommandAsync("uptime", cancellationToken);
            return result.ExitStatus == 0 ? Results.Text(result.StandardOutputText) : Results.Problem("uptime failed.");
        });

        app.MapHealthChecks("/healthz");
        // </endpoint>
    }

    // <factory>
    /// <summary>A service that wants a connection of its own, for one job, and closes it afterwards.</summary>
    public sealed class Deployer(ISshClientFactory ssh)
    {
        public async Task<int> RestartAsync(string service, CancellationToken cancellationToken)
        {
            await using var client = await ssh.ConnectAsync("deploy", cancellationToken);   // new connection: ours to dispose
            var result = await client.RunCommandAsync($"sudo systemctl restart {Commands.Quote(service)}", cancellationToken);
            return result.ExitStatus ?? -1;
        }
    }
    // </factory>

    // <provider>
    /// <summary>A service that runs many short commands: the shared connection, opened once and reopened when it drops.</summary>
    public sealed class ServerStatus(ISshConnectionProvider connections)
    {
        public async Task<string> LoadAverageAsync(CancellationToken cancellationToken)
        {
            var client = await connections.GetClientAsync("deploy", cancellationToken);   // owned by the provider
            return (await client.RunCommandAsync("cat /proc/loadavg", cancellationToken)).StandardOutputText.Trim();
        }
    }
    // </provider>

    public static void Containers(WebApplicationBuilder builder)
    {
        // <containers>
        // Program.cs: the same registration as anywhere else. In the container, the configuration comes from environment variables
        // or a secret store, and holds the key's text and the pinned fingerprints instead of file paths.
        builder.Services.AddSshClient("deploy")
            .BindConfiguration("Ssh:Deploy")
            .ValidateOnStart();   // a malformed fingerprint, an unreadable key or a wrong passphrase stops the start, by index only
        // </containers>
    }

    public static void PinInCode(IServiceCollection services, IConfiguration configuration)
    {
        // <pin-in-code>
        services.AddSshClient("deploy", o =>
        {
            o.Host = "deploy.example.com";
            o.UserName = "deploy";

            // Both values are secrets (or, for the fingerprint, trust anchors): read them from configuration, never write them here.
            o.HostKeyFingerprints.Add(configuration["Ssh:Deploy:HostKeyFingerprint"]
                ?? throw new InvalidOperationException("Set Ssh:Deploy:HostKeyFingerprint."));
            o.PrivateKeys.Add(new SshEndpointPrivateKey
            {
                Key = configuration["Ssh:Deploy:Key"],
                Passphrase = configuration["Ssh:Deploy:KeyPassphrase"],   // null for an unencrypted key
            });
        });
        // </pin-in-code>
    }

    /// <summary>A trust store the application already has (a CMDB, an inventory service).</summary>
    public interface IHostKeyInventory
    {
        ValueTask<bool> IsTrustedAsync(string? host, string fingerprint, CancellationToken cancellationToken);
    }

    public static void Customize(IServiceCollection services)
    {
        // <customize>
        services.AddSshClient("deploy", o =>
        {
            o.Host = "deploy.example.com";
            o.UserName = "deploy";
            o.PrivateKeyFiles.Add("~/.ssh/deploy_ed25519");

            // SshClientOptions is immutable: build new options, and keep what the endpoint already set.
            o.ConfigureClientOptions = (provider, built) => new SshClientOptions
            {
                UserName = built.UserName,
                Password = built.Password,
                PrivateKeys = built.PrivateKeys,
                Proxy = built.Proxy,
                KeepAliveInterval = built.KeepAliveInterval,
                ConnectTimeout = built.ConnectTimeout,
                Logger = built.Logger,
                // Changed: host keys checked by a service from the container instead of known_hosts or pinned fingerprints.
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((context, cancellationToken) =>
                    provider.GetRequiredService<IHostKeyInventory>().IsTrustedAsync(context.Host, context.HostKey.Fingerprint, cancellationToken)),
            };
        });
        // </customize>
    }
}
