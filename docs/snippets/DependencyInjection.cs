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
                KeepAliveInterval = built.KeepAliveInterval,
                Logger = built.Logger,
                // Changed: the host key pinned in configuration instead of known_hosts, and an outbound HTTP proxy.
                HostKeyVerifier = SshHostKeyVerifier.Pinned(
                    provider.GetRequiredService<IConfiguration>()["Ssh:Deploy:HostKeyFingerprint"]
                    ?? throw new InvalidOperationException("Set Ssh:Deploy:HostKeyFingerprint.")),
                Proxy = SshProxy.Http("proxy.example.com", 3128),
            };
        });
        // </customize>
    }
}
