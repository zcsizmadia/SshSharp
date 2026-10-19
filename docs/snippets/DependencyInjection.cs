using System.IO.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SshSharp;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.IO.Abstractions;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/aspnetcore-and-di.md.</summary>
internal static partial class DependencyInjection
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

    // <sftp>
    /// <summary>A service that reads files: an SFTP session of its own for each call, on the shared connection.</summary>
    public sealed class ReportReader(ISshConnectionProvider connections)
    {
        public async Task<long> SizeAsync(string path, CancellationToken cancellationToken)
        {
            await using var sftp = await connections.OpenSftpAsync("deploy", cancellationToken);   // the session is ours to dispose
            return (await sftp.GetAttributesAsync(path, cancellationToken: cancellationToken)).Size ?? 0;
        }
    }
    // </sftp>

    public static void RegisterFileSystem(IServiceCollection services)
    {
        // <file-system>
        // An IFileSystem over the shared connection, for services that take one. It keeps one SFTP session and opens a new one after
        // the connection drops. The container owns it and disposes it (and its session) with the application; the connection under
        // it stays the provider's.
        services.AddSingleton<IFileSystem>(sp =>
        {
            var connections = sp.GetRequiredService<ISshConnectionProvider>();
            return new SftpFileSystem(ct => connections.OpenSftpAsync("deploy", ct));
        });
        // </file-system>
    }

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
                PrivateKeys = built.PrivateKeys,   // the agent's too, with UseAgent
                Proxy = built.Proxy,
                JumpHosts = built.JumpHosts,
                AddressFamily = built.AddressFamily,
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

    public static void JumpHost(IServiceCollection services)
    {
        // <jump-hosts>
        services.AddSshClient("internal-app", o =>
        {
            o.Host = "app1.internal.example.com"; // resolved by the bastion
            o.UserName = "deploy";
            o.PrivateKeyFiles.Add("~/.ssh/deploy_ed25519");
            o.KnownHostsFiles.Add("/etc/myapp/known_hosts"); // holds the target's key, and the bastion's (it has none of its own below)

            // The bastion, with its own user and key. The endpoint's password and keys are never offered to it, nor its to the target.
            o.JumpHosts.Add(new SshEndpointJumpHost
            {
                Host = "bastion.example.com",
                UserName = "jump",
                PrivateKeyFiles = ["~/.ssh/jump_ed25519"],
            });
        });
        // </jump-hosts>
    }

    // <keyed>
    /// <summary>A service that works with one endpoint, and names it once, where it is injected.</summary>
    public sealed class Backups([FromKeyedServices("deploy")] ISshEndpoint deploy)
    {
        public async Task<string> ListAsync(CancellationToken cancellationToken)
        {
            var client = await deploy.GetClientAsync(cancellationToken);   // the shared connection: do not dispose
            return (await client.RunCommandAsync("ls /var/backups", cancellationToken)).StandardOutputText;
        }

        public async Task<long> SizeAsync(string path, CancellationToken cancellationToken)
        {
            await using var sftp = await deploy.OpenSftpAsync(cancellationToken);   // an SFTP session on it: ours to dispose
            return (await sftp.GetAttributesAsync(path, cancellationToken: cancellationToken)).Size ?? 0;
        }
    }
    // </keyed>

    public static void HttpClientThroughSsh(IServiceCollection services)
    {
        // <http-client>
        services.AddSshClient("bastion").BindConfiguration("Ssh:Bastion");

        // Every connection this client makes goes through the bastion's shared SSH connection; the bastion resolves the host name.
        services.AddHttpClient("inventory", http => http.BaseAddress = new Uri("https://inventory.internal.example.com/"))
            .UseSshTunnel("bastion");
        // </http-client>
    }

    // <http-client-use>
    /// <summary>Uses the tunnelled client like any other named HttpClient.</summary>
    public sealed class Inventory(IHttpClientFactory httpClients)
    {
        public Task<string> HostsAsync(CancellationToken cancellationToken) =>
            httpClients.CreateClient("inventory").GetStringAsync("api/hosts", cancellationToken);
    }
    // </http-client-use>

    // <watch>
    /// <summary>
    /// Keeps a remote forwarding (port 8080 on the server to this application's port 5000) on the shared connection, and sets it up
    /// again on each new connection.
    /// </summary>
    public sealed partial class ReverseTunnel([FromKeyedServices("deploy")] ISshEndpoint deploy, ILogger<ReverseTunnel> logger) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await ConnectAsync(stoppingToken);

            // The first event is the current state; then each change, as it happens.
            await foreach (var change in deploy.WatchAsync(stoppingToken))
            {
                if (change.Kind == SshConnectionEventKind.Disconnected)
                {
                    Dropped(logger, change.EndpointName, change.Error);
                    await ConnectAsync(stoppingToken);   // a Reconnected event follows
                    continue;
                }

                try
                {
                    // Connected or Reconnected: forwardings die with their connection, so set this one up on the new connection.
                    await change.Client.ForwardRemotePortAsync("localhost", 8080, "localhost", 5000, stoppingToken);
                }
                catch (Exception ex) when (ex is SshException or ObjectDisposedException && !change.Client.IsConnected)
                {
                    // Dropped again already (and perhaps disposed, replaced by a newer connection): the next event says what followed.
                }
            }
        }

        /// <summary>Opens the shared connection, trying again until it is up (the provider waits between failed attempts too).</summary>
        private async Task ConnectAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                try
                {
                    await deploy.GetClientAsync(cancellationToken);
                    return;
                }
                catch (Exception ex) when (ex is SshException or TimeoutException)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
            }
        }

        [LoggerMessage(Level = LogLevel.Warning, Message = "SSH endpoint {Endpoint} disconnected; reconnecting")]
        private static partial void Dropped(ILogger logger, string endpoint, Exception? error);
    }
    // </watch>

    public static void Agent(IServiceCollection services)
    {
        // <agent>
        services.AddSshClient("deploy", o =>
        {
            o.Host = "deploy.example.com";
            o.UserName = "deploy";
            o.KnownHostsFiles.Add("/etc/myapp/known_hosts");
            o.UseAgent = true;   // the agent's keys, after any key files and keys given as values
        });
        // </agent>
    }

    public static void InProcessAgent(IServiceCollection services, SshPrivateKey kmsKey)
    {
        // <agent-in-process>
        // An agent served in this process, for example from a key behind SshPrivateKey.FromSigner (a cloud KMS): endpoints with
        // UseAgent use it instead of the environment's agent.
        services.AddSingleton(SshAgent.FromKeys(kmsKey));
        // </agent-in-process>
    }
}
