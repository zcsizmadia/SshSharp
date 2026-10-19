using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.FileProviders;
using SshSharp.Sftp;
using SshSharp.Tests.Sftp;

namespace SshSharp.Tests.DependencyInjection;

/// <summary>SshSharp.Extensions.DependencyInjection: named endpoints, the factory, the shared reconnecting connection, the health check.</summary>
public sealed class DependencyInjectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-di").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private string KnownHosts => Path.Combine(_dir, "known_hosts");

    private Action<SshEndpointOptions> Endpoint(TcpFakeSshServer server, bool acceptNew = true) => o =>
    {
        o.Host = "127.0.0.1";
        o.Port = server.Port;
        o.UserName = "tester";
        o.Password = "secret";
        o.KnownHostsFiles = [KnownHosts];
        o.AcceptNewHostKeys = acceptNew;
        o.ReconnectDelay = TimeSpan.FromSeconds(10);
        o.MaxReconnectDelay = TimeSpan.FromSeconds(40);
    };

    [Test]
    public async Task TheFactory_OpensANewConnectionPerCall_AndRecordsANewHostKey()
    {
        await using var server = new TcpFakeSshServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<ISshClientFactory>();

        await using (var first = await factory.ConnectAsync("box", Timeout()))
        {
            await Assert.That(first.IsConnected).IsTrue();
        }

        await using var second = await factory.ConnectAsync("box", Timeout());
        await Assert.That(second.IsConnected).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(2);
        await Assert.That(await File.ReadAllTextAsync(KnownHosts)).Contains($"[127.0.0.1]:{server.Port} ssh-ed25519 ");
    }

    [Test]
    public async Task AnUnknownHost_FailsByDefault()
    {
        await using var server = new TcpFakeSshServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server, acceptNew: false));
        await using var provider = services.BuildServiceProvider();

        var ex = await Assert.ThrowsAsync<SshException>(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout()));
        await Assert.That(ex!.Reason).IsEqualTo(SshFailureReason.HostKeyRejected);
        await Assert.That(File.Exists(KnownHosts)).IsFalse();
    }

    [Test]
    public async Task UnknownNames_AndIncompleteSettings_FailClearly()
    {
        var services = new ServiceCollection();
        services.AddSshClient("nohost", o => o.UserName = "u");
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<ISshClientFactory>();

        await Assert.That(async () => await factory.ConnectAsync("other", Timeout())).Throws<InvalidOperationException>().WithMessageContaining("AddSshClient");
        await Assert.That(async () => await factory.ConnectAsync("nohost", Timeout())).Throws<OptionsValidationException>().WithMessageContaining("Host");
    }

    [Test]
    public async Task Settings_BindFromConfiguration()
    {
        await using var server = new TcpFakeSshServer();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Ssh:Box:Host"] = "127.0.0.1",
            ["Ssh:Box:Port"] = server.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Ssh:Box:UserName"] = "tester",
            ["Ssh:Box:Password"] = "secret",
            ["Ssh:Box:KnownHostsFiles:0"] = KnownHosts,
            ["Ssh:Box:AcceptNewHostKeys"] = "true",
            ["Ssh:Box:ConnectTimeout"] = "00:00:20",
        }).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSshClient("box").BindConfiguration("Ssh:Box");
        await using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptionsMonitor<SshEndpointOptions>>().Get("box");
        await Assert.That(options.ConnectTimeout).IsEqualTo(TimeSpan.FromSeconds(20));
        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task TheSharedConnection_IsReused_AndOpenedAgainAfterItDrops()
    {
        await using var server = new TcpFakeSshServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();

        var first = await connections.GetClientAsync("box", Timeout());
        var again = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => connections.GetClientAsync("box", Timeout())));
        await Assert.That(again.All(c => ReferenceEquals(c, first))).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(1);

        server.DropAll();
        for (var i = 0; i < 500 && first.IsConnected; i++)
        {
            await Task.Delay(10);
        }

        var reconnected = await connections.GetClientAsync("box", Timeout());
        await Assert.That(ReferenceEquals(reconnected, first)).IsFalse();
        await Assert.That(reconnected.IsConnected).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(2);
    }

    [Test]
    public async Task AFailingEndpoint_IsRetriedOnlyAfterAGrowingWait()
    {
        await using var server = new TcpFakeSshServer { Refuse = true };
        var time = new FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();

        var first = await Assert.ThrowsAsync<SshException>(async () => await connections.GetClientAsync("box", Timeout()));
        await Assert.That(server.Connections).IsEqualTo(1);

        // Within the wait (10 s after the first failure), the last error comes back at once, without connecting: inside a new
        // exception for each caller, so the shared one's stack trace does not grow with every caller.
        time.Advance(TimeSpan.FromSeconds(9));
        var again = await Assert.ThrowsAsync<SshException>(async () => await connections.GetClientAsync("box", Timeout()));
        var third = await Assert.ThrowsAsync<SshException>(async () => await connections.GetClientAsync("box", Timeout()));
        await Assert.That(ReferenceEquals(again!.InnerException, first)).IsTrue();
        await Assert.That(ReferenceEquals(third!.InnerException, first)).IsTrue();
        await Assert.That(ReferenceEquals(again, third)).IsFalse();
        await Assert.That(again.Reason).IsEqualTo(first!.Reason);
        await Assert.That(server.Connections).IsEqualTo(1);

        // After it, one attempt; it fails too, so the next wait is twice as long.
        time.Advance(TimeSpan.FromSeconds(2));
        await Assert.That(async () => await connections.GetClientAsync("box", Timeout())).Throws<SshException>();
        await Assert.That(server.Connections).IsEqualTo(2);
        time.Advance(TimeSpan.FromSeconds(15));
        await Assert.That(async () => await connections.GetClientAsync("box", Timeout())).Throws<SshException>();
        await Assert.That(server.Connections).IsEqualTo(2);

        server.Refuse = false;
        time.Advance(TimeSpan.FromSeconds(10));
        await Assert.That((await connections.GetClientAsync("box", Timeout())).IsConnected).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(3);
    }

    /// <summary>An endpoint at a loopback port that completes TCP connections (the backlog does) and never sends an identification.</summary>
    private Action<SshEndpointOptions> Silent(System.Net.Sockets.TcpListener listener, TimeSpan connectTimeout, Func<IServiceProvider, SshClientOptions, SshClientOptions>? configure = null) => o =>
    {
        o.Host = "127.0.0.1";
        o.Port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        o.UserName = "tester";
        o.KnownHostsFiles = [KnownHosts];
        o.ConnectTimeout = connectTimeout;
        o.ConfigureClientOptions = configure;
    };

    [Test]
    public async Task ConnectTimeout_IsTheClientOptionsConnectTimeout()
    {
        await using var server = new TcpFakeSshServer();
        TimeSpan? seen = null;
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server)).Configure(o =>
        {
            o.ConnectTimeout = TimeSpan.FromSeconds(20);
            o.ConfigureClientOptions = (_, options) =>
            {
                seen = options.ConnectTimeout;
                return options;
            };
        });
        await using var provider = services.BuildServiceProvider();

        await using var client = await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout());
        await Assert.That(client.IsConnected).IsTrue();
        await Assert.That(seen).IsEqualTo(TimeSpan.FromSeconds(20));
    }

    [Test]
    public async Task ConnectTimeout_StopsAServerThatNeverAnswers_WithATimeoutException()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var services = new ServiceCollection();
            services.AddSshClient("box", Silent(listener, TimeSpan.FromMilliseconds(300)));
            await using var provider = services.BuildServiceProvider();

            await Assert.That(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout()))
                .Throws<TimeoutException>().WithMessageContaining("'box'");
        }
        finally
        {
            listener.Stop();
        }
    }

    [Test]
    public async Task ConfigureClientOptions_CanShortenTheConnectTimeout_StillATimeoutException()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var services = new ServiceCollection();
            services.AddSshClient("box", Silent(listener, TimeSpan.FromMinutes(5), (_, o) => new SshClientOptions
            {
                UserName = o.UserName,
                HostKeyVerifier = o.HostKeyVerifier,
                ConnectTimeout = TimeSpan.FromMilliseconds(300),
            }));
            await using var provider = services.BuildServiceProvider();

            var ex = await Assert.ThrowsAsync<TimeoutException>(async () => await provider.GetRequiredService<ISshClientFactory>().ConnectAsync("box", Timeout()));
            await Assert.That(ex!.InnerException).IsTypeOf<SshException>();
            await Assert.That(((SshException)ex.InnerException!).Reason).IsEqualTo(SshFailureReason.Timeout);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Test]
    public async Task OpenSftpAsync_OpensSessionsOnTheSharedConnection_SoAFileProviderFollowsItAcrossADrop()
    {
        var files = new FakeSftpServer();
        files.AddDirectory(FakeSftpServer.Home + "/site");
        files.AddFile(FakeSftpServer.Home + "/site/index.html", "<h1>hello</h1>"u8.ToArray());
        await using var server = new TcpFakeSshServer { Configure = files.Install };
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();
        await using var fileProvider = new SftpFileProvider(ct => connections.OpenSftpAsync("box", ct), "site",
            new SftpFileProviderOptions { CacheDuration = TimeSpan.Zero });

        await Assert.That(fileProvider.GetFileInfo("index.html").Exists).IsTrue();
        await using (var sftp = await connections.OpenSftpAsync("box", Timeout())) // the caller's own session, on the same connection
        {
            await Assert.That(await sftp.ExistsAsync("site/index.html", Timeout())).IsTrue();
        }

        await Assert.That(server.Connections).IsEqualTo(1);
        await Assert.That(files.Sessions).IsEqualTo(2);

        var first = await connections.GetClientAsync("box", Timeout());
        server.DropAll();
        for (var i = 0; i < 500 && first.IsConnected; i++)
        {
            await Task.Delay(10);
        }

        // The provider meets the dropped session, opens a new one on the reconnected shared connection, and answers.
        await Assert.That(fileProvider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(2);
        await Assert.That(files.Sessions).IsEqualTo(3);
        await Assert.That(async () => await connections.OpenSftpAsync("", Timeout())).Throws<ArgumentException>();
    }

    [Test]
    public async Task DisposingTheContainer_ClosesTheSharedConnection()
    {
        await using var server = new TcpFakeSshServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        var provider = services.BuildServiceProvider();
        var client = await provider.GetRequiredService<ISshConnectionProvider>().GetClientAsync("box", Timeout());

        await provider.DisposeAsync();

        await Assert.That(client.IsConnected).IsFalse();
    }

    [Test]
    public async Task TheHealthCheck_PingsTheSharedConnection()
    {
        await using var server = new TcpFakeSshServer();
        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>)); // the health check service logs
        services.AddSshClient("box", Endpoint(server));
        services.AddHealthChecks().AddSsh("box");
        await using var provider = services.BuildServiceProvider();
        var health = provider.GetRequiredService<HealthCheckService>();

        var healthy = await health.CheckHealthAsync(Timeout());
        await Assert.That(healthy.Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(healthy.Entries["ssh-box"].Description).Contains("ping");
        await Assert.That(healthy.Entries["ssh-box"].Description).DoesNotContain("SSH-2.0"); // nothing from the server: /healthz is often public

        server.Refuse = true;
        server.DropAll();
        var client = await provider.GetRequiredService<ISshConnectionProvider>().GetClientAsync("box", Timeout()).ContinueWith(t => t.IsCompletedSuccessfully ? t.Result : null);
        for (var i = 0; i < 500 && client?.IsConnected == true; i++)
        {
            await Task.Delay(10);
        }

        var unhealthy = await health.CheckHealthAsync(Timeout());
        await Assert.That(unhealthy.Status).IsEqualTo(HealthStatus.Unhealthy);
    }
}
