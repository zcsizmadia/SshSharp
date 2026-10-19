using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.Tests.Protocol;
using SshSharp.Tests.Sftp;

namespace SshSharp.Tests.DependencyInjection;

/// <summary>
/// The shared connection seen from the application: keyed <see cref="ISshEndpoint"/> services, connection change notifications
/// (<see cref="ISshConnectionProvider.WatchAsync"/>) across drops, and an HttpClient tunnelled through the connection.
/// </summary>
public sealed class SharedConnectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-di-shared").FullName;
    private readonly string _password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private TcpFakeSshServer NewServer(Action<FakeSessionServer>? configure = null) => new() { Password = _password, Configure = configure };

    private Action<SshEndpointOptions> Endpoint(TcpFakeSshServer server) => o =>
    {
        o.Host = "127.0.0.1";
        o.Port = server.Port;
        o.UserName = "tester";
        o.Password = _password;
        o.HostKeyFingerprints = [server.HostKeyFingerprint];
        o.ReconnectDelay = TimeSpan.FromSeconds(10);
        o.MaxReconnectDelay = TimeSpan.FromSeconds(40);
    };

    private static async Task WaitUntilDroppedAsync(SshClient client)
    {
        for (var i = 0; i < 500 && client.IsConnected; i++)
        {
            await Task.Delay(10);
        }
    }

    /// <summary>A service that takes its endpoint by name, as an application's would.</summary>
    private sealed class Consumer([FromKeyedServices("box")] ISshEndpoint box)
    {
        public ISshEndpoint Box { get; } = box;
    }

    [Test]
    public async Task KeyedEndpoints_ResolveByName_AndShareTheProvidersConnection()
    {
        await using var server = NewServer();
        await using var other = NewServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        services.AddSshClient("box", Endpoint(server)); // registering twice adds no second keyed service
        services.AddSshClient("other", Endpoint(other));
        services.AddSingleton<Consumer>();
        await using var provider = services.BuildServiceProvider();

        var box = provider.GetRequiredService<Consumer>().Box;
        await Assert.That(box.Name).IsEqualTo("box");
        await Assert.That(ReferenceEquals(box, provider.GetRequiredKeyedService<ISshEndpoint>("box"))).IsTrue(); // a singleton
        await Assert.That(provider.GetKeyedServices<ISshEndpoint>("box").Count()).IsEqualTo(1);
        await Assert.That(provider.GetRequiredKeyedService<ISshEndpoint>("other").Name).IsEqualTo("other");
        await Assert.That(provider.GetKeyedService<ISshEndpoint>("missing")).IsNull();

        // The shared connection is the provider's; ConnectAsync is a new one, the caller's.
        var shared = await box.GetClientAsync(Timeout());
        await Assert.That(ReferenceEquals(shared, await provider.GetRequiredService<ISshConnectionProvider>().GetClientAsync("box", Timeout()))).IsTrue();
        await using (var own = await box.ConnectAsync(Timeout()))
        {
            await Assert.That(ReferenceEquals(own, shared)).IsFalse();
            await Assert.That(own.IsConnected).IsTrue();
        }

        await Assert.That(shared.IsConnected).IsTrue();
        await Assert.That(server.Connections).IsEqualTo(2);
        await Assert.That(other.Connections).IsEqualTo(0);
    }

    [Test]
    public async Task AKeyedEndpoint_OpensSftpOnTheSharedConnection()
    {
        var files = new FakeSftpServer();
        files.AddFile(FakeSftpServer.Home + "/report.txt", "42"u8.ToArray());
        await using var server = NewServer(files.Install);
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var box = provider.GetRequiredKeyedService<ISshEndpoint>("box");

        await using (var sftp = await box.OpenSftpAsync(Timeout()))
        {
            await Assert.That(await sftp.ExistsAsync("report.txt", Timeout())).IsTrue();
        }

        await Assert.That(server.Connections).IsEqualTo(1);
    }

    [Test]
    public async Task Watchers_SeeConnected_Disconnected_AndReconnected_AcrossADrop()
    {
        await using var server = NewServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();
        var cancel = Timeout();

        // A watcher from before the first connection: watching connects nothing.
        await using var early = connections.WatchAsync("box", cancel).GetAsyncEnumerator(cancel);
        var pending = early.MoveNextAsync();
        await Task.Delay(50);
        await Assert.That(pending.IsCompleted).IsFalse();
        await Assert.That(server.Connections).IsEqualTo(0);

        var first = await connections.GetClientAsync("box", cancel);
        await Assert.That(await pending).IsTrue();
        await Assert.That(early.Current.Kind).IsEqualTo(SshConnectionEventKind.Connected);
        await Assert.That(early.Current.EndpointName).IsEqualTo("box");
        await Assert.That(ReferenceEquals(early.Current.Client, first)).IsTrue();
        await Assert.That(early.Current.Error).IsNull();

        // A watcher that starts while the connection is up learns of it at once.
        await using var late = provider.GetRequiredKeyedService<ISshEndpoint>("box").WatchAsync(cancel).GetAsyncEnumerator(cancel);
        await Assert.That(await late.MoveNextAsync()).IsTrue();
        await Assert.That(late.Current.Kind).IsEqualTo(SshConnectionEventKind.Connected);
        await Assert.That(ReferenceEquals(late.Current.Client, first)).IsTrue();

        // The drop is reported without anyone calling the provider, with the connection's error.
        server.DropAll();
        await Assert.That(await early.MoveNextAsync()).IsTrue();
        var disconnected = early.Current;
        await Assert.That(disconnected.Kind).IsEqualTo(SshConnectionEventKind.Disconnected);
        await Assert.That(ReferenceEquals(disconnected.Client, first)).IsTrue();
        await Assert.That(disconnected.Error).IsNotNull();
        await Assert.That(ReferenceEquals(disconnected.Error, first.ConnectionError)).IsTrue();
        await Assert.That(await late.MoveNextAsync()).IsTrue();
        await Assert.That(late.Current.Kind).IsEqualTo(SshConnectionEventKind.Disconnected);

        // A watcher that starts now learns that the connection is down, and why.
        await using var afterDrop = connections.WatchAsync("box", cancel).GetAsyncEnumerator(cancel);
        await Assert.That(await afterDrop.MoveNextAsync()).IsTrue();
        await Assert.That(afterDrop.Current.Kind).IsEqualTo(SshConnectionEventKind.Disconnected);
        await Assert.That(ReferenceEquals(afterDrop.Current.Error, disconnected.Error)).IsTrue();

        // The next GetClientAsync reconnects; the reconnection carries the reason the old connection ended.
        var second = await connections.GetClientAsync("box", cancel);
        await Assert.That(await early.MoveNextAsync()).IsTrue();
        await Assert.That(early.Current.Kind).IsEqualTo(SshConnectionEventKind.Reconnected);
        await Assert.That(ReferenceEquals(early.Current.Client, second)).IsTrue();
        await Assert.That(ReferenceEquals(early.Current.Error, disconnected.Error)).IsTrue();
        await Assert.That(await late.MoveNextAsync()).IsTrue();
        await Assert.That(late.Current.Kind).IsEqualTo(SshConnectionEventKind.Reconnected);
        await Assert.That(await afterDrop.MoveNextAsync()).IsTrue();
        await Assert.That(afterDrop.Current.Kind).IsEqualTo(SshConnectionEventKind.Reconnected);
        await Assert.That(server.Connections).IsEqualTo(2);
    }

    [Test]
    public async Task ADropNoticedByGetClientAsync_IsReportedOnce_BeforeTheReconnection()
    {
        await using var server = NewServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();
        var cancel = Timeout();
        var first = await connections.GetClientAsync("box", cancel);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        await using var watcher = connections.WatchAsync("box", stop.Token).GetAsyncEnumerator(stop.Token);
        var seen = new List<SshConnectionEventKind>();
        await Assert.That(await watcher.MoveNextAsync()).IsTrue();
        seen.Add(watcher.Current.Kind);

        // Each time, the provider may meet the dead connection before the closed connection's own callback reports it: either way,
        // one Disconnected, before the Reconnected.
        for (var i = 0; i < 3; i++)
        {
            var client = await connections.GetClientAsync("box", cancel);
            server.DropAll();
            await WaitUntilDroppedAsync(client);
        }

        await connections.GetClientAsync("box", cancel);
        for (var i = 0; i < 6; i++)
        {
            await Assert.That(await watcher.MoveNextAsync()).IsTrue();
            seen.Add(watcher.Current.Kind);
        }

        SshConnectionEventKind[] expected =
        [
            SshConnectionEventKind.Connected,
            SshConnectionEventKind.Disconnected, SshConnectionEventKind.Reconnected,
            SshConnectionEventKind.Disconnected, SshConnectionEventKind.Reconnected,
            SshConnectionEventKind.Disconnected, SshConnectionEventKind.Reconnected,
        ];
        await Assert.That(seen).IsEquivalentTo(expected, TUnit.Assertions.Enums.CollectionOrdering.Matching);
        await Assert.That(first.IsConnected).IsFalse();

        // Nothing more: no event was reported twice (one would complete the next read at once, rather than leave it to the cancellation).
        var next = watcher.MoveNextAsync().AsTask();
        await Task.Delay(100);
        await stop.CancelAsync();
        await Assert.That(async () => await next).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task DisposingTheContainer_EndsWatching_WithoutADisconnectedEvent()
    {
        await using var server = NewServer();
        var services = new ServiceCollection();
        services.AddSshClient("box", Endpoint(server));
        var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();
        var cancel = Timeout();
        await connections.GetClientAsync("box", cancel);
        await using var watcher = connections.WatchAsync("box", cancel).GetAsyncEnumerator(cancel);
        await Assert.That(await watcher.MoveNextAsync()).IsTrue(); // Connected

        await provider.DisposeAsync();

        await Assert.That(await watcher.MoveNextAsync()).IsFalse();
        await Assert.That(async () => await connections.WatchAsync("box", cancel).GetAsyncEnumerator(cancel).MoveNextAsync())
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Watching_AnUnknownName_Fails_AndAFakeProviderDoesNotSupportIt()
    {
        var services = new ServiceCollection();
        services.AddSshClient("box", o => o.Host = "192.0.2.1");
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();

        await Assert.That(async () => await connections.WatchAsync("other", Timeout()).GetAsyncEnumerator().MoveNextAsync())
            .Throws<InvalidOperationException>().WithMessageContaining("AddSshClient");
        ISshConnectionProvider fake = new FakeProvider();
        Assert.Throws<NotSupportedException>(() => fake.WatchAsync("box"));
    }

    /// <summary>An implementation written before WatchAsync existed: it still compiles, and watching it says it is not supported.</summary>
    private sealed class FakeProvider : ISshConnectionProvider
    {
        public Task<SshClient> GetClientAsync(string name, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    }

    /// <summary>
    /// A one-response HTTP server on a loopback port, standing for a service only the SSH server reaches: answers every request with
    /// <paramref name="body"/>.
    /// </summary>
    private static async Task ServeHttpAsync(TcpListener listener, string body, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using var socket = await listener.AcceptSocketAsync(cancellationToken);
            await using var stream = new NetworkStream(socket, ownsSocket: false);
            var request = new StringBuilder();
            var buffer = new byte[1024];
            while (!request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    break;
                }

                request.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }

            var response = $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
            socket.Shutdown(SocketShutdown.Both);
        }
    }

    [Test]
    public async Task UseSshTunnel_SendsAnHttpClientsRequestsThroughTheSharedConnection_AcrossADrop()
    {
        var web = new TcpListener(IPAddress.Loopback, 0);
        web.Start();
        using var stopWeb = new CancellationTokenSource();
        var serving = ServeHttpAsync(web, "healthy", stopWeb.Token);
        var tunnels = new ConcurrentQueue<string>();
        await using var server = NewServer(s => s.DirectTcpIp = (host, port) =>
        {
            // The SSH server resolves the name: here every destination is the local web server.
            tunnels.Enqueue($"{host}:{port}");
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect((IPEndPoint)web.LocalEndpoint);
            return new NetworkStream(socket, ownsSocket: true);
        });
        try
        {
            var services = new ServiceCollection();
            services.AddSshClient("box", Endpoint(server));
            services.AddHttpClient("internal", http => http.BaseAddress = new Uri("http://api.internal.example.com:8080/")).UseSshTunnel("box");
            await using var provider = services.BuildServiceProvider();
            var http = provider.GetRequiredService<IHttpClientFactory>().CreateClient("internal");

            await Assert.That(await http.GetStringAsync("health", Timeout())).IsEqualTo("healthy");
            await Assert.That(tunnels.ToArray()).IsEquivalentTo(["api.internal.example.com:8080"]);
            await Assert.That(server.Connections).IsEqualTo(1);

            // After a drop, the next request reconnects the shared connection and goes through the new one.
            var first = await provider.GetRequiredService<ISshConnectionProvider>().GetClientAsync("box", Timeout());
            server.DropAll();
            await WaitUntilDroppedAsync(first);
            await Assert.That(await http.GetStringAsync("health", Timeout())).IsEqualTo("healthy");
            await Assert.That(server.Connections).IsEqualTo(2);
            await Assert.That(tunnels.Count).IsEqualTo(2);
        }
        finally
        {
            await stopWeb.CancelAsync();
            web.Stop();
            try
            {
                await serving;
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                // Stopped.
            }
        }
    }

    [Test]
    public async Task UseSshTunnel_ToAnUnregisteredEndpoint_FailsWhenTheHandlerIsBuilt()
    {
        var services = new ServiceCollection();
        services.AddSshClient("box", o => o.Host = "192.0.2.1");
        services.AddHttpClient("internal").UseSshTunnel("other");
        await using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var ex = Assert.Throws<InvalidOperationException>(() => factory.CreateClient("internal"));
        await Assert.That(ex.Message).Contains("'other'");
    }
}
