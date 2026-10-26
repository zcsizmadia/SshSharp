using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Extensions.DependencyInjection;
using SshSharp.Scp;
using SshSharp.Sftp;
using SshSharp.Tests.DependencyInjection;
using SshSharp.Tests.Protocol;
using SshSharp.Tests.Scp;
using SshSharp.Tests.Sftp;

namespace SshSharp.Tests;

/// <summary>
/// The authentication span, the SFTP and SCP transfer spans and byte counters, the forwarding counters, the keep-alive round trip and the
/// connection provider's reconnections (#368); and that none of them records a path, a user name or a host name. Other tests record
/// into the same instruments in parallel, so the metrics are looked for among theirs; the spans are isolated by a root span of the test's.
/// </summary>
public sealed class SshTelemetryTests : IDisposable
{
    private const string User = "telemetry-user";

    private readonly string _dir = Directory.CreateTempSubdirectory("sshsharp-telemetry").FullName;
    private readonly string _password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private SshClientOptions Options(string? password = null, FakeTimeProvider? time = null) => new()
    {
        UserName = User,
        Password = password ?? _password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        KeepAliveInterval = time is null ? TimeSpan.Zero : TimeSpan.FromSeconds(30),
        TimeProvider = time ?? TimeProvider.System,
    };

    private async Task<SshClient> ConnectAsync(FakeSessionServer server, FakeTimeProvider? time = null)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, Options(time: time), leaveOpen: true, Timeout());
    }

    /// <summary>What SshSharp's instruments record while it listens.</summary>
    private sealed class Measurements : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly List<(string Instrument, double Value, KeyValuePair<string, object?>[] Tags)> _seen = [];

        public Measurements()
        {
            _listener.InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == SshTelemetry.SourceName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i.Name, v, t));
            _listener.SetMeasurementEventCallback<int>((i, v, t, _) => Add(i.Name, v, t));
            _listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i.Name, v, t));
            _listener.Start();
        }

        private void Add(string name, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var copy = tags.ToArray();
            lock (_seen)
            {
                _seen.Add((name, value, copy));
            }
        }

        public List<(string Instrument, double Value, KeyValuePair<string, object?>[] Tags)> Of(string instrument)
        {
            lock (_seen)
            {
                return [.. _seen.Where(m => m.Instrument == instrument)];
            }
        }

        public static bool Has(KeyValuePair<string, object?>[] tags, string key, string value) =>
            tags.Any(t => t.Key == key && (string?)t.Value == value);

        public void Dispose() => _listener.Dispose();
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
        {
            await Task.Delay(10);
        }
    }

    /// <summary>No tag of <paramref name="spans"/> holds any of <paramref name="secrets"/>.</summary>
    private static async Task AssertNoneRecordedAsync(IEnumerable<Activity> spans, params string[] secrets)
    {
        foreach (var span in spans)
        {
            foreach (var tag in span.TagObjects)
            {
                var text = tag.Value?.ToString() ?? "";
                await Assert.That(secrets.Any(s => text.Contains(s, StringComparison.OrdinalIgnoreCase))).IsFalse();
            }
        }
    }

    // ---- authentication ----

    [Test]
    public async Task Authentication_IsASpanInsideTheConnect_WithTheMethodAndAttempts()
    {
        SshSpans.Listen();
        using var root = new Activity("telemetry-auth").Start();
        await using var server = new FakeSessionServer { UserName = User, Password = _password };
        await using (await ConnectAsync(server))
        {
        }

        var spans = SshSpans.InTrace(root.TraceId);
        var connect = spans.Single(a => a.OperationName == "SshSharp.Connect");
        var auth = spans.Single(a => a.OperationName == "SshSharp.Authenticate");
        await Assert.That(auth.ParentSpanId).IsEqualTo(connect.SpanId);
        await Assert.That(auth.GetTagItem("ssh.auth.method")).IsEqualTo("password");
        await Assert.That(auth.GetTagItem("ssh.auth.attempts")).IsEqualTo(1); // "none" asks for the methods and is not counted
        await Assert.That(auth.GetTagItem("error.type")).IsNull();
        await Assert.That(auth.Status).IsEqualTo(ActivityStatusCode.Unset);
        await AssertNoneRecordedAsync(spans, "telemetry-user", _password);
    }

    [Test]
    public async Task AFailedAuthentication_IsAnErrorSpan_WithItsAttempts()
    {
        SshSpans.Listen();
        using var root = new Activity("telemetry-auth-failed").Start();
        await using var server = new FakeSessionServer { UserName = User, Password = _password };
        _ = server.StartAsync();
        var wrong = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        await Assert.That(async () => await SshClient.ConnectAsync(server.ClientStream, Options(password: wrong), true, Timeout())).Throws<SshAuthenticationException>();

        var auth = SshSpans.InTrace(root.TraceId).Single(a => a.OperationName == "SshSharp.Authenticate");
        await Assert.That(auth.Status).IsEqualTo(ActivityStatusCode.Error);
        await Assert.That(auth.GetTagItem("error.type")).IsEqualTo(nameof(SshFailureReason.AuthenticationFailed));
        await Assert.That(auth.GetTagItem("ssh.auth.method")).IsNull();
        await Assert.That((int)auth.GetTagItem("ssh.auth.attempts")!).IsGreaterThanOrEqualTo(1);
        await AssertNoneRecordedAsync([auth], "telemetry-user", wrong);
    }

    // ---- SFTP ----

    private async Task<(FakeSessionServer Ssh, SshClient Client, SftpClient Sftp)> StartSftpAsync(FakeSftpServer files)
    {
        var ssh = new FakeSessionServer { UserName = User, Password = _password };
        files.Install(ssh);
        var client = await ConnectAsync(ssh);
        return (ssh, client, await client.OpenSftpAsync(Timeout()));
    }

    private static async Task StopAsync((FakeSessionServer Ssh, SshClient Client, SftpClient Sftp) rig)
    {
        await rig.Sftp.DisposeAsync();
        await rig.Client.DisposeAsync();
        await rig.Ssh.DisposeAsync();
    }

    [Test]
    public async Task SftpTransfers_AreSpans_WithTheirBytes_AndTheBytesAreCounted()
    {
        SshSpans.Listen();
        using var measurements = new Measurements();
        var data = RandomNumberGenerator.GetBytes(150_001);
        var files = new FakeSftpServer();
        files.AddFile(FakeSftpServer.Home + "/secret-name.bin", data);
        var rig = await StartSftpAsync(files);
        using var root = new Activity("telemetry-sftp").Start();
        try
        {
            var local = Path.Combine(_dir, "secret-name.bin");
            await Assert.That(await rig.Sftp.DownloadFileAsync("secret-name.bin", local, cancellationToken: Timeout())).IsEqualTo(data.Length);
            await Assert.That(await rig.Sftp.UploadFileAsync(local, "secret-copy.bin", cancellationToken: Timeout())).IsEqualTo(data.Length);
            await rig.Sftp.UploadAsync(new MemoryStream(data, 0, 1000), "secret-stream.bin", cancellationToken: Timeout());
            await rig.Sftp.DownloadAsync("secret-stream.bin", new MemoryStream(), cancellationToken: Timeout());
        }
        finally
        {
            await StopAsync(rig);
        }

        var spans = SshSpans.InTrace(root.TraceId);
        var downloads = spans.Where(a => a.OperationName == "SshSharp.Sftp.Download").Select(a => a.GetTagItem("ssh.sftp.bytes")).ToList();
        var uploads = spans.Where(a => a.OperationName == "SshSharp.Sftp.Upload").Select(a => a.GetTagItem("ssh.sftp.bytes")).ToList();
        await Assert.That(downloads).IsEquivalentTo(new object?[] { (long)data.Length, 1000L });

        // UploadFileAsync is one span, not one with an UploadAsync span inside.
        await Assert.That(uploads).IsEquivalentTo(new object?[] { (long)data.Length, 1000L });
        await AssertNoneRecordedAsync(spans, TestSecrets.Password, _dir, "telemetry-user");

        // Others transfer in parallel: at least these bytes, each counted once per direction.
        double Sum(string direction) => measurements.Of("sshsharp.sftp.bytes").Where(m => Measurements.Has(m.Tags, "ssh.sftp.direction", direction)).Sum(m => m.Value);
        await Assert.That(Sum("download")).IsGreaterThanOrEqualTo(data.Length + 1000);
        await Assert.That(Sum("upload")).IsGreaterThanOrEqualTo(data.Length + 1000);
        await Assert.That(measurements.Of("sshsharp.sftp.bytes").All(m => m.Tags.Length == 1)).IsTrue();
    }

    [Test]
    public async Task ADirectoryTransfer_IsASpan_WithAFileSpanInsideForEachFile()
    {
        SshSpans.Listen();
        var files = new FakeSftpServer();
        files.AddDirectory(FakeSftpServer.Home + "/tree");
        files.AddFile(FakeSftpServer.Home + "/tree/a.txt", "alpha"u8.ToArray());
        files.AddDirectory(FakeSftpServer.Home + "/tree/sub");
        files.AddFile(FakeSftpServer.Home + "/tree/sub/b.bin", new byte[70_000]);
        var rig = await StartSftpAsync(files);
        using var root = new Activity("telemetry-sftp-dir").Start();
        try
        {
            await rig.Sftp.DownloadDirectoryAsync("tree", Path.Combine(_dir, "down"), cancellationToken: Timeout());
            await rig.Sftp.UploadDirectoryAsync(Path.Combine(_dir, "down"), "up", cancellationToken: Timeout());
        }
        finally
        {
            await StopAsync(rig);
        }

        var spans = SshSpans.InTrace(root.TraceId);
        foreach (var (directory, file) in new[] { ("SshSharp.Sftp.DownloadDirectory", "SshSharp.Sftp.Download"), ("SshSharp.Sftp.UploadDirectory", "SshSharp.Sftp.Upload") })
        {
            var tree = spans.Single(a => a.OperationName == directory);
            await Assert.That(tree.GetTagItem("ssh.sftp.bytes")).IsEqualTo(70_005L);
            await Assert.That(tree.GetTagItem("ssh.sftp.files")).IsEqualTo(2);
            await Assert.That(tree.GetTagItem("ssh.sftp.directories")).IsEqualTo(1);
            await Assert.That(spans.Count(a => a.OperationName == file && a.ParentSpanId == tree.SpanId)).IsEqualTo(2);
        }

        await AssertNoneRecordedAsync(spans, "tree", "a.txt", "b.bin", _dir);
    }

    [Test]
    public async Task AFailedTransfer_IsAnErrorSpan_WithoutThePath()
    {
        SshSpans.Listen();
        var rig = await StartSftpAsync(new FakeSftpServer());
        using var root = new Activity("telemetry-sftp-failed").Start();
        try
        {
            await Assert.That(async () => await rig.Sftp.DownloadAsync("missing-secret.bin", new MemoryStream(), cancellationToken: Timeout())).Throws<SftpException>();
        }
        finally
        {
            await StopAsync(rig);
        }

        var download = SshSpans.InTrace(root.TraceId).Single(a => a.OperationName == "SshSharp.Sftp.Download");
        await Assert.That(download.Status).IsEqualTo(ActivityStatusCode.Error);
        await Assert.That(download.GetTagItem("error.type")).IsEqualTo(nameof(SshFailureReason.SftpFailed));
        await Assert.That(download.GetTagItem("ssh.sftp.bytes")).IsNull();
        await AssertNoneRecordedAsync([download], "missing-secret");
    }

    // ---- SCP (#381) ----

    /// <summary>A client of a fake server that runs <paramref name="scp"/> (a sink or source script of <see cref="ScpTests"/>) for each command.</summary>
    private async Task<(FakeSessionServer Ssh, SshClient Client)> StartScpAsync(Func<ExecScript, Task> scp)
    {
        var ssh = new FakeSessionServer { UserName = User, Password = _password, OnExec = scp };
        return (ssh, await ConnectAsync(ssh));
    }

    private static async Task StopAsync((FakeSessionServer Ssh, SshClient Client) rig)
    {
        await rig.Client.DisposeAsync();
        await rig.Ssh.DisposeAsync();
    }

    [Test]
    public async Task ScpTransfers_AreSpans_WithTheirBytes_AndTheBytesAreCounted()
    {
        SshSpans.Listen();
        using var measurements = new Measurements();
        var content = new string('x', 150_001);
        var local = Path.Combine(_dir, "secret-name.bin");
        await File.WriteAllTextAsync(local, content);
        var sink = await StartScpAsync(ScpTests.Sink([], []));
        var source = await StartScpAsync(ScpTests.Source(ScpTests.File("secret-name.bin", content)));
        using var root = new Activity("telemetry-scp").Start();
        try
        {
            await sink.Client.UploadFileAsync(local, "/srv/secret-copy.bin", cancellationToken: Timeout());
            await sink.Client.UploadAsync(new MemoryStream(new byte[1000]), "/srv/secret-stream.bin", cancellationToken: Timeout());
            await source.Client.DownloadFileAsync("/srv/secret-name.bin", Path.Combine(_dir, "secret-download.bin"), cancellationToken: Timeout());
            await source.Client.DownloadAsync("/srv/secret-name.bin", new MemoryStream(), cancellationToken: Timeout());
        }
        finally
        {
            await StopAsync(sink);
            await StopAsync(source);
        }

        var spans = SshSpans.InTrace(root.TraceId);
        var uploads = spans.Where(a => a.OperationName == "SshSharp.Scp.Upload").Select(a => a.GetTagItem("ssh.scp.bytes")).ToList();
        var downloads = spans.Where(a => a.OperationName == "SshSharp.Scp.Download").Select(a => a.GetTagItem("ssh.scp.bytes")).ToList();
        await Assert.That(uploads).IsEquivalentTo(new object?[] { (long)content.Length, 1000L });
        await Assert.That(downloads).IsEquivalentTo(new object?[] { (long)content.Length, (long)content.Length });

        // A single-file transfer has no file or directory counts: they are the directory spans' tags, as for SFTP.
        await Assert.That(spans.Any(a => a.GetTagItem("ssh.scp.files") is not null || a.GetTagItem("ssh.scp.directories") is not null)).IsFalse();
        await AssertNoneRecordedAsync(spans, TestSecrets.Password, "/srv", _dir, "telemetry-user");

        // Others transfer in parallel: at least these bytes, each counted once per direction.
        double Sum(string direction) => measurements.Of("sshsharp.scp.bytes").Where(m => Measurements.Has(m.Tags, "ssh.scp.direction", direction)).Sum(m => m.Value);
        await Assert.That(Sum("upload")).IsGreaterThanOrEqualTo(content.Length + 1000);
        await Assert.That(Sum("download")).IsGreaterThanOrEqualTo(2 * content.Length);
        await Assert.That(measurements.Of("sshsharp.scp.bytes").All(m => m.Tags.Length == 1)).IsTrue();
    }

    [Test]
    public async Task AnScpDirectoryTransfer_IsOneSpan_WithItsBytesFilesAndDirectories()
    {
        SshSpans.Listen();
        var tree = Directory.CreateDirectory(Path.Combine(_dir, "tree"));
        await File.WriteAllTextAsync(Path.Combine(tree.FullName, "a.txt"), "alpha");
        Directory.CreateDirectory(Path.Combine(tree.FullName, "sub"));
        await File.WriteAllBytesAsync(Path.Combine(tree.FullName, "sub", "b.bin"), new byte[70_000]);
        var sink = await StartScpAsync(ScpTests.Sink([], []));
        var source = await StartScpAsync(ScpTests.Source([
            ScpTests.Text("D0755 0 tree\n"), .. ScpTests.File("a.txt", "alpha"),
            ScpTests.Text("D0755 0 sub\n"), .. ScpTests.File("b.bin", new string('\0', 70_000)), ScpTests.Text("E\n"),
            ScpTests.Text("E\n")]));
        using var root = new Activity("telemetry-scp-dir").Start();
        try
        {
            await sink.Client.UploadDirectoryAsync(tree.FullName, "/srv/up", cancellationToken: Timeout());
            await source.Client.DownloadDirectoryAsync("/srv/tree", Path.Combine(_dir, "down"), cancellationToken: Timeout());
        }
        finally
        {
            await StopAsync(sink);
            await StopAsync(source);
        }

        var spans = SshSpans.InTrace(root.TraceId);
        foreach (var name in new[] { "SshSharp.Scp.UploadDirectory", "SshSharp.Scp.DownloadDirectory" })
        {
            var span = spans.Single(a => a.OperationName == name);
            await Assert.That(span.GetTagItem("ssh.scp.bytes")).IsEqualTo(70_005L);
            await Assert.That(span.GetTagItem("ssh.scp.files")).IsEqualTo(2);
            await Assert.That(span.GetTagItem("ssh.scp.directories")).IsEqualTo(1); // below the top one, as SftpTransferSummary counts
        }

        // One scp run moves the whole tree, so there are no file spans inside.
        await Assert.That(spans.Count(a => a.OperationName is "SshSharp.Scp.Upload" or "SshSharp.Scp.Download")).IsEqualTo(0);
        await AssertNoneRecordedAsync(spans, "tree", "a.txt", "b.bin", "/srv", _dir);
    }

    [Test]
    public async Task AFailedScpTransfer_IsAnErrorSpan_WithoutThePath()
    {
        SshSpans.Listen();
        var refused = await StartScpAsync(ScpTests.Sink([], [], refuseWith: "scp: /root/missing-secret: Permission denied"));
        using var root = new Activity("telemetry-scp-failed").Start();
        try
        {
            await Assert.That(async () => await refused.Client.UploadAsync(new MemoryStream(new byte[10]), "/root/missing-secret", cancellationToken: Timeout())).Throws<SshException>();
        }
        finally
        {
            await StopAsync(refused);
        }

        var upload = SshSpans.InTrace(root.TraceId).Single(a => a.OperationName == "SshSharp.Scp.Upload");
        await Assert.That(upload.Status).IsEqualTo(ActivityStatusCode.Error);
        await Assert.That(upload.GetTagItem("error.type")).IsEqualTo(nameof(SshFailureReason.TransferFailed));
        await Assert.That(upload.GetTagItem("ssh.scp.bytes")).IsNull();
        await AssertNoneRecordedAsync([upload], "missing-secret", "/root");
    }

    // ---- forwarding ----

    /// <summary>A service at the far end of the fake server: answers what it read, then hangs up.</summary>
    private static DuplexStream EchoService()
    {
        var (near, far) = DuplexStream.CreatePair();
        _ = Task.Run(async () =>
        {
            using var buffer = new MemoryStream();
            await far.CopyToAsync(buffer);
            await far.WriteAsync(buffer.ToArray());
            await far.DisposeAsync();
        });
        return near;
    }

    private static async Task ExchangeAsync(IPEndPoint endPoint)
    {
        using var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(endPoint, Timeout());
        var buffer = new byte[64];
        try
        {
            // The reset of a refused connection can arrive before the shutdown as well as during the read.
            await socket.SendAsync("ping"u8.ToArray(), SocketFlags.None, Timeout());
            socket.Shutdown(SocketShutdown.Send);
            while (await socket.ReceiveAsync(buffer, SocketFlags.None, Timeout()) > 0)
            {
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
        {
            // A refused connection is closed with what it sent unread, which can reset it (as with ssh -L).
        }
    }

    [Test]
    public async Task LocalForwarding_CountsOpenedAndFailedConnections_AndTheActiveOnes()
    {
        using var measurements = new Measurements();
        var refuse = true;
        await using var server = new FakeSessionServer { UserName = User, Password = _password, DirectTcpIp = (_, _) => refuse ? null : EchoService() };
        await using var client = await ConnectAsync(server);
        await using (var forwarder = await client.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), "service.example.com", 7, Timeout()))
        {
            await ExchangeAsync(forwarder.LocalEndPoint); // refused by the server: the local connection is closed
            refuse = false;
            await ExchangeAsync(forwarder.LocalEndPoint);
            await WaitUntilAsync(() => forwarder.ActiveConnections == 0);
        }

        bool Counted(string result) => measurements.Of("sshsharp.forwarding.connections")
            .Any(m => Measurements.Has(m.Tags, "ssh.forwarding.type", "local") && Measurements.Has(m.Tags, "result", result));
        await Assert.That(Counted("opened")).IsTrue();
        await Assert.That(Counted("failed")).IsTrue();
        var active = measurements.Of("sshsharp.forwarding.active").Where(m => Measurements.Has(m.Tags, "ssh.forwarding.type", "local")).ToList();
        await Assert.That(active.Any(m => m.Value == 1)).IsTrue();
        await Assert.That(active.Any(m => m.Value == -1)).IsTrue();

        // The type is all: no address, port or host name.
        await Assert.That(measurements.Of("sshsharp.forwarding.connections").Concat(measurements.Of("sshsharp.forwarding.active"))
            .All(m => m.Tags.All(t => t.Key is "ssh.forwarding.type" or "result"))).IsTrue();
    }

    [Test]
    public async Task RemoteForwarding_CountsOpenedAndFailedConnections()
    {
        using var measurements = new Measurements();
        using var service = new TcpListener(IPAddress.Loopback, 0);
        service.Start();
        var servicePort = ((IPEndPoint)service.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            using var accepted = await service.AcceptSocketAsync();
            var buffer = new byte[64];
            while (await accepted.ReceiveAsync(buffer, SocketFlags.None) > 0)
            {
            }
        });

        // A port nothing listens on: the forwarded connection fails here.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var deadPort = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        await using var server = new FakeSessionServer { UserName = User, Password = _password };
        await using var client = await ConnectAsync(server);
        await using (var working = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", servicePort, Timeout()))
        {
            var remote = await server.ConnectForwardedAsync(working.RemotePort);
            await using (remote!)
            {
                ((DuplexStream)remote!).CloseWrite();
                await remote!.CopyToAsync(Stream.Null, Timeout());
            }

            await WaitUntilAsync(() => working.ActiveConnections == 0);
        }

        await using (var broken = await client.ForwardRemotePortAsync("localhost", 0, "127.0.0.1", deadPort, Timeout()))
        {
            var remote = await server.ConnectForwardedAsync(broken.RemotePort);
            await using (remote!)
            {
                await remote!.CopyToAsync(Stream.Null, Timeout()); // closed by the client when its connection fails
            }

            await WaitUntilAsync(() => broken.ActiveConnections == 0);
        }

        bool Counted(string result) => measurements.Of("sshsharp.forwarding.connections")
            .Any(m => Measurements.Has(m.Tags, "ssh.forwarding.type", "remote") && Measurements.Has(m.Tags, "result", result));
        await Assert.That(Counted("opened")).IsTrue();
        await Assert.That(Counted("failed")).IsTrue();
    }

    // ---- keep-alive ----

    [Test]
    [Arguments(false)] // keepalive@openssh.com global requests
    [Arguments(true)] // transport pings
    public async Task KeepAliveRoundTrips_AreMeasured(bool pings)
    {
        using var measurements = new Measurements();
        var time = new FakeTimeProvider();
        var extensions = pings ? new Dictionary<string, string> { ["ping@openssh.com"] = "0" } : [];
        await using var server = new FakeSessionServer(new FakeServerOptions { ExtraExtensions = extensions }) { UserName = User, Password = _password };
        await using var client = await ConnectAsync(server, time);

        // The keep-alive loop starts on the thread pool: advance until a probe has been answered.
        for (var i = 0; i < 50 && measurements.Of("sshsharp.keep_alive.round_trip_time").Count == 0; i++)
        {
            time.Advance(TimeSpan.FromSeconds(30));
            await Task.Delay(50);
        }

        await Assert.That(measurements.Of("sshsharp.keep_alive.round_trip_time").Any(m => m.Value >= 0 && m.Tags.Length == 0)).IsTrue();
        await Assert.That(client.IsConnected).IsTrue();
    }

    // ---- the connection provider ----

    [Test]
    public async Task TheConnectionProvider_CountsReconnections_AndFailedOnes()
    {
        using var measurements = new Measurements();
        var server = new TcpFakeSshServer { Password = _password };
        var services = new ServiceCollection();
        services.AddSshClient("telemetry-box", o =>
        {
            o.Host = "127.0.0.1";
            o.Port = server.Port;
            o.UserName = "tester";
            o.Password = _password;
            o.HostKeyFingerprints = [server.HostKeyFingerprint];
            o.ReconnectDelay = TimeSpan.FromMilliseconds(1);
            o.MaxReconnectDelay = TimeSpan.FromMilliseconds(1);
        });
        await using var provider = services.BuildServiceProvider();
        var connections = provider.GetRequiredService<ISshConnectionProvider>();
        try
        {
            var first = await connections.GetClientAsync("telemetry-box", Timeout());
            server.DropAll();
            await WaitUntilAsync(() => !first.IsConnected);
            var second = await connections.GetClientAsync("telemetry-box", Timeout());
            await Assert.That(ReferenceEquals(first, second)).IsFalse();

            // The server goes away for good: the next reconnection fails.
            server.DropAll();
            await WaitUntilAsync(() => !second.IsConnected);
        }
        finally
        {
            await server.DisposeAsync();
        }

        await Task.Delay(10); // past the reconnect delay
        await Assert.That(async () => await connections.GetClientAsync("telemetry-box", Timeout())).Throws<Exception>();

        var reconnects = measurements.Of("sshsharp.connection_provider.reconnects");
        await Assert.That(reconnects.Any(m => Measurements.Has(m.Tags, "result", "success") && m.Tags.Length == 1)).IsTrue();
        await Assert.That(reconnects.Any(m => Measurements.Has(m.Tags, "result", "error") && m.Tags.Any(t => t.Key == "error.type"))).IsTrue();
        await Assert.That(reconnects.SelectMany(m => m.Tags).Any(t => t.Value?.ToString()?.Contains("telemetry-box", StringComparison.Ordinal) == true)).IsFalse();
    }
}
