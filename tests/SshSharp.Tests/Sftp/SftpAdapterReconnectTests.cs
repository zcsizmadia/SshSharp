using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using SshSharp.FileProviders;
using SshSharp.IO.Abstractions;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// <see cref="SftpFileProvider"/> and <see cref="SftpFileSystem"/> built from a session factory: one shared session, opened again
/// after the connection under it drops, never after an ordinary SFTP error; one open for concurrent callers; disposal.
/// </summary>
public class SftpAdapterReconnectTests
{
    private const string Site = FakeSftpServer.Home + "/site";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>
    /// A session factory over in-memory servers that share one file tree: each session it opens is on a connection of its own, which a
    /// test can drop as a network failure would.
    /// </summary>
    private sealed class Connections : IAsyncDisposable
    {
        private readonly HashSet<FakeSessionServer> _dropped = [];
        private readonly string _password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        private readonly List<(FakeSessionServer Server, SshClient Client)> _connections = [];
        private int _opened;

        public Connections()
        {
            Files.AddDirectory(Site);
            Files.AddFile(Site + "/index.html", "<h1>hello</h1>"u8.ToArray());
            Files.AddDirectory(Site + "/css");
            Files.AddFile(Site + "/css/site.css", "body{}"u8.ToArray());
        }

        public FakeSftpServer Files { get; } = new();

        /// <summary>How many times the factory was called.</summary>
        public int Opened => Volatile.Read(ref _opened);

        /// <summary>While set and not completed, opens wait for it.</summary>
        public TaskCompletionSource? Hold { get; set; }

        /// <summary>While set, opens fail with it (a server that is down).</summary>
        public Exception? Failure { get; set; }

        /// <summary>When set, connections send keep-alives on this clock (every 30 s, one unanswered probe ends them).</summary>
        public FakeTimeProvider? Clock { get; init; }

        public async Task<SftpClient> OpenAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _opened);
            if (Hold is { } hold)
            {
                await hold.Task.WaitAsync(cancellationToken);
            }

            if (Failure is { } failure)
            {
                throw failure;
            }

            var server = new FakeSessionServer { Password = _password };
            Files.Install(server);
            _ = server.StartAsync();
            var client = await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = _password,
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
                KeepAliveInterval = Clock is null ? null : TimeSpan.FromSeconds(30),
                KeepAliveCountMax = 1,
                TimeProvider = Clock ?? TimeProvider.System,
            }, leaveOpen: true, cancellationToken);
            lock (_connections)
            {
                _connections.Add((server, client));
            }

            return await client.OpenSftpAsync(cancellationToken);
        }

        /// <summary>Drops the newest connection: the server goes away, and the client sees its connection fail.</summary>
        public async Task DropAsync()
        {
            (FakeSessionServer Server, SshClient Client) newest;
            lock (_connections)
            {
                newest = _connections[^1];
            }

            _dropped.Add(newest.Server);
            await newest.Server.DisposeAsync();
            for (var i = 0; i < 500 && newest.Client.IsConnected; i++)
            {
                await Task.Delay(10);
            }
        }

        /// <summary>
        /// Ends the newest connection the way a dead peer does behind a live TCP connection: the server stops answering keep-alives, and
        /// the client's keep-alive fails the connection with <see cref="SshFailureReason.Timeout"/>. Needs <see cref="Clock"/>.
        /// </summary>
        public async Task TimeOutByKeepAliveAsync()
        {
            (FakeSessionServer Server, SshClient Client) newest;
            lock (_connections)
            {
                newest = _connections[^1];
            }

            newest.Server.IgnoreGlobalRequests = true;
            for (var i = 0; i < 500 && newest.Client.IsConnected; i++)
            {
                Clock!.Advance(TimeSpan.FromSeconds(30));
                await Task.Delay(10); // what the clock released is on its way
            }

            if (newest.Client.ConnectionError is not SshException { Reason: SshFailureReason.Timeout })
            {
                throw new InvalidOperationException("The connection did not time out: " + newest.Client.ConnectionError);
            }
        }

        /// <summary>Waits until the server has no SFTP session open (the client closed them).</summary>
        public async Task<int> OpenSessionsAfterSettlingAsync()
        {
            for (var i = 0; i < 500 && Files.OpenSessions > 0; i++)
            {
                await Task.Delay(10);
            }

            return Files.OpenSessions;
        }

        public async ValueTask DisposeAsync()
        {
            Files.Released.TrySetResult(); // a held session answers, and can end
            foreach (var (server, client) in _connections)
            {
                await client.DisposeAsync();
                if (!_dropped.Contains(server))
                {
                    await server.DisposeAsync();
                }
            }
        }
    }

    private static readonly SftpFileProviderOptions NoCache = new() { CacheDuration = TimeSpan.Zero };

    [Test]
    public async Task TheProvider_OpensOneSessionOnFirstUse_AndSharesIt()
    {
        await using var connections = new Connections();
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        await Assert.That(connections.Opened).IsEqualTo(0); // nothing until the first lookup

        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(provider.GetDirectoryContents("css").Exists).IsTrue();
        await Assert.That(provider.GetFileInfo("css/site.css").Exists).IsTrue();

        await Assert.That(connections.Opened).IsEqualTo(1);
        await Assert.That(connections.Files.Sessions).IsEqualTo(1);
    }

    [Test]
    public async Task TheProvider_FollowsADroppedConnection_WithoutFailingTheLookup()
    {
        await using var connections = new Connections();
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();

        await connections.DropAsync();

        // The lookup meets the dropped connection, and is tried again on a new session.
        var index = provider.GetFileInfo("index.html");
        await Assert.That(index.Exists).IsTrue();
        await using (var stream = index.CreateReadStream())
        {
            using var reader = new StreamReader(stream);
            await Assert.That(await reader.ReadToEndAsync()).IsEqualTo("<h1>hello</h1>");
        }

        await Assert.That(connections.Opened).IsEqualTo(2);
        await Assert.That(provider.GetDirectoryContents("/").Select(f => f.Name)).IsEquivalentTo(["index.html", "css"]);
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task TheProvider_KeepsItsSession_AfterOrdinarySftpErrors()
    {
        await using var connections = new Connections();
        connections.Files.DenyStat = path => path.EndsWith("/private", StringComparison.Ordinal);
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);

        await Assert.That(provider.GetFileInfo("missing.html").Exists).IsFalse();
        await Assert.That(provider.GetFileInfo("private").Exists).IsFalse();
        await Assert.That(provider.GetDirectoryContents("missing").Exists).IsFalse();
        await Assert.That(provider.GetDirectoryContents("index.html").Exists).IsFalse();
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();

        await Assert.That(connections.Opened).IsEqualTo(1);
    }

    [Test]
    public async Task TheProvider_KeepsItsSession_AfterATimeout()
    {
        await using var connections = new Connections();
        await using var ready = await connections.OpenAsync(Timeout()); // opened up front, so the short timeout only bounds requests
        var opens = 0;
        await using var provider = new SftpFileProvider(_ =>
        {
            Interlocked.Increment(ref opens);
            return Task.FromResult(ready);
        }, "site", new SftpFileProviderOptions { CacheDuration = TimeSpan.Zero, OperationTimeout = TimeSpan.FromSeconds(2) });
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();

        // One slow answer is a timeout, not a failed connection: the session stays. (The server holds every reply behind the slow one,
        // so the lookups after it may time out too, until it has gone.)
        var slow = 1;
        connections.Files.ReplyDelay = (_, _) => Interlocked.Exchange(ref slow, 0) == 1 ? TimeSpan.FromSeconds(4) : TimeSpan.Zero;
        var timeout = await Assert.That(() => provider.GetFileInfo("index.html")).Throws<SshException>();
        await Assert.That(timeout!.Reason).IsEqualTo(SshFailureReason.Timeout);

        var exists = false;
        for (var i = 0; i < 30 && !exists; i++)
        {
            try
            {
                exists = provider.GetFileInfo("index.html").Exists;
            }
            catch (SshException ex) when (ex.Reason == SshFailureReason.Timeout)
            {
                // Still behind the slow reply.
            }
        }

        await Assert.That(exists).IsTrue();
        await Assert.That(opens).IsEqualTo(1);
    }

    [Test]
    public async Task TheProvider_FollowsAConnectionTheKeepAliveDeclaredDead_DuringALookup()
    {
        // The keep-alive fails the connection with Timeout, not ConnectionClosed: the session is replaced because it has ended, whatever
        // the reason the lookup failed with.
        var time = new FakeTimeProvider();
        await using var connections = new Connections { Clock = time };
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();

        // A lookup in flight when the connection dies: the server holds it, then stops answering keep-alives.
        connections.Files.Hold = packet => packet[0] is 7 or 17; // LSTAT, STAT
        var lookup = Task.Run(() => provider.GetFileInfo("css/site.css").Exists);
        for (var i = 0; i < 500 && connections.Files.Held == 0; i++)
        {
            await Task.Delay(10);
        }

        connections.Files.Hold = null; // the next session answers
        await connections.TimeOutByKeepAliveAsync();

        await Assert.That(await lookup).IsTrue(); // tried again on a new session
        await Assert.That(connections.Opened).IsEqualTo(2);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task TheFileSystem_FollowsAConnectionTheKeepAliveDeclaredDead_WhileIdle()
    {
        var time = new FakeTimeProvider();
        await using var connections = new Connections { Clock = time };
        await using var fs = new SftpFileSystem(connections.OpenAsync);
        await Assert.That(fs.File.ReadAllText("site/index.html")).IsEqualTo("<h1>hello</h1>");

        await connections.TimeOutByKeepAliveAsync();

        // The session ended while nothing ran on it: the next call, a write included, opens a new one rather than fail on the old.
        fs.File.WriteAllText("site/after.txt", "written");
        await Assert.That(Encoding.UTF8.GetString(connections.Files.FileData(Site + "/after.txt")!)).IsEqualTo("written");
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task OneRequestsProtocolError_LeavesTheSharedSessionInUse()
    {
        // A listing that never ends is stopped with ProtocolError: that request's failure, not the session's.
        await using var connections = new Connections();
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        await using var fs = new SftpFileSystem(connections.OpenAsync);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(fs.File.Exists("site/index.html")).IsTrue();

        connections.Files.EndlessListing = true;
        await Assert.That(() => provider.GetDirectoryContents("css").ToList()).Throws<SshException>();
        await Assert.That(() => fs.Directory.GetFiles("site")).Throws<IOException>();
        connections.Files.EndlessListing = false;

        await Assert.That(provider.GetDirectoryContents("css").Select(f => f.Name)).IsEquivalentTo(["site.css"]);
        await Assert.That(fs.Directory.GetFiles("site/css").Length).IsEqualTo(1);
        await Assert.That(connections.Opened).IsEqualTo(2); // one session each, never replaced
    }

    [Test]
    public async Task ConcurrentLookups_ShareOneOpen_AtFirstUseAndAfterADrop()
    {
        await using var connections = new Connections();
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        connections.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var lookups = Enumerable.Range(0, 16).Select(i => Task.Run(() => provider.GetFileInfo(i % 2 == 0 ? "index.html" : "css").Exists)).ToArray();
        for (var i = 0; i < 500 && connections.Opened == 0; i++)
        {
            await Task.Delay(10);
        }

        await Task.Delay(100); // every lookup has had the time to ask for a session
        connections.Hold.SetResult();
        await Assert.That((await Task.WhenAll(lookups)).All(exists => exists)).IsTrue();
        await Assert.That(connections.Opened).IsEqualTo(1);

        await connections.DropAsync();
        lookups = Enumerable.Range(0, 16).Select(i => Task.Run(() => provider.GetFileInfo(i % 2 == 0 ? "index.html" : "css").Exists)).ToArray();
        await Assert.That((await Task.WhenAll(lookups)).All(exists => exists)).IsTrue();
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task AFailedOpen_FailsTheLookup_AndTheNextLookupTriesAgain()
    {
        await using var connections = new Connections();
        await using var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        connections.Failure = new SshException(SshFailureReason.ConnectFailed, "The server is down.");

        var failure = await Assert.That(() => provider.GetFileInfo("index.html")).Throws<SshException>();
        await Assert.That(failure!.Reason).IsEqualTo(SshFailureReason.ConnectFailed);
        await Assert.That(failure.InnerException).IsSameReferenceAs(connections.Failure);

        connections.Failure = null;
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task ASlowOpen_IsBoundedByTheOperationTimeout_AndTheNextLookupOpensAgain()
    {
        await using var connections = new Connections();
        await using var ready = await connections.OpenAsync(Timeout());
        var slow = 1;
        var opens = 0;
        await using var provider = new SftpFileProvider(async ct =>
        {
            Interlocked.Increment(ref opens);
            if (Volatile.Read(ref slow) == 1)
            {
                await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, ct); // a server that never answers
            }

            return ready;
        }, "site", new SftpFileProviderOptions { CacheDuration = TimeSpan.Zero, OperationTimeout = TimeSpan.FromSeconds(1) });

        var failure = await Assert.That(() => provider.GetFileInfo("index.html")).Throws<SshException>();
        await Assert.That(failure!.Reason).IsEqualTo(SshFailureReason.Timeout);

        // The lookup gave up on its own timeout, which may pass just before the open's: a lookup in between still waits for that open,
        // and fails with it. Once the open has failed, the next lookup opens again.
        Volatile.Write(ref slow, 0);
        var exists = false;
        for (var i = 0; i < 10 && !exists; i++)
        {
            try
            {
                exists = provider.GetFileInfo("index.html").Exists;
            }
            catch (SshException ex) when (ex.Reason == SshFailureReason.Timeout)
            {
                // The first open, still timing out.
            }
        }

        await Assert.That(exists).IsTrue();
        await Assert.That(opens).IsEqualTo(2);
    }

    [Test]
    public async Task DisposingTheProvider_ClosesTheSessionsItOpened()
    {
        await using var connections = new Connections();
        var provider = new SftpFileProvider(connections.OpenAsync, "site", NoCache);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(connections.Files.OpenSessions).IsEqualTo(1);

        provider.Dispose();
        await provider.DisposeAsync(); // twice is harmless

        await Assert.That(await connections.OpenSessionsAfterSettlingAsync()).IsEqualTo(0);
        await Assert.That(() => provider.GetFileInfo("other.html")).Throws<ObjectDisposedException>();
        await Assert.That(connections.Opened).IsEqualTo(1);
    }

    [Test]
    public async Task DisposingAProviderOverOneSession_LeavesTheSessionToItsOwner()
    {
        await using var connections = new Connections();
        await using var sftp = await connections.OpenAsync(Timeout());
        var provider = new SftpFileProvider(sftp, "site", NoCache);

        await provider.DisposeAsync();

        // As before the provider was disposable: the session is the caller's, and the provider keeps working with it.
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();
        await Assert.That(await sftp.ExistsAsync(Site + "/index.html", Timeout())).IsTrue();
    }

    [Test]
    public async Task AProviderOverOneSession_DoesNotReconnect()
    {
        await using var connections = new Connections();
        await using var sftp = await connections.OpenAsync(Timeout());
        var provider = new SftpFileProvider(sftp, "site", NoCache);
        await Assert.That(provider.GetFileInfo("index.html").Exists).IsTrue();

        await connections.DropAsync();

        await Assert.That(() => provider.GetFileInfo("index.html")).Throws<SshException>();
        await Assert.That(connections.Opened).IsEqualTo(1);
    }

    [Test]
    public async Task TheFileSystem_FollowsADroppedConnection()
    {
        await using var connections = new Connections();
        await using var fs = new SftpFileSystem(connections.OpenAsync);
        await Assert.That(connections.Opened).IsEqualTo(0);
        await Assert.That(fs.File.ReadAllText("site/index.html")).IsEqualTo("<h1>hello</h1>");

        // Reads are tried again on a new session.
        await connections.DropAsync();
        await Assert.That(fs.File.Exists("site/index.html")).IsTrue();
        await Assert.That(connections.Opened).IsEqualTo(2);

        await connections.DropAsync();
        await Assert.That(await fs.File.ReadAllTextAsync("site/css/site.css", Timeout())).IsEqualTo("body{}");
        await Assert.That(connections.Opened).IsEqualTo(3);

        await connections.DropAsync();
        await Assert.That(fs.Directory.GetFiles("site").Select(f => fs.Path.GetFileName(f)!)).IsEquivalentTo(["index.html"]);
        await Assert.That(connections.Opened).IsEqualTo(4);
    }

    [Test]
    public async Task TheFileSystem_DoesNotRepeatAWrite_ThatMetADroppedConnection()
    {
        await using var connections = new Connections();
        await using var fs = new SftpFileSystem(connections.OpenAsync);
        fs.File.WriteAllText("site/a.txt", "first");

        // The connection drops while the write is in flight (a drop noticed before a call starts just means a new session for it).
        connections.Files.Hold = packet => packet[0] == 6; // WRITE
        var write = Task.Run(() => fs.File.WriteAllBytes("site/b.txt", "lost"u8.ToArray()));
        for (var i = 0; i < 500 && connections.Files.Held == 0; i++)
        {
            await Task.Delay(10);
        }

        connections.Files.Hold = null;
        await connections.DropAsync();

        // The server may have done it before the connection dropped, so the write fails rather than running twice.
        await Assert.That(async () => await write).Throws<IOException>();
        await Assert.That(connections.Opened).IsEqualTo(1);

        // The next call opens a new session.
        fs.File.AppendAllText("site/a.txt", "+second");
        fs.File.WriteAllBytes("site/b.txt", "kept"u8.ToArray());
        await Assert.That(Encoding.UTF8.GetString(connections.Files.FileData(Site + "/a.txt")!)).IsEqualTo("first+second");
        await Assert.That(Encoding.UTF8.GetString(connections.Files.FileData(Site + "/b.txt")!)).IsEqualTo("kept");
        await Assert.That(connections.Opened).IsEqualTo(2);
    }

    [Test]
    public async Task TheFileSystem_KeepsItsSession_AfterOrdinarySftpErrors()
    {
        await using var connections = new Connections();
        await using var fs = new SftpFileSystem(connections.OpenAsync);

        await Assert.That(() => fs.File.ReadAllText("site/missing.txt")).Throws<FileNotFoundException>();
        await Assert.That(() => fs.Directory.Delete("site/missing")).Throws<DirectoryNotFoundException>();
        await Assert.That(() => fs.Directory.CreateDirectory("site/index.html")).Throws<IOException>();
        await Assert.That(fs.File.Exists("site/missing.txt")).IsFalse();

        await Assert.That(connections.Opened).IsEqualTo(1);
    }

    [Test]
    public async Task TheFileSystem_ReportsAFailedOpen_AsAnIOException()
    {
        await using var connections = new Connections();
        await using var fs = new SftpFileSystem(connections.OpenAsync);
        connections.Failure = new SshException(SshFailureReason.AuthenticationFailed, "Denied.");

        var failure = await Assert.That(() => fs.File.ReadAllText("site/index.html")).Throws<IOException>();
        await Assert.That(failure!.InnerException).IsTypeOf<SshException>();
        await Assert.That(async () => await fs.File.ReadAllTextAsync("site/index.html", Timeout())).Throws<IOException>();

        connections.Failure = null;
        await Assert.That(fs.File.ReadAllText("site/index.html")).IsEqualTo("<h1>hello</h1>");
    }

    [Test]
    public async Task DisposingTheFileSystem_ClosesTheSessionItOpened_AndStreamsOnItFail()
    {
        await using var connections = new Connections();
        var fs = new SftpFileSystem(connections.OpenAsync);
        var stream = fs.File.OpenRead("site/index.html");

        await fs.DisposeAsync();

        await Assert.That(await connections.OpenSessionsAfterSettlingAsync()).IsEqualTo(0);
        await Assert.That(() => fs.File.ReadAllText("site/index.html")).Throws<ObjectDisposedException>();
        await Assert.That(() => stream.ReadByte()).Throws<IOException>();
        await stream.DisposeAsync();
    }

    [Test]
    public async Task DisposingAFileSystemOverOneSession_LeavesTheSessionToItsOwner()
    {
        await using var connections = new Connections();
        await using var sftp = await connections.OpenAsync(Timeout());
        var fs = new SftpFileSystem(sftp);

        fs.Dispose();

        await Assert.That(fs.File.ReadAllText("site/index.html")).IsEqualTo("<h1>hello</h1>");
    }

    [Test]
    public async Task ANullFactory_IsRejected()
    {
        await Assert.That(() => new SftpFileSystem((Func<CancellationToken, Task<SftpClient>>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => new SftpFileSystem((SftpClient)null!)).Throws<ArgumentNullException>();
    }
}
