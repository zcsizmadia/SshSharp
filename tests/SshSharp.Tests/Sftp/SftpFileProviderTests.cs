using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using SshSharp.FileProviders;
using SshSharp.Sftp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary><see cref="SftpFileProvider"/>: an IFileProvider over SFTP, against the in-memory server.</summary>
public class SftpFileProviderTests
{
    private const string Site = FakeSftpServer.Home + "/site";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class Rig : IAsyncDisposable
    {
        public FakeSessionServer Ssh { get; } = new();

        public FakeSftpServer Files { get; } = new();

        public SshClient Client { get; private set; } = null!;

        public SftpClient Sftp { get; private set; } = null!;

        public static async Task<Rig> StartAsync()
        {
            var rig = new Rig();
            rig.Files.AddDirectory(Site);
            rig.Files.AddFile(Site + "/index.html", "<h1>hello</h1>"u8.ToArray(), modifyTime: 1_650_000_000);
            rig.Files.AddDirectory(Site + "/css");
            rig.Files.AddFile(Site + "/css/site.css", "body{}"u8.ToArray());
            rig.Files.AddFile(Site + "/appsettings.json", """{ "Greeting": "from the server", "Limits": { "Max": 42 } }"""u8.ToArray());
            rig.Files.AddLink(Site + "/latest.html", "index.html");
            rig.Files.AddLink(Site + "/dangling", "nowhere");
            rig.Files.AddFile(FakeSftpServer.Home + "/secret.txt", "outside the root"u8.ToArray());
            rig.Files.Install(rig.Ssh);
            _ = rig.Ssh.StartAsync();
            rig.Client = await SshClient.ConnectAsync(rig.Ssh.ClientStream, new SshClientOptions
            {
                UserName = "tester",
                Password = "secret",
                HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
            }, leaveOpen: true, Timeout());
            rig.Sftp = await rig.Client.OpenSftpAsync(Timeout());
            return rig;
        }

        public int Requests
        {
            get
            {
                lock (Files.Requests)
                {
                    return Files.Requests.Count;
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Sftp.DisposeAsync();
            await Client.DisposeAsync();
            await Ssh.DisposeAsync();
        }
    }

    [Test]
    public async Task Files_AndDirectories_AreDescribed()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");

        var index = provider.GetFileInfo("/index.html");
        await Assert.That(index.Exists).IsTrue();
        await Assert.That(index.Name).IsEqualTo("index.html");
        await Assert.That(index.Length).IsEqualTo(14L);
        await Assert.That(index.IsDirectory).IsFalse();
        await Assert.That(index.PhysicalPath).IsNull();
        await Assert.That(index.LastModified).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1_650_000_000));

        var css = provider.GetFileInfo("css");
        await Assert.That(css.Exists).IsTrue();
        await Assert.That(css.IsDirectory).IsTrue();
        await Assert.That(css.Length).IsEqualTo(-1L);
        await Assert.That(() => css.CreateReadStream()).Throws<InvalidOperationException>();

        await Assert.That(provider.GetFileInfo("css\\site.css").Exists).IsTrue(); // either separator
        await Assert.That(provider.GetFileInfo("./css//site.css").Exists).IsTrue();
        await Assert.That(provider.GetFileInfo("missing.html").Exists).IsFalse();
        await Assert.That(provider.GetFileInfo("latest.html").Length).IsEqualTo(14L); // a link is followed
        await Assert.That(provider.GetFileInfo("").IsDirectory).IsTrue();
    }

    [Test]
    [Arguments("../secret.txt")]
    [Arguments("css/../../secret.txt")]
    [Arguments("..\\secret.txt")]
    [Arguments("/../secret.txt")]
    [Arguments("a\0b")]
    public async Task PathsThatLeaveTheRoot_DoNotExist_WithoutAskingTheServer(string subpath)
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");
        var before = rig.Requests;

        await Assert.That(provider.GetFileInfo(subpath).Exists).IsFalse();
        await Assert.That(provider.GetDirectoryContents(subpath).Exists).IsFalse();

        await Assert.That(rig.Requests).IsEqualTo(before);
    }

    [Test]
    public async Task DirectoryContents_ListTheEntries_FollowingLinksAndLeavingOutDanglingOnes()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");

        var contents = provider.GetDirectoryContents("/");

        await Assert.That(contents.Exists).IsTrue();
        await Assert.That(contents.Select(f => f.Name)).IsEquivalentTo(["index.html", "css", "appsettings.json", "latest.html"]);
        await Assert.That(contents.Single(f => f.Name == "css").IsDirectory).IsTrue();
        await Assert.That(contents.Single(f => f.Name == "latest.html").Length).IsEqualTo(14L);
        await Assert.That(provider.GetDirectoryContents("missing").Exists).IsFalse();
        await Assert.That(provider.GetDirectoryContents("index.html").Exists).IsFalse();
    }

    [Test]
    public async Task Streams_ReadSynchronouslyAndAsynchronously()
    {
        await using var rig = await Rig.StartAsync();
        var data = RandomNumberGenerator.GetBytes(300_000);
        rig.Files.AddFile(Site + "/big.bin", data);
        var provider = new SftpFileProvider(rig.Sftp, "site");

        // Synchronously, as many IFileInfo consumers read.
        using (var reader = new StreamReader(provider.GetFileInfo("index.html").CreateReadStream()))
        {
            await Assert.That(reader.ReadToEnd()).IsEqualTo("<h1>hello</h1>");
        }

        using (var stream = provider.GetFileInfo("big.bin").CreateReadStream())
        {
            await Assert.That(stream.Length).IsEqualTo(300_000L);
            var sync = new MemoryStream();
            stream.CopyTo(sync);
            await Assert.That(sync.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        }

        // Asynchronously, as ASP.NET Core's static files do.
        await using (var stream = provider.GetFileInfo("big.bin").CreateReadStream())
        {
            var copy = new MemoryStream();
            await stream.CopyToAsync(copy, Timeout());
            await Assert.That(copy.ToArray().AsSpan().SequenceEqual(data)).IsTrue();
        }

        await Assert.That(rig.Files.OpenHandles).IsEqualTo(0);
    }

    [Test]
    public async Task Configuration_LoadsAJsonFileFromTheServer()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");

        var configuration = new ConfigurationBuilder()
            .AddJsonFile(provider, "appsettings.json", optional: false, reloadOnChange: false)
            .Build();

        await Assert.That(configuration["Greeting"]).IsEqualTo("from the server");
        await Assert.That(configuration.GetSection("Limits")["Max"]).IsEqualTo("42");
    }

    [Test]
    public async Task Lookups_AreCached_UntilTheCacheExpiresOrIsCleared()
    {
        await using var rig = await Rig.StartAsync();
        var cached = new SftpFileProvider(rig.Sftp, "site");
        cached.GetFileInfo("index.html");
        cached.GetDirectoryContents("css");
        var before = rig.Requests;

        cached.GetFileInfo("index.html");
        cached.GetDirectoryContents("css");
        await Assert.That(rig.Requests).IsEqualTo(before);

        cached.ClearCache();
        cached.GetFileInfo("index.html");
        await Assert.That(rig.Requests).IsGreaterThan(before);

        var uncached = new SftpFileProvider(rig.Sftp, "site", new SftpFileProviderOptions { CacheDuration = TimeSpan.Zero });
        uncached.GetFileInfo("index.html");
        var middle = rig.Requests;
        uncached.GetFileInfo("index.html");
        await Assert.That(rig.Requests).IsGreaterThan(middle);
    }

    [Test]
    public async Task Watch_NeverSignals()
    {
        await using var rig = await Rig.StartAsync();
        var token = new SftpFileProvider(rig.Sftp, "site").Watch("**/*");

        await Assert.That(token.HasChanged).IsFalse();
        await Assert.That(token.ActiveChangeCallbacks).IsFalse();
    }

    [Test]
    public async Task ManyThreads_ShareOneProvider()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site", new SftpFileProviderOptions { CacheDuration = TimeSpan.Zero });

        var lengths = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            using var reader = new StreamReader(provider.GetFileInfo("css/site.css").CreateReadStream());
            return reader.ReadToEnd().Length;
        })));

        await Assert.That(lengths.All(l => l == 6)).IsTrue();
    }

    [Test]
    public async Task ABrokenSession_IsAnError_NotAMissingFile()
    {
        await using var rig = await Rig.StartAsync();
        var provider = new SftpFileProvider(rig.Sftp, "site");
        await rig.Sftp.DisposeAsync();

        await Assert.That(() => provider.GetFileInfo("index.html")).Throws<SshException>();
    }

    [Test]
    public async Task InvalidArguments_AreRejected()
    {
        await using var rig = await Rig.StartAsync();

        await Assert.That(() => new SftpFileProvider(null!, "site")).Throws<ArgumentNullException>();
        await Assert.That(() => new SftpFileProvider(rig.Sftp, "")).Throws<ArgumentException>();
        await Assert.That(() => new SftpFileProviderOptions { CacheDuration = TimeSpan.FromSeconds(-1) }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new SftpFileProviderOptions { OperationTimeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();
    }
}
