using SshSharp.Config;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// The permissions of a local forwarding's Unix socket (the <c>socketMode</c> overloads and <c>StreamLocalBindMask</c>), and the
/// expansion of <c>RemoteForward</c> socket paths.
/// </summary>
public sealed class SocketForwardingModeTests : IDisposable
{
    // Short: a Unix socket path is limited to about 104 bytes (macOS) or 108 (Linux), and the temporary directory can be long.
    private readonly string _dir = Directory.CreateTempSubdirectory("sfm").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    /// <summary>A password made for the test run: never written in the source.</summary>
    private static readonly string Password = Guid.NewGuid().ToString("N");

    private const UnixFileMode OwnerAndGroup = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite;

    private string SocketPath(string name = "fwd.sock") => Path.Combine(_dir, name);

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    private async Task<(FakeSessionServer Server, SshClient Client)> ConnectByConfigAsync(string forwardings, Func<string, string?>? environment = null)
    {
        var server = new FakeSessionServer { Password = Password };
        var client = await SshClient.ConnectAsync("target", new SshConfigConnectOptions
        {
            Config = SshConfig.Parse($"Host *\n User tester\n StrictHostKeyChecking no\n UserKnownHostsFile none\n{forwardings}"),
            ResolveOptions = new SshConfigResolveOptions
            {
                LocalUser = "local",
                HomeDirectory = _dir,
                GetEnvironmentVariable = environment ?? (_ => null),
            },
            Password = Password,
            UseAgent = false,
            StartForwardings = true,
            TcpConnector = (_, _, _, _) =>
            {
                _ = server.StartAsync();
                return ValueTask.FromResult<(Stream, IAsyncDisposable?)>((server.ClientStream, null));
            },
        }, Timeout());
        return (server, client);
    }

    /// <summary>The socket has <paramref name="mode"/> on Unix; on Windows, whatever the mode, an ACL with the current user only.</summary>
    private static async Task AssertModeAsync(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows())
        {
            await Assert.That(IsOwnerOnly(path)).IsTrue();
        }
        else
        {
            await Assert.That(File.GetUnixFileMode(path)).IsEqualTo(mode);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsOwnerOnly(string path)
    {
        var acl = new FileInfo(path).GetAccessControl();
        using var me = System.Security.Principal.WindowsIdentity.GetCurrent();
        var rules = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
        return acl.AreAccessRulesProtected && rules.Count > 0 && rules.All(r => !r.IsInherited && r.IdentityReference.Value == me.User!.Value);
    }

    [Test]
    public async Task TheGivenMode_IsTheSocketFilesMode()
    {
        await using var server = new FakeSessionServer { Password = Password };
        await using var client = await ConnectAsync(server);

        await using (var toHost = await client.ForwardLocalUnixSocketAsync(SocketPath("a.sock"), "db", 1, OwnerAndGroup, Timeout()))
        {
            await AssertModeAsync(toHost.LocalSocketPath, OwnerAndGroup);
        }

        await using (var toSocket = await client.ForwardLocalUnixSocketAsync(SocketPath("b.sock"), "/run/app.sock", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, Timeout()))
        {
            await AssertModeAsync(toSocket.LocalSocketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        // The overloads without a mode keep to owner-only.
        await using var plain = await client.ForwardLocalUnixSocketAsync(SocketPath("c.sock"), "db", 1, Timeout());
        await AssertModeAsync(plain.LocalSocketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Test]
    [Arguments(UnixFileMode.SetUser)]
    [Arguments(UnixFileMode.SetGroup)]
    [Arguments(UnixFileMode.StickyBit)]
    [Arguments((UnixFileMode)0x1000)]
    public async Task AModeBeyondThePermissionBits_IsRejected(UnixFileMode extra)
    {
        await using var server = new FakeSessionServer { Password = Password };
        await using var client = await ConnectAsync(server);
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | extra;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "db", 1, mode, Timeout()));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.ForwardLocalUnixSocketAsync(SocketPath(), "/run/app.sock", mode, Timeout()));
        await Assert.That(Directory.GetFiles(_dir)).IsEmpty();
    }

    [Test]
    [Arguments("", 0x180)] // ssh's default mask, 0177: 0600
    [Arguments(" StreamLocalBindMask 0117\n", 0x1B0)] // 0660
    [Arguments(" StreamLocalBindMask 0177\n", 0x180)]
    [Arguments(" StreamLocalBindMask 0077\n", 0x1C0)] // 0700
    public async Task StreamLocalBindMask_SetsTheModeOfLocalForwardSockets(string mask, int mode)
    {
        var path = SocketPath();
        var (server, client) = await ConnectByConfigAsync($" LocalForward \"{path}\" db.internal:5432\n{mask}");
        await using (server)
        await using (client)
        {
            await Assert.That(client.LocalSocketForwardings.Count).IsEqualTo(1);
            await AssertModeAsync(path, (UnixFileMode)mode);
        }
    }

    [Test]
    public async Task RemoteForwardSocketPaths_TakeTokensAndVariables_ButOnlyTheLocalOneTakesTilde()
    {
        var local = _dir.Replace('\\', '/');
        var (server, client) = await ConnectByConfigAsync(
            " RemoteForward /run/user/%r/%n.sock 127.0.0.1:3000\n"
            + " RemoteForward ${SOCKET_DIR}/app.sock 127.0.0.1:3001\n"
            + " RemoteForward ~/home.sock 127.0.0.1:3002\n"
            + " RemoteForward /run/agent.sock ~/agent.sock\n"
            + " RemoteForward /run/gpg.sock %d/gpg.sock\n",
            name => name == "SOCKET_DIR" ? "/run/sockets" : null);
        await using (server)
        await using (client)
        {
            await Assert.That(server.RemoteSocketForwards).IsEquivalentTo(new[]
            {
                "/run/user/tester/target.sock", // %r is the remote user, %n the alias
                "/run/sockets/app.sock",
                "~/home.sock", // the server's home is the server's business
                "/run/agent.sock",
                "/run/gpg.sock",
            });
            await Assert.That(client.RemoteSocketForwardings[3].LocalSocketPath!.Replace('\\', '/')).IsEqualTo($"{local}/agent.sock");
            await Assert.That(client.RemoteSocketForwardings[4].LocalSocketPath!.Replace('\\', '/')).IsEqualTo($"{local}/gpg.sock");
        }
    }

    [Test]
    public async Task ARemoteForwardPathThatDoesNotExpand_IsSkipped()
    {
        var (server, client) = await ConnectByConfigAsync(" RemoteForward ${UNSET_VARIABLE}/app.sock 127.0.0.1:3000\n RemoteForward /run/%Q.sock 127.0.0.1:3001\n");
        await using (server)
        await using (client)
        {
            await Assert.That(client.RemoteSocketForwardings).IsEmpty();
            await Assert.That(server.RemoteSocketForwards).IsEmpty();
        }
    }
}
