using System.Net;
using System.Net.Sockets;
using System.Text;
using SshSharp;
using SshSharp.Config;
using SshSharp.Scp;

// A Native AOT smoke test: the configuration parsers always, and with SSHSHARP_TEST_SSHD (host:port), SSHSHARP_TEST_USER and
// SSHSHARP_TEST_PASSWORD or SSHSHARP_TEST_KEYDIR, a real connection through every main feature. Exit code 0 means it all worked.
var steps = 0;
void Pass(string step)
{
    steps++;
    Console.WriteLine($"ok  {step}");
}

using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
var ct = timeout.Token;

var config = SshConfig.Parse("Host db\n  HostName db.internal\n  User app\n  ProxyJump bastion\n  LocalForward 15432 localhost:5432\n");
var resolved = config.Resolve("db", new SshConfigResolveOptions { LocalUser = "me", HomeDirectory = Path.GetTempPath() });
Check(resolved.HostName == "db.internal" && resolved.User == "app" && resolved.ProxyJump.Single() == "bastion", "ssh_config resolves");
Pass("ssh_config");

// An Ed25519 public key blob: string "ssh-ed25519", string 32 key bytes.
byte[] blob = [0, 0, 0, 11, .. "ssh-ed25519"u8, 0, 0, 0, 32, .. Enumerable.Range(1, 32).Select(i => (byte)i)];
var knownHosts = KnownHostsFile.Parse($"{KnownHostsEntry.HashHost("example.com", 22)} ssh-ed25519 {Convert.ToBase64String(blob)}\n");
Check(knownHosts.Check("example.com", 22, "ssh-ed25519", blob) == KnownHostsCheckResult.Match, "known_hosts matches a hashed host");
Pass("known_hosts");

var endpoint = Environment.GetEnvironmentVariable("SSHSHARP_TEST_SSHD");
if (string.IsNullOrEmpty(endpoint))
{
    Console.WriteLine($"{steps} steps passed; set SSHSHARP_TEST_SSHD for the connection steps.");
    return 0;
}

var host = endpoint[..endpoint.LastIndexOf(':')];
var port = int.Parse(endpoint[(endpoint.LastIndexOf(':') + 1)..], System.Globalization.CultureInfo.InvariantCulture);
var keyDir = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR");
var keys = new List<SshPrivateKey>();
if (!string.IsNullOrEmpty(keyDir) && File.Exists(Path.Combine(keyDir, "ed25519")))
{
    keys.Add(await SshPrivateKey.LoadAsync(Path.Combine(keyDir, "ed25519"), cancellationToken: ct));
}

await using var client = await SshClient.ConnectAsync(host, port, new SshClientOptions
{
    UserName = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER")!,
    Password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD"),
    PrivateKeys = keys,
    HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
    KeepAliveInterval = TimeSpan.FromSeconds(30),
}, ct);
Pass($"connect ({client.ServerIdentification}, host key {client.HostKey.KeyType})");

var result = await client.RunCommandAsync("echo aot", ct);
Check(result.ExitStatus == 0 && result.StandardOutputText == "aot\n", "a command runs");
Pass("RunCommandAsync");

await using (var session = await client.StartCommandAsync("tr a-z A-Z", cancellationToken: ct))
{
    await session.StandardInput.WriteAsync("streamed\n"u8.ToArray(), ct);
    await session.CloseInputAsync(ct);
    using var reader = new StreamReader(session.StandardOutput);
    Check(await reader.ReadToEndAsync(ct) == "STREAMED\n", "a session streams");
    await session.WaitForExitAsync(ct);
}

Pass("StartCommandAsync");

await using (var shell = await client.StartShellAsync(new SshSessionOptions { Terminal = new SshTerminalOptions { TerminalType = "dumb" } }, ct))
{
    await shell.StandardInput.WriteAsync("exit 3\n"u8.ToArray(), ct);
    await shell.StandardOutput.CopyToAsync(Stream.Null, ct);
    await shell.WaitForExitAsync(ct);
    Check(shell.ExitStatus == 3, "a shell with a terminal exits with its status");
}

Pass("StartShellAsync");

await using (var tunnel = await client.OpenTcpTunnelAsync("127.0.0.1", port, ct))
{
    var line = new byte[8];
    await tunnel.ReadExactlyAsync(line, ct);
    Check(Encoding.ASCII.GetString(line) == "SSH-2.0-", "a tunnel reaches the server's own sshd");
}

Pass("OpenTcpTunnelAsync");

await using (var proxy = await client.ForwardDynamicPortAsync(new IPEndPoint(IPAddress.Loopback, 0), ct))
{
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    await socket.ConnectAsync(proxy.LocalEndPoint, ct);
    await socket.SendAsync(new byte[] { 5, 1, 0 }, SocketFlags.None, ct);
    var reply = new byte[2];
    await socket.ReceiveAsync(reply, SocketFlags.None, ct);
    Check(reply[0] == 5 && reply[1] == 0, "the SOCKS proxy answers");
}

Pass("ForwardDynamicPortAsync");

var content = new byte[200_000];
Random.Shared.NextBytes(content);
var remote = (await client.RunCommandAsync("mktemp", ct)).StandardOutputText.Trim();
await client.UploadAsync(new MemoryStream(content), remote, cancellationToken: ct);
using (var back = new MemoryStream())
{
    await client.DownloadAsync(remote, back, cancellationToken: ct);
    Check(back.ToArray().AsSpan().SequenceEqual(content), "SCP round-trips a file");
}

await client.RunCommandAsync($"rm -f '{remote}'", ct);
Pass("SCP");

Console.WriteLine($"{steps} steps passed.");
return 0;

static void Check(bool condition, string what)
{
    if (!condition)
    {
        Console.Error.WriteLine($"FAIL {what}");
        Environment.Exit(1);
    }
}
