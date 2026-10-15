using System.Text;

namespace SshSharp.Tests.Integration;

/// <summary>Shells and streamed commands against a real server. Needs SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD.</summary>
public class SessionInteropTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient?> ConnectAsync()
    {
        var user = Environment.GetEnvironmentVariable("SSHSHARP_TEST_USER");
        var password = Environment.GetEnvironmentVariable("SSHSHARP_TEST_PASSWORD");
        var keyFile = Environment.GetEnvironmentVariable("SSHSHARP_TEST_KEYDIR") is { Length: > 0 } dir ? Path.Combine(dir, "ed25519") : null;
        if (RealServer.Endpoint is not var (host, port) || string.IsNullOrEmpty(user) || (string.IsNullOrEmpty(password) && keyFile is null))
        {
            return null;
        }

        // The key is not disposed until the process ends; fine for a test.
        var key = keyFile is not null && File.Exists(keyFile) ? await SshPrivateKey.LoadFileAsync(keyFile) : null;
        var options = new SshClientOptions
        {
            UserName = user,
            Password = password,
            PrivateKeys = key is null ? [] : [key],
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(host, port, options, Timeout());
    }

    private static async Task<string> ReadAllAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, Timeout());
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    [Test]
    public async Task AShellWithATerminal_RunsWhatIsTyped()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var terminal = new SshTerminalOptions { TerminalType = "dumb", Columns = 132, Rows = 50 };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = terminal }, Timeout());
        await Assert.That(session.HasTerminal).IsTrue();

        // The terminal reports its size to programs; "exit 7" ends the shell with that status.
        await session.StandardInput.WriteAsync("stty size; echo marker-$((6*7)); exit 7\n"u8.ToArray(), Timeout());
        var output = await ReadAllAsync(session.StandardOutput);
        await session.WaitForExitAsync(Timeout());

        await Assert.That(output).Contains("50 132");
        await Assert.That(output).Contains("marker-42");
        if (!RealServer.IsWindows)
        {
            // OpenSSH for Windows runs the shell through ConPTY and does not pass its exit status on.
            await Assert.That(session.ExitStatus).IsEqualTo(7);
        }
    }

    [Test]
    public async Task Expect_DrivesARealShell()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var terminal = new SshTerminalOptions { TerminalType = "dumb", Columns = 132, Rows = 50 };
        await using var session = await client.StartShellAsync(new SshSessionOptions { Terminal = terminal }, Timeout());
        var expect = new SshExpect(session);

        // The terminal echoes what is typed; the arithmetic makes the output differ from the echo, so only the result can match.
        await expect.SendLineAsync("echo first-$((6*7))", Timeout());
        await expect.ExpectAsync("first-42", Timeout());
        await expect.SendLineAsync("echo second-$((7*8))-end", Timeout());
        var match = await expect.ExpectAsync(new System.Text.RegularExpressions.Regex(@"second-(\d+)-end"), Timeout());
        await Assert.That(match.Match!.Groups[1].Value).IsEqualTo("56");

        await expect.SendLineAsync("exit", Timeout());
        await Assert.That(async () => await expect.ExpectAsync("never-printed", Timeout())).Throws<EndOfStreamException>();
    }

    [Test]
    public async Task TheSftpSubsystem_AnswersTheVersionHandshake()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        if (!RealServer.IsOpenSsh)
        {
            Skip.Test("Dropbear needs a separate sftp-server, which the test image does not install.");
            return;
        }

        // SFTP's first exchange (draft-ietf-secsh-filexfer-02): SSH_FXP_INIT with version 3, answered by SSH_FXP_VERSION. Enough to show
        // that a subsystem carries a binary protocol both ways with a real server; SFTP itself is SshSharp.Sftp's job (#7).
        await using var sftp = await client.StartSubsystemAsync("sftp", cancellationToken: Timeout());
        await sftp.StandardInput.WriteAsync(new byte[] { 0, 0, 0, 5, 1, 0, 0, 0, 3 }, Timeout());
        var header = new byte[4];
        await sftp.StandardOutput.ReadExactlyAsync(header, Timeout());
        var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header);
        await Assert.That(length).IsGreaterThanOrEqualTo(5u).And.IsLessThan(64u * 1024);
        var reply = new byte[length];
        await sftp.StandardOutput.ReadExactlyAsync(reply, Timeout());
        await Assert.That(reply[0]).IsEqualTo((byte)2); // SSH_FXP_VERSION
        await Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(1))).IsEqualTo(3u);
    }

    [Test]
    public async Task ASubsystemTheServerDoesNotOffer_IsRefused()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        var error = await Assert.ThrowsAsync<SshException>(async () => await client.StartSubsystemAsync("sshsharp-no-such-subsystem", cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That((await client.RunCommandAsync("true", Timeout())).ExitStatus).IsEqualTo(0);
    }

    [Test]
    public async Task ACommandWithoutATerminal_KeepsStdoutAndStderrApart_AndReadsStdin()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        await using var session = await client.StartCommandAsync("echo to-err 1>&2; tr a-z A-Z; exit 4", cancellationToken: Timeout());
        await Assert.That(session.HasTerminal).IsFalse();
        var output = ReadAllAsync(session.StandardOutput);
        var error = ReadAllAsync(session.StandardError);

        // More than the server's initial window, so the input only gets through as the server adjusts it.
        var line = new string('x', 1023) + "\n";
        var input = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(line, 4096)));
        await session.StandardInput.WriteAsync(input, Timeout());
        await session.CloseInputAsync(Timeout());

        await Assert.That((await output).Length).IsEqualTo(input.Length);
        await Assert.That((await output).All(c => c is 'X' or '\n')).IsTrue();
        await Assert.That((await error).Trim()).IsEqualTo("to-err");
        await session.WaitForExitAsync(Timeout());
        await Assert.That(session.ExitStatus).IsEqualTo(4);
    }

    [Test]
    public async Task PingAsync_MeasuresARoundTrip_WithPingsOrWithoutThem()
    {
        await using var client = await ConnectAsync();
        if (client is null)
        {
            Skip.Test("SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and SSHSHARP_TEST_PASSWORD are needed.");
            return;
        }

        // OpenSSH 9.5+ answers transport pings; older OpenSSH and Dropbear answer the keepalive@openssh.com request instead.
        for (var i = 0; i < 3; i++)
        {
            var roundTrip = await client.PingAsync(Timeout());
            await Assert.That(roundTrip).IsLessThan(TimeSpan.FromSeconds(30));
        }

        var result = await client.RunCommandAsync("echo still-here", Timeout());
        await Assert.That(result.StandardOutputText.Trim()).IsEqualTo("still-here");
    }
}
