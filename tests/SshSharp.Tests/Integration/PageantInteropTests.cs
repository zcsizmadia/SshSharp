using System.Diagnostics;

namespace SshSharp.Tests.Integration;

/// <summary>
/// PuTTY's Pageant, found by its pipe and used as an agent. Needs SSHSHARP_TEST_PAGEANT=1 with Pageant running for the current user
/// (CI starts it on the Windows runner), no SSH_AUTH_SOCK and no OpenSSH agent service.
/// </summary>
public class PageantInteropTests
{
    [Test]
    public async Task ARunningPageant_IsFound_AndSignsWithItsKeys()
    {
        if (Environment.GetEnvironmentVariable("SSHSHARP_TEST_PAGEANT") != "1" || !OperatingSystem.IsWindows())
        {
            Skip.Test("SSHSHARP_TEST_PAGEANT=1 and a running Pageant are needed.");
            return;
        }

        var pageant = SshAgent.Pageant();
        await Assert.That(pageant).IsNotNull();
        await Assert.That(pageant!.Path).StartsWith(@"\\.\pipe\pageant.");
        await Assert.That(SshAgent.FromEnvironment()!.Path).IsEqualTo(pageant.Path);

        // A key added through the pipe with Windows OpenSSH's ssh-add, which proves the pipe speaks the agent protocol.
        var directory = Directory.CreateTempSubdirectory("sshsharp-pageant-");
        try
        {
            using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "pageant-test");
            var path = Path.Combine(directory.FullName, "id_ed25519");
            await key.SaveAsync(path);
            var add = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-add.exe"), [path])
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            add.Environment["SSH_AUTH_SOCK"] = pageant.Path;
            using (var process = Process.Start(add)!)
            {
                var output = await process.StandardError.ReadToEndAsync() + await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();
                await Assert.That(process.ExitCode).IsEqualTo(0).Because(output);
            }

            var keys = await pageant.GetKeysAsync();
            var held = keys.Single(k => k.PublicKey.Span.SequenceEqual(key.PublicKey.Span));
            var message = "signed by pageant"u8.ToArray();
            var signature = await SshSignature.SignAsync(held, message, "file");
            await Assert.That(signature.Verify(message, "file")).IsTrue();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
