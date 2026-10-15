using System.IO.Pipes;
using SshSharp.Protocol;

namespace SshSharp.Tests.Agent;

/// <summary>Finding PuTTY's Pageant by the pipe name it derives for the current user.</summary>
public class PageantTests
{
    [Test]
    public async Task ThePipeName_HasPuttysForm_AndIsStable()
    {
        if (!OperatingSystem.IsWindows())
        {
            await Assert.That(SshAgent.Pageant()).IsNull();
            return;
        }

        var name = PageantPipe.Name();
        await Assert.That(name).IsNotNull();
        var parts = name!.Split('.');
        await Assert.That(parts[0]).IsEqualTo("pageant");
        await Assert.That(parts[^1]).Matches("^[0-9a-f]{64}$");
        await Assert.That(string.Join('.', parts[1..^1])).IsNotEmpty().And.DoesNotContain("@");

        // CryptProtectMemory with CROSS_PROCESS gives the same bytes for every process, so the name is stable (and no secret).
        await Assert.That(PageantPipe.Name()).IsEqualTo(name);
        await Assert.That(PageantPipe.Obfuscate("Pageant")).IsEqualTo(parts[^1]);
        await Assert.That(PageantPipe.Obfuscate("Other")).IsNotEqualTo(parts[^1]);
    }

    [Test]
    public async Task APipeTheUserOwns_IsUsedAsAnAgent()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // The owner check passes for the user's own pipe: an agent with no keys answers SSH_AGENT_IDENTITIES_ANSWER with a count of 0.
        var name = "sshsharp-test-" + Guid.NewGuid().ToString("N")[..12];
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var serving = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            var request = new byte[5];
            await server.ReadExactlyAsync(request);
            await server.WriteAsync(new byte[] { 0, 0, 0, 5, 12, 0, 0, 0, 0 });
            await server.FlushAsync();
        });

        var keys = await new SshAgent(@"\\.\pipe\" + name).GetKeysAsync(new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);

        await Assert.That(keys).IsEmpty();
        await serving;
    }
}
