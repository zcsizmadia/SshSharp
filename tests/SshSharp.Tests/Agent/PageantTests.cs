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

        // CryptProtectMemory with CROSS_PROCESS gives the same bytes for every process of this logon session, so the name is stable.
        await Assert.That(PageantPipe.Name()).IsEqualTo(name);
        await Assert.That(PageantPipe.Obfuscate("Pageant")).IsEqualTo(parts[^1]);
        await Assert.That(PageantPipe.Obfuscate("Other")).IsNotEqualTo(parts[^1]);
    }
}
