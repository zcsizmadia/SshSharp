namespace SshSharp.Tests;

public class SshSharpInfoTests
{
    [Test]
    public async Task SoftwareVersion_StartsWithProductName()
    {
        await Assert.That(SshSharpInfo.SoftwareVersion).StartsWith("SshSharp_");
    }

    [Test]
    public async Task SoftwareVersion_ContainsNoBuildMetadata()
    {
        await Assert.That(SshSharpInfo.SoftwareVersion).DoesNotContain("+");
    }
}