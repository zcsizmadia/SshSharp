using SshSharp.Config;

namespace SshSharp.Tests.Config;

public class GlobTests
{
    [Test]
    [Arguments("*", "anything", true)]
    [Arguments("*", "", true)]
    [Arguments("", "", true)]
    [Arguments("", "a", false)]
    [Arguments("a?c", "abc", true)]
    [Arguments("a?c", "ac", false)]
    [Arguments("*.example.com", "host.example.com", true)]
    [Arguments("*.example.com", "example.com", false)]
    [Arguments("*.EXAMPLE.com", "Host.example.COM", true)]
    [Arguments("a*b*c", "aXXbYYc", true)]
    [Arguments("a*b*c", "aXXbYY", false)]
    [Arguments("10.0.*.?", "10.0.5.7", true)]
    [Arguments("abc", "abcd", false)]
    [Arguments("abc*", "abc", true)]
    [Arguments("*abc", "xxabc", true)]
    [Arguments("*abc", "xxabd", false)]
    public async Task IsMatch(string pattern, string text, bool expected)
    {
        await Assert.That(Glob.IsMatch(pattern, text)).IsEqualTo(expected);
    }
}