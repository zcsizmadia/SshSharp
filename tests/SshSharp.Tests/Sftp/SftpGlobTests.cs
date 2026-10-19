using SshSharp.Sftp;

namespace SshSharp.Tests.Sftp;

/// <summary>The name patterns of <see cref="SftpListOptions.Pattern"/>: fnmatch(3) without flags, case-sensitive, by code point.</summary>
public sealed class SftpGlobTests
{
    [Test]
    [Arguments("*.log", "app.log", true)]
    [Arguments("*.log", "app.log.1", false)]
    [Arguments("*.log", "app.LOG", false)] // case-sensitive
    [Arguments("*.log", ".log", true)] // a leading dot is not special
    [Arguments("*", ".hidden", true)]
    [Arguments("*", "", true)]
    [Arguments("", "", true)]
    [Arguments("", "a", false)]
    [Arguments("Report.TXT", "report.txt", false)]
    [Arguments("abc", "abc", true)]
    [Arguments("abc", "abcd", false)]
    [Arguments("abcd", "abc", false)]
    public async Task Literals_AndStar(string pattern, string name, bool expected) =>
        await Assert.That(SftpGlob.Parse(pattern).IsMatch(name)).IsEqualTo(expected);

    [Test]
    [Arguments("?", "a", true)]
    [Arguments("?", "", false)]
    [Arguments("?", "ab", false)]
    [Arguments("a?c", "abc", true)]
    [Arguments("a?c", "ac", false)]
    [Arguments("*?", "", false)]
    [Arguments("*?", "a", true)]
    [Arguments("**x", "x", true)]
    [Arguments("*a*b", "xaybzb", true)]
    [Arguments("*a*b", "xaybzc", false)]
    [Arguments("a*b*c", "abc", true)]
    [Arguments("a*b*c", "acb", false)]
    [Arguments("a*", "a", true)]
    [Arguments("a*", "ba", false)]
    [Arguments("*a", "ba", true)]
    [Arguments("*ab", "aab", true)] // the star takes one more character when what follows fails
    public async Task QuestionMark_AndStarBacktracking(string pattern, string name, bool expected) =>
        await Assert.That(SftpGlob.Parse(pattern).IsMatch(name)).IsEqualTo(expected);

    [Test]
    [Arguments("[abc]", "b", true)]
    [Arguments("[abc]", "d", false)]
    [Arguments("[abc]", "", false)]
    [Arguments("[a-c]", "a", true)]
    [Arguments("[a-c]", "c", true)]
    [Arguments("[a-c]", "d", false)]
    [Arguments("[a-c]", "`", false)]
    [Arguments("[!a-c]", "d", true)]
    [Arguments("[!a-c]", "b", false)]
    [Arguments("[!a]", "", false)]
    [Arguments("[^a-c]", "d", true)]
    [Arguments("[^a-c]", "a", false)]
    [Arguments("[]]", "]", true)] // a ']' first in the set is a member
    [Arguments("[]a]", "a", true)]
    [Arguments("[]a]", "b", false)]
    [Arguments("[!]]", "]", false)]
    [Arguments("[!]]", "a", true)]
    [Arguments("[a-]", "-", true)] // a '-' last is a member
    [Arguments("[a-]", "b", false)]
    [Arguments("[-a]", "-", true)]
    [Arguments("[z-a]", "m", false)] // a reversed range matches nothing
    [Arguments("[z-a]", "z", false)]
    [Arguments("[a-cx-z]", "y", true)]
    [Arguments("[a-cx-z]", "m", false)]
    [Arguments("log-[0-9][0-9].txt", "log-07.txt", true)]
    [Arguments("log-[0-9][0-9].txt", "log-7.txt", false)]
    [Arguments("[ab]*", "bcd", true)]
    [Arguments("*[ab]", "xxa", true)]
    [Arguments("*[ab]", "xxc", false)]
    public async Task Sets(string pattern, string name, bool expected) =>
        await Assert.That(SftpGlob.Parse(pattern).IsMatch(name)).IsEqualTo(expected);

    [Test]
    [Arguments("[abc", "[abc", true)] // an unclosed '[' is itself
    [Arguments("[abc", "a", false)]
    [Arguments("a[", "a[", true)]
    [Arguments("[!", "[!", true)]
    [Arguments("[]", "[]", true)] // ']' right after '[' is a member, so the set never closes
    [Arguments("\\*", "*", true)]
    [Arguments("\\*", "a", false)]
    [Arguments("\\?", "?", true)]
    [Arguments("\\?", "a", false)]
    [Arguments("\\[a]", "[a]", true)]
    [Arguments("\\[a]", "a", false)]
    [Arguments("a\\", "a\\", true)] // a trailing backslash is itself
    [Arguments("\\\\", "\\", true)]
    [Arguments("[\\]]", "]", true)]
    [Arguments("[\\!a]", "!", true)] // an escaped '!' first does not negate
    [Arguments("[\\!a]", "b", false)]
    [Arguments("[a\\-c]", "-", true)] // an escaped '-' is not a range
    [Arguments("[a\\-c]", "b", false)]
    [Arguments("[a-\\c]", "b", true)] // an escaped range end
    [Arguments("[\\", "[\\", true)]
    public async Task Malformed_AndEscapes(string pattern, string name, bool expected) =>
        await Assert.That(SftpGlob.Parse(pattern).IsMatch(name)).IsEqualTo(expected);

    [Test]
    [Arguments("?.txt", "\U0001F600.txt", true)] // an emoji is one character, as ? should take it
    [Arguments("??.txt", "\U0001F600.txt", false)]
    [Arguments("[\U0001F600-\U0001F602]", "\U0001F601", true)]
    [Arguments("[\U0001F600-\U0001F602]", "\U0001F603", false)]
    [Arguments("caf?", "café", true)]
    public async Task CodePoints(string pattern, string name, bool expected) =>
        await Assert.That(SftpGlob.Parse(pattern).IsMatch(name)).IsEqualTo(expected);

    [Test]
    public async Task ManyStars_DoNotBacktrackWithoutEnd()
    {
        // Each star is remembered in turn, never all at once: a pattern that would take exponential time in a backtracking matcher
        // fails in about the pattern's length times the name's.
        var name = new string('a', 5_000);
        await Assert.That(SftpGlob.Parse("*a*a*a*a*a*a*a*a*a*a*b").IsMatch(name)).IsFalse();
        await Assert.That(SftpGlob.Parse("*a*a*a*a*a*a*a*a*a*a*a").IsMatch(name)).IsTrue();
    }
}
