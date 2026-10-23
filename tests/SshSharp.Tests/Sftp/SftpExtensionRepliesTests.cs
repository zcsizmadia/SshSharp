using System.Buffers;
using SshSharp.Protocol;
using SshSharp.Sftp;

namespace SshSharp.Tests.Sftp;

/// <summary>The parsers of file hash replies, check-file announcements and statuses, one rule at a time.</summary>
public sealed class SftpExtensionRepliesTests
{
    private static byte[] Build(Action<SshWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        write(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static (string Algorithm, byte[] Hash) CheckFile(byte[] body, params string[] requested)
    {
        var reader = new SshReader(body);
        return SftpExtensionReplies.ParseCheckFile(ref reader, requested);
    }

    private static byte[] Md5(byte[] body)
    {
        var reader = new SshReader(body);
        return SftpExtensionReplies.ParseMd5Hash(ref reader);
    }

    [Test]
    [Arguments("md5", 16)]
    [Arguments("sha1", 20)]
    [Arguments("sha224", 28)]
    [Arguments("sha256", 32)]
    [Arguments("sha384", 48)]
    [Arguments("sha512", 64)]
    [Arguments("crc32", 4)]
    public async Task HashLength_IsTheDigestLength(string algorithm, int length) =>
        await Assert.That(SftpExtensionReplies.HashLength(algorithm)).IsEqualTo(length);

    [Test]
    public async Task HashLength_OfAnotherAlgorithm_IsUnknown()
    {
        await Assert.That(SftpExtensionReplies.HashLength("blake2b@example.com")).IsNull();
        await Assert.That(SftpExtensionReplies.HashLength("SHA256")).IsNull();
    }

    [Test]
    public async Task AnnouncedAlgorithms_ReadsAList()
    {
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms("md5,sha1,sha256")!).IsEquivalentTo(["md5", "sha1", "sha256"]);
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms("sha256")!).IsEquivalentTo(["sha256"]);
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms(" md5 , sha-512@example.com ")!).IsEquivalentTo(["md5", "sha-512@example.com"]);
    }

    [Test]
    [Arguments("")]
    [Arguments("1")]
    [Arguments("2.0")]
    [Arguments("md5,,sha1")]
    [Arguments("md5,SHA1")]
    [Arguments("md5;sha1")]
    [Arguments("md5,é")]
    public async Task AnnouncedAlgorithms_OfSomethingElse_IsNull(string data) =>
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms(data)).IsNull();

    [Test]
    public async Task AnnouncedAlgorithms_TakesAtMostThirtyTwo()
    {
        var names = Enumerable.Range(0, 32).Select(i => "a" + i).ToArray();
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms(string.Join(',', names))!.Count).IsEqualTo(32);
        await Assert.That(SftpExtensionReplies.AnnouncedAlgorithms(string.Join(',', names) + ",a32")).IsNull();
    }

    [Test]
    public async Task IsAlgorithmName_TakesLowerCaseNames_StartingWithALetter()
    {
        foreach (var name in new[] { "a", "z", "sha256", "sha-1", "x.y", "v@example.com", "a0", "a9", new string('a', 64) })
        {
            await Assert.That(SftpExtensionReplies.IsAlgorithmName(name)).IsTrue().Because(name);
        }

        foreach (var name in new[] { "", "1md5", "-a", ".a", "@a", "Sha256", "sha 256", "sha,256", "a/b", "a`", "a{", new string('a', 65), "a\0" })
        {
            await Assert.That(SftpExtensionReplies.IsAlgorithmName(name)).IsFalse().Because(name);
        }
    }

    [Test]
    public async Task ParseCheckFile_ReadsTheAlgorithmAndTheHash()
    {
        var hash = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var (algorithm, parsed) = CheckFile(Build(w => { w.WriteString("check-file"); w.WriteString("sha256"); w.WriteBytes(hash); }), "sha512", "sha256");

        await Assert.That(algorithm).IsEqualTo("sha256");
        await Assert.That(parsed.SequenceEqual(hash)).IsTrue();
    }

    [Test]
    public async Task ParseCheckFile_NamesTheAlgorithmAsAsked_WhateverTheCaseTheServerUsed()
    {
        var (algorithm, _) = CheckFile(Build(w => { w.WriteString("check-file"); w.WriteString("SHA256"); w.WriteBytes(new byte[32]); }), "sha256");

        await Assert.That(algorithm).IsEqualTo("sha256");
    }

    [Test]
    public async Task ParseCheckFile_WithoutTheLeadingName_AsProFtpdSendsIt_ReadsTheAlgorithmAndTheHash()
    {
        var hash = Enumerable.Range(1, 64).Select(i => (byte)i).ToArray();
        var (algorithm, parsed) = CheckFile(Build(w => { w.WriteString("sha512"); w.WriteBytes(hash); }), "sha256", "sha512");

        await Assert.That(algorithm).IsEqualTo("sha512");
        await Assert.That(parsed.SequenceEqual(hash)).IsTrue();
    }

    [Test]
    public async Task ParseCheckFile_OfAnUnknownAlgorithm_TakesAHashOfAnyLength()
    {
        var (algorithm, hash) = CheckFile(Build(w => { w.WriteString("check-file"); w.WriteString("vendor@example.com"); w.WriteBytes([1, 2, 3]); }), "vendor@example.com");

        await Assert.That(algorithm).IsEqualTo("vendor@example.com");
        await Assert.That(hash.Length).IsEqualTo(3);
    }

    [Test]
    public async Task ParseCheckFile_RejectsWhatIsNotAWholeHashOfAnAlgorithmAskedFor()
    {
        byte[][] bad =
        [
            Build(w => { w.WriteString("check-files"); w.WriteString("sha256"); w.WriteBytes(new byte[32]); }),
            Build(w => { w.WriteString("md5-hash"); w.WriteString("sha256"); w.WriteBytes(new byte[32]); }),
            Build(w => { w.WriteString("check-file"); w.WriteString("md5"); w.WriteBytes(new byte[16]); }),
            Build(w => { w.WriteString("check-file"); w.WriteString("sha256"); w.WriteBytes(new byte[31]); }),
            Build(w => { w.WriteString("check-file"); w.WriteString("sha256"); w.WriteBytes(new byte[33]); }),
            Build(w => { w.WriteString("check-file"); w.WriteString("sha256"); }),
            Build(w => w.WriteString("check-file")),
            [],

            // ProFTPD's form, without the leading name, is held to the same rules.
            Build(w => { w.WriteString("md5"); w.WriteBytes(new byte[16]); }),
            Build(w => { w.WriteString("sha256"); w.WriteBytes(new byte[31]); }),
            Build(w => w.WriteString("sha256")),
        ];

        foreach (var body in bad)
        {
            await Assert.That(() => CheckFile(body, "sha256", "sha512")).Throws<SshProtocolException>();
        }

        // Unknown algorithms still need some hash.
        await Assert.That(() => CheckFile(Build(w => { w.WriteString("check-file"); w.WriteString("vendor@example.com"); }), "vendor@example.com"))
            .Throws<SshProtocolException>();
    }

    [Test]
    public async Task ParseMd5Hash_ReadsSixteenBytes()
    {
        var hash = Enumerable.Range(0, 16).Select(i => (byte)(i * 7)).ToArray();

        await Assert.That(Md5(Build(w => { w.WriteString("md5-hash"); w.WriteString(hash); })).SequenceEqual(hash)).IsTrue();
    }

    [Test]
    public async Task ParseMd5Hash_RejectsAnythingElse()
    {
        byte[][] bad =
        [
            Build(w => { w.WriteString("md5-hashes"); w.WriteString(new byte[16]); }),
            Build(w => { w.WriteString("check-file"); w.WriteString(new byte[16]); }),
            Build(w => { w.WriteString("md5-hash"); w.WriteString(new byte[15]); }),
            Build(w => { w.WriteString("md5-hash"); w.WriteString(new byte[17]); }),
            Build(w => { w.WriteString("md5-hash"); w.WriteString(ReadOnlySpan<byte>.Empty); }), // the quick check did not match
            Build(w => w.WriteString("md5-hash")),
        ];

        foreach (var body in bad)
        {
            await Assert.That(() => Md5(body)).Throws<SshProtocolException>();
        }
    }

    [Test]
    public async Task ParseStatus_ReadsTheCodeAndTheMessage_WhichMayBeMissing()
    {
        var full = Build(w => { w.WriteUInt32(3); w.WriteString("Permission denied"); w.WriteString("en"); });
        var reader = new SshReader(full);
        await Assert.That(SftpExtensionReplies.ParseStatus(ref reader)).IsEqualTo((SftpStatusCode.PermissionDenied, "Permission denied"));

        var bare = Build(w => w.WriteUInt32(8));
        reader = new SshReader(bare);
        await Assert.That(SftpExtensionReplies.ParseStatus(ref reader)).IsEqualTo((SftpStatusCode.OperationUnsupported, string.Empty));

        await Assert.That(() =>
        {
            var truncated = new SshReader([0, 0, 1]);
            return SftpExtensionReplies.ParseStatus(ref truncated);
        }).Throws<SshProtocolException>();
    }
}
