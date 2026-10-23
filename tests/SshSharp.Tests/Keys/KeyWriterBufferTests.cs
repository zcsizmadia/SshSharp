using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp.Tests.Keys;

/// <summary>Writing a private key leaves no copy of its private fields behind in buffers that were outgrown.</summary>
public class KeyWriterBufferTests
{
    [Test]
    public async Task TheZeroingWriter_ClearsEveryArrayItOutgrows_AndItsLastOneOnDispose()
    {
        var writer = new ZeroingBufferWriter(16);
        var first = writer.GetMemory(16);
        first.Span.Fill(0xAB);
        writer.Advance(16);

        var second = writer.GetMemory(100); // grows: the first array must now be all zero
        await Assert.That(writer.Reallocations).IsEqualTo(1);
        await Assert.That(first.ToArray().All(b => b == 0)).IsTrue();
        await Assert.That(writer.WrittenSpan.ToArray().All(b => b == 0xAB)).IsTrue();

        second.Span[..10].Fill(0xCD);
        writer.Advance(10);
        await Assert.That(writer.WrittenCount).IsEqualTo(26);
        writer.Dispose();
        await Assert.That(second.ToArray().All(b => b == 0)).IsTrue();
        await Assert.That(() => writer.Advance(10_000)).Throws<InvalidOperationException>();
    }

    public static IEnumerable<Func<(SshKeyType Type, int Bits, string Comment)>> Keys()
    {
        yield return () => (SshKeyType.Ed25519, 0, "");
        yield return () => (SshKeyType.Ed25519, 0, new string('é', 300)); // a long comment of two-byte characters
        yield return () => (SshKeyType.EcdsaNistp256, 0, "user@host");
        yield return () => (SshKeyType.EcdsaNistp384, 0, "user@host");
        yield return () => (SshKeyType.EcdsaNistp521, 0, "user@host");
        yield return () => (SshKeyType.Rsa, 2048, "user@host");
        yield return () => (SshKeyType.Rsa, 3072, "user@host");
        yield return () => (SshKeyType.Rsa, 4096, new string('x', 1000));
    }

    [Test]
    [MethodDataSource(nameof(Keys))]
    public async Task ThePrivateSectionEstimate_CoversTheWholeSection_SoTheBufferNeverGrows(SshKeyType type, int bits, string comment)
    {
        using var key = SshPrivateKey.Generate(type, comment, bits == 0 ? 3072 : bits);

        // The section as OpenSshKeyWriter lays it out, encrypted padding included, into a writer that may grow freely.
        using var section = new ZeroingBufferWriter(16);
        var writer = new SshWriter(section);
        writer.WriteUInt32(1);
        writer.WriteUInt32(1);
        writer.WriteString(key.KeyType);
        key.WritePrivateFields(writer);
        writer.WriteString(System.Text.Encoding.UTF8.GetBytes(key.Comment ?? string.Empty));
        for (byte pad = 1; section.WrittenCount % 16 != 0; pad++)
        {
            writer.WriteByte(pad);
        }

        await Assert.That(OpenSshKeyWriter.EstimatePrivateSectionSize(key)).IsGreaterThanOrEqualTo(section.WrittenCount);

        // RSA's private fields grow with the modulus no faster than the public blob does (n, d ~ modulus; p, q, iqmp ~ half).
        var passphrase = TestSecrets.New();
        var text = key.ToOpenSshPrivateKey(passphrase, kdfRounds: 1);
        using var reloaded = SshPrivateKey.Parse(text, passphrase);
        await Assert.That(reloaded.PublicKey.ToArray().SequenceEqual(key.PublicKey.ToArray())).IsTrue();
    }
}
