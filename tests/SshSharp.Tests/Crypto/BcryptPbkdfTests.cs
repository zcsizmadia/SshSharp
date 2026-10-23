using System.Security.Cryptography;
using SshSharp.Crypto;

namespace SshSharp.Tests.Crypto;

/// <summary>
/// bcrypt_pbkdf as OpenSSH uses it for encrypted keys. End-to-end agreement with OpenSSH is checked in interop
/// (keys encrypted by ssh-keygen with every supported cipher are decrypted and compared with their .pub files).
/// </summary>
public class BcryptPbkdfTests
{
    [Test]
    public async Task BlowfishInitialState_IsTheDigitsOfPi()
    {
        // Published Blowfish constants: first and last P-array words, and the first and last S-box words.
        await Assert.That(BcryptPbkdf.InitialWord(0)).IsEqualTo(0x243F6A88u);
        await Assert.That(BcryptPbkdf.InitialWord(1)).IsEqualTo(0x85A308D3u);
        await Assert.That(BcryptPbkdf.InitialWord(17)).IsEqualTo(0x8979FB1Bu);
        await Assert.That(BcryptPbkdf.InitialWord(18)).IsEqualTo(0xD1310BA6u);
        await Assert.That(BcryptPbkdf.InitialWord(19)).IsEqualTo(0x98DFB5ACu);
        await Assert.That(BcryptPbkdf.InitialWord(18 + 1023)).IsEqualTo(0x3AC372E6u);
    }

    [Test]
    public async Task KnownAnswer_FromThePycaBcryptTestSuite()
    {
        // The published vector's inputs, kept as they are: fixed inputs of the algorithm's test, not a credential.
        var key = new byte[32];
        BcryptPbkdf.DeriveKey("password"u8, "salt"u8, 4, key);
        await Assert.That(Convert.ToHexString(key)).IsEqualTo("5BBF0CC293587F1C3635555C27796598D47E579071BF427E9D8FBE842ABA34D9");
    }

    [Test]
    public async Task OutputIsSpreadAcrossTheKey_NotWrittenBlockByBlock()
    {
        // Longer outputs interleave the blocks: a 64-byte key is not the 32-byte key followed by more bytes.
        var password = RandomNumberGenerator.GetBytes(12);
        var short32 = new byte[32];
        var long64 = new byte[64];
        BcryptPbkdf.DeriveKey(password, "salt"u8, 2, short32);
        BcryptPbkdf.DeriveKey(password, "salt"u8, 2, long64);
        await Assert.That(long64.AsSpan(0, 32).SequenceEqual(short32)).IsFalse();
        await Assert.That(long64[0]).IsEqualTo(short32[0]);
        await Assert.That(long64[2]).IsEqualTo(short32[1]);

        // Deterministic, and sensitive to every input.
        var again = new byte[64];
        BcryptPbkdf.DeriveKey(password, "salt"u8, 2, again);
        await Assert.That(again).IsEquivalentTo(long64);
        var otherRounds = new byte[64];
        BcryptPbkdf.DeriveKey(password, "salt"u8, 3, otherRounds);
        await Assert.That(otherRounds).IsNotEquivalentTo(long64);
    }

    [Test]
    public async Task InvalidParameters_AreRefused()
    {
        var password = RandomNumberGenerator.GetBytes(12);
        var key = new byte[32];
        await Assert.That(() => BcryptPbkdf.DeriveKey(""u8, "salt"u8, 4, key)).Throws<ArgumentException>();
        await Assert.That(() => BcryptPbkdf.DeriveKey(password, ""u8, 4, key)).Throws<ArgumentException>();
        await Assert.That(() => BcryptPbkdf.DeriveKey(password, "salt"u8, 0, key)).Throws<ArgumentException>();
        await Assert.That(() => BcryptPbkdf.DeriveKey(password, "salt"u8, 4, new byte[1025])).Throws<ArgumentException>();
    }
}
