using System.Buffers;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

public class SshWireTests
{
    // SshReader is a ref struct and cannot live across an await, so reads happen in these synchronous helpers.
    private static byte[] Write(Action<SshWriter> action)
    {
        var buffer = new ArrayBufferWriter<byte>();
        action(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static T Id<T>(T value) => value;

    private static string HexOf(Action<SshWriter> action) => Convert.ToHexString(Write(action));

    private static (byte, bool, bool, uint, ulong, bool, int) ReadScalars(byte[] data)
    {
        var r = new SshReader(data);
        return (r.ReadByte(), r.ReadBoolean(), r.ReadBoolean(), r.ReadUInt32(), r.ReadUInt64(), r.IsEmpty, r.Remaining.Length);
    }

    private static bool Fails(byte[] data, Action<SshReaderAction> read)
    {
        try
        {
            read(new SshReaderAction(data));
            return false;
        }
        catch (SshProtocolException)
        {
            return true;
        }
    }

    // A reader wrapper usable from lambdas: each call creates a fresh reader over the data.
    private sealed class SshReaderAction(byte[] data)
    {
        public void ReadByte() => new SshReader(data).ReadByte();
        public void ReadUInt32() => new SshReader(data).ReadUInt32();
        public void ReadUInt64() => new SshReader(data).ReadUInt64();
        public void ReadString() => new SshReader(data).ReadString();
        public void ReadBytes(int n) => new SshReader(data).ReadBytes(n);
        public void ReadMpint() => new SshReader(data).ReadMpint();
        public void ReadUtf8String() => new SshReader(data).ReadUtf8String();
        public void ReadNameList() => new SshReader(data).ReadNameList();
    }

    [Test]
    public async Task Scalars_RoundTrip()
    {
        var bytes = Write(w =>
        {
            w.WriteByte(0xAB);
            w.WriteBoolean(true);
            w.WriteBoolean(false);
            w.WriteUInt32(0x01020304);
            w.WriteUInt64(0x0102030405060708);
        });
        await Assert.That(Convert.ToHexString(bytes)).IsEqualTo("AB" + "01" + "00" + "01020304" + "0102030405060708");

        var (b, t, f, u32, u64, empty, remaining) = ReadScalars(bytes);
        await Assert.That(b).IsEqualTo((byte)0xAB);
        await Assert.That(t).IsTrue();
        await Assert.That(f).IsFalse();
        await Assert.That(u32).IsEqualTo(0x01020304u);
        await Assert.That(u64).IsEqualTo(0x0102030405060708ul);
        await Assert.That(empty).IsTrue();
        await Assert.That(remaining).IsEqualTo(0);
    }

    [Test]
    public async Task Strings_EncodeLikeRfc4251()
    {
        // RFC 4251 section 5: the string "testing" is 00 00 00 07 't' 'e' 's' 't' 'i' 'n' 'g'.
        await Assert.That(HexOf(w => w.WriteString("testing"))).IsEqualTo("00000007" + "74657374696E67");
        await Assert.That(HexOf(w => w.WriteString(new byte[] { 1, 2, 3 }))).IsEqualTo("00000003010203");
    }

    [Test]
    public async Task Strings_RoundTrip()
    {
        var unicode = Write(w => w.WriteString("h\u00e9llo"));
        var raw = Write(w => w.WriteString(new byte[] { 1, 2, 3 }));
        await Assert.That(ReadUtf8(unicode)).IsEqualTo("h\u00e9llo");
        await Assert.That(Convert.ToHexString(ReadBytesString(raw))).IsEqualTo("010203");
    }

    private static string ReadUtf8(byte[] data) => new SshReader(data).ReadUtf8String();

    private static byte[] ReadBytesString(byte[] data) => new SshReader(data).ReadString().ToArray();

    private static (int Taken, int Left) ReadBytesCount(byte[] data, int n)
    {
        var r = new SshReader(data);
        return (r.ReadBytes(n).Length, r.Remaining.Length);
    }

    [Test]
    public async Task ReadBytes_TakesExactlyThatMany()
    {
        var (taken, left) = ReadBytesCount([1, 2, 3, 4], 3);
        await Assert.That(taken).IsEqualTo(3);
        await Assert.That(left).IsEqualTo(1);
    }

    private static string[] ReadNames(byte[] data) => [.. new SshReader(data).ReadNameList()];

    [Test]
    public async Task NameList_RoundTrip_AndRfcExamples()
    {
        // RFC 4251: the empty list is 00 00 00 00; ("zlib","none") is 00 00 00 09 "zlib,none".
        await Assert.That(HexOf(w => w.WriteNameList([]))).IsEqualTo("00000000");
        var bytes = Write(w => w.WriteNameList(["zlib", "none"]));
        await Assert.That(Convert.ToHexString(bytes)).IsEqualTo("00000009" + "7A6C69622C6E6F6E65");
        await Assert.That(string.Join("|", ReadNames(bytes))).IsEqualTo("zlib|none");
        await Assert.That(ReadNames(Write(w => w.WriteNameList([]))).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Mpint_MatchesRfc4251Examples()
    {
        // RFC 4251 section 5 examples (non-negative ones).
        await Assert.That(HexOf(w => w.WriteMpint([]))).IsEqualTo("00000000");
        await Assert.That(HexOf(w => w.WriteMpint([0, 0]))).IsEqualTo("00000000");
        await Assert.That(HexOf(w => w.WriteMpint(Convert.FromHexString("09A378F9B2E332A7")))).IsEqualTo("0000000809A378F9B2E332A7");
        await Assert.That(HexOf(w => w.WriteMpint([0x80]))).IsEqualTo("000000020080");
        await Assert.That(HexOf(w => w.WriteMpint([0, 0, 0x7F]))).IsEqualTo("000000017F");
    }

    private static byte[] ReadMpintBytes(byte[] data) => new SshReader(data).ReadMpint().ToArray();

    [Test]
    public async Task Mpint_RoundTripsMagnitude()
    {
        var value = Convert.FromHexString("80112233");
        await Assert.That(Convert.ToHexString(ReadMpintBytes(Write(w => w.WriteMpint(value))))).IsEqualTo("80112233");
        await Assert.That(ReadMpintBytes(Write(w => w.WriteMpint([]))).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Mpint_RejectsNegativeAndNonMinimal()
    {
        await Assert.That(Fails(Convert.FromHexString("000000019C"), r => r.ReadMpint())).IsTrue();
        await Assert.That(Fails(Convert.FromHexString("00000002007F"), r => r.ReadMpint())).IsTrue();
    }

    [Test]
    public async Task Reader_RejectsTruncatedData()
    {
        await Assert.That(Fails([], r => r.ReadByte())).IsTrue();
        await Assert.That(Fails([1, 2, 3], r => r.ReadUInt32())).IsTrue();
        await Assert.That(Fails([1, 2, 3, 4, 5, 6, 7], r => r.ReadUInt64())).IsTrue();
        await Assert.That(Fails([0, 0, 0, 5, 1, 2], r => r.ReadString())).IsTrue();
        await Assert.That(Fails([1], r => r.ReadBytes(2))).IsTrue();
        await Assert.That(() => new SshReaderAction([1]).ReadBytes(-1)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Reader_RejectsOversizedStringWithoutTrustingTheLength()
    {
        // A claimed length of 4 GiB must be refused, not trusted; so must one byte past the limit.
        await Assert.That(Fails([0xFF, 0xFF, 0xFF, 0xFF], r => r.ReadString())).IsTrue();
        await Assert.That(Fails([0, 4, 0, 1], r => r.ReadString())).IsTrue();
    }

    [Test]
    public async Task Reader_RejectsInvalidUtf8_AndBadNameLists()
    {
        await Assert.That(Fails([0, 0, 0, 1, 0xFF], r => r.ReadUtf8String())).IsTrue();
        await Assert.That(Fails([0, 0, 0, 3, (byte)'a', (byte)',', (byte)','], r => r.ReadNameList())).IsTrue();
        await Assert.That(Fails([0, 0, 0, 3, (byte)'a', (byte)' ', (byte)'b'], r => r.ReadNameList())).IsTrue();
        await Assert.That(Fails([0, 0, 0, 1, 0xC3], r => r.ReadNameList())).IsTrue();
    }

    [Test]
    public async Task Writer_HandlesLargeValuesAcrossBufferGrowth()
    {
        var big = new byte[100_000];
        Array.Fill(big, (byte)7);
        var bytes = Write(w =>
        {
            w.WriteString(big);
            w.WriteString("tail");
        });
        await Assert.That(ReadBytesString(bytes).Length).IsEqualTo(100_000);
        await Assert.That(bytes.Length).IsEqualTo(4 + 100_000 + 4 + 4);
    }

    [Test]
    public async Task Writer_ArgumentsAreChecked()
    {
        var w = new SshWriter(new ArrayBufferWriter<byte>());
        await Assert.That(() => w.WriteString((string)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => w.WriteNameList(null!)).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task Exceptions_CarryAReason()
    {
        var protocol = new SshProtocolException("bad");
        await Assert.That(protocol.Reason).IsEqualTo(SshFailureReason.ProtocolError);
        await Assert.That(protocol.Message).IsEqualTo("bad");

        var inner = new InvalidOperationException("inner");
        var general = new SshException(SshFailureReason.Timeout, "slow", inner);
        await Assert.That(general.Reason).IsEqualTo(SshFailureReason.Timeout);
        await Assert.That(general.InnerException).IsEqualTo(inner);
    }

    [Test]
    public async Task MessageNumbers_MatchRfc4250()
    {
        await Assert.That(Id(SshMessage.Disconnect)).IsEqualTo((byte)1);
        await Assert.That(Id(SshMessage.KexInit)).IsEqualTo((byte)20);
        await Assert.That(Id(SshMessage.NewKeys)).IsEqualTo((byte)21);
        await Assert.That(Id(SshMessage.UserAuthRequest)).IsEqualTo((byte)50);
        await Assert.That(Id(SshMessage.ChannelOpen)).IsEqualTo((byte)90);
        await Assert.That(Id(SshMessage.ChannelFailure)).IsEqualTo((byte)100);
        await Assert.That((uint)Id(DisconnectReason.ByApplication)).IsEqualTo(11u);
    }
}