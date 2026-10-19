using SshSharp.Config;

namespace SshSharp.Tests.Config;

/// <summary>Resolving <c>TCPKeepAlive</c>, <c>IPQoS</c>, <c>StreamLocalBindMask</c> and <c>AddKeysToAgent ask</c>.</summary>
public class SocketAndAgentDirectivesTests
{
    private static readonly SshConfigResolveOptions Options = new() { LocalUser = "local", HomeDirectory = "/home/local" };

    private static SshHostConfig Resolve(string config) => SshConfig.Parse(config).Resolve("h", Options);

    [Test]
    [Arguments("", true)] // on by default, as in ssh
    [Arguments("TCPKeepAlive yes\n", true)]
    [Arguments("TCPKeepAlive no\n", false)]
    [Arguments("tcpkeepalive NO\n", false)]
    [Arguments("TCPKeepAlive no\nTCPKeepAlive yes\n", false)] // the first value wins
    public async Task TcpKeepAlive_Resolves(string config, bool expected) =>
        await Assert.That(Resolve(config).TcpKeepAlive).IsEqualTo(expected);

    [Test]
    [Arguments("", null, null)]
    [Arguments("IPQoS af21 cs1\n", 0x48, 0x20)]
    [Arguments("IPQoS ef\n", 0xb8, 0xb8)] // one value is both
    [Arguments("IPQoS EF CS0\n", 0xb8, 0x00)]
    [Arguments("IPQoS lowdelay throughput\n", 0x10, 0x08)]
    [Arguments("IPQoS reliability le\n", 0x04, 0x04)]
    [Arguments("IPQoS 184 0\n", 184, 0)]
    [Arguments("IPQoS 255\n", 255, 255)]
    [Arguments("IPQoS none\n", null, null)]
    [Arguments("IPQoS af11 none\n", 0x28, null)]
    [Arguments("IPQoS none af43\n", null, 0x98)]
    [Arguments("IPQoS 256\n", null, null)] // what ssh would refuse sets nothing
    [Arguments("IPQoS -1\n", null, null)]
    [Arguments("IPQoS 0x10\n", null, null)]
    [Arguments("IPQoS af44\n", null, null)]
    [Arguments("IPQoS af21 bogus\n", null, null)]
    [Arguments("IPQoS af21 cs1 ef\n", null, null)]
    [Arguments("IPQoS cs7 cs6\nIPQoS af11\n", 0xe0, 0xc0)] // the first line wins
    public async Task IPQoS_Resolves(string config, int? interactive, int? bulk)
    {
        var host = Resolve(config);
        await Assert.That(host.IPQoSInteractive).IsEqualTo(interactive);
        await Assert.That(host.IPQoSBulk).IsEqualTo(bulk);
    }

    [Test]
    public async Task IPQoS_KnowsEveryNameSshDoes()
    {
        // The DSCP code points of RFC 2474, 2597, 3246 and 8622, shifted into the type-of-service byte.
        (string Name, int Value)[] names =
        [
            ("af11", 10 << 2), ("af12", 12 << 2), ("af13", 14 << 2), ("af21", 18 << 2), ("af22", 20 << 2), ("af23", 22 << 2),
            ("af31", 26 << 2), ("af32", 28 << 2), ("af33", 30 << 2), ("af41", 34 << 2), ("af42", 36 << 2), ("af43", 38 << 2),
            ("cs0", 0), ("cs1", 8 << 2), ("cs2", 16 << 2), ("cs3", 24 << 2), ("cs4", 32 << 2), ("cs5", 40 << 2), ("cs6", 48 << 2), ("cs7", 56 << 2),
            ("ef", 46 << 2), ("le", 1 << 2), ("lowdelay", 0x10), ("throughput", 0x08), ("reliability", 0x04),
        ];
        foreach (var (name, value) in names)
        {
            await Assert.That(SshConfig.ParseIPQoS([name])).IsEqualTo(((int?)value, (int?)value));
        }
    }

    [Test]
    [Arguments("", 0x7F)] // 0177, ssh's default
    [Arguments("StreamLocalBindMask 0177\n", 0x7F)]
    [Arguments("StreamLocalBindMask 0117\n", 0x4F)]
    [Arguments("StreamLocalBindMask 117\n", 0x4F)]
    [Arguments("StreamLocalBindMask 0\n", 0)]
    [Arguments("StreamLocalBindMask 0777\n", 0x1FF)]
    [Arguments("StreamLocalBindMask 0077\nStreamLocalBindMask 0\n", 0x3F)] // the first value wins
    [Arguments("StreamLocalBindMask 1000\n", 0x7F)] // above 0777: left out
    [Arguments("StreamLocalBindMask 0778\n", 0x7F)] // not octal
    [Arguments("StreamLocalBindMask 000117\n", 0x4F)] // leading zeros, as strtol takes them
    [Arguments("StreamLocalBindMask 77777777777777777\n", 0x7F)] // no overflow into a small value
    [Arguments("StreamLocalBindMask -1\n", 0x7F)]
    [Arguments("StreamLocalBindMask u=rw\n", 0x7F)]
    public async Task StreamLocalBindMask_Resolves(string config, int expected) =>
        await Assert.That(Resolve(config).StreamLocalBindMask).IsEqualTo((UnixFileMode)expected);

    [Test]
    [Arguments(0x7F, 0x180)] // 0177 leaves 0600
    [Arguments(0x4F, 0x1B0)] // 0117 leaves 0660
    [Arguments(0x12, 0x1ED)] // 0022 leaves 0755
    [Arguments(0, 0x1FF)]
    [Arguments(0x1FF, 0)]
    public async Task TheSocketMode_IsWhatTheMaskLeaves(int mask, int mode) =>
        await Assert.That(SshClient.SocketModeFromMask((UnixFileMode)mask)).IsEqualTo((UnixFileMode)mode);

    [Test]
    [Arguments("AddKeysToAgent ask\n", true)]
    [Arguments("AddKeysToAgent ASK\n", true)]
    [Arguments("AddKeysToAgent ask 1h\n", false)] // ssh refuses a lifetime with ask
    [Arguments("AddKeysToAgent yes\n", false)]
    [Arguments("AddKeysToAgent confirm\n", false)]
    [Arguments("AddKeysToAgent no\n", false)]
    [Arguments("", false)]
    [Arguments("AddKeysToAgent no\nAddKeysToAgent ask\n", false)] // the first value wins
    public async Task AddKeysToAgentAsk_Resolves(string config, bool ask)
    {
        var host = Resolve(config);
        await Assert.That(host.AddKeysToAgentAsk).IsEqualTo(ask);
        if (ask)
        {
            await Assert.That(host.AddKeysToAgent).IsNull(); // as before: code that reads only AddKeysToAgent adds nothing for ask
        }
    }
}
