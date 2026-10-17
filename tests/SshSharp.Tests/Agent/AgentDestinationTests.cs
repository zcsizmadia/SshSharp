using SshSharp.Config;

namespace SshSharp.Tests.Agent;

/// <summary>Destination constraints on agent keys (restrict-destination-v00@openssh.com, ssh-add -h).</summary>
public class AgentDestinationTests
{
    [Test]
    public async Task Destinations_CompareByContent_AndKeepTheirOwnCopies()
    {
        // The same key bytes in different arrays, and the same hosts in different lists: equal, as a value should be.
        var bytes = new byte[] { 1, 2, 3 };
        var keys = new List<SshAgentHostKey> { new(bytes.ToArray()) };
        var a = new SshAgentDestination { To = new SshAgentHost("dest.example", keys) { UserName = "alice" } };
        var b = new SshAgentDestination { To = new SshAgentHost("dest.example", [new SshAgentHostKey(bytes.ToArray())]) { UserName = "alice" } };

        await Assert.That(a).IsEqualTo(b);
        await Assert.That(a.GetHashCode()).IsEqualTo(b.GetHashCode());
        await Assert.That(new SshAgentHostKey(bytes, IsCertificateAuthority: true)).IsNotEqualTo(new SshAgentHostKey(bytes));

        // The host keeps its own copy of the keys: changing the caller's list afterwards changes nothing.
        keys.Add(new SshAgentHostKey(new byte[] { 9 }));
        await Assert.That(a.To.HostKeys.Count).IsEqualTo(1);

        var destinations = new List<SshAgentDestination> { a };
        var constraints = new SshAgentKeyConstraints { Destinations = destinations };
        destinations.Clear();
        await Assert.That(constraints.Destinations.Count).IsEqualTo(1);
    }

    // Throwaway host keys and the restrict-destination constraint bodies OpenSSH 10.6's ssh-add sent for them, captured from
    // "ssh-add -H known_hosts -h dest.example id" and
    // "ssh-add -H known_hosts -h 'jump.example>alice@dest.example' -h bob@host1.corp.test -t 600 -c id".
    private const string KnownHosts = """
        jump.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaPfPmIN8GTUGm4tUQrsPYevU/6Y4NTK4IqHbL7h85z
        dest.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOkewh434iIbqbv/KuJZxwFyWK/+6jAL9JHNyL0kRfBT
        @cert-authority *.corp.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEj2GgSG/QKrg55uGo7nlmg6jOtfYdz0Nw88OURD9k0k
        @revoked dest.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaPfPmIN8GTUGm4tUQrsPYevU/6Y4NTK4IqHbL7h85z
        """;

    private const string OneDestination =
        "000000680000000C00000000000000000000000000000050000000000000000C646573742E6578616D706C6500000000000000330000000B7373682D6564323535313900000020E91EC21E37E2221BA9BBFF2AE259C7017258AFFEEA300BF491CDC8BD2445F0530000000000";

    private const string HopAndAuthority =
        "000000B100000050000000000000000C6A756D702E6578616D706C6500000000000000330000000B7373682D6564323535313900000020068F7CF98837C1935069B8B5442BB0F61EBD4FFA6383532B822A1DB2FB87CE73000000005500000005616C6963650000000C646573742E6578616D706C6500000000000000330000000B7373682D6564323535313900000020E91EC21E37E2221BA9BBFF2AE259C7017258AFFEEA300BF491CDC8BD2445F05300000000000000006E0000000C0000000000000000000000000000005600000003626F620000000F686F7374312E636F72702E7465737400000000000000330000000B7373682D656432353531390000002048F61A0486FD02AB839E6E1A8EE796683A8CEB5F61DCF4370F3C394443F64D240100000000";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static readonly KnownHostsFile Hosts = KnownHostsFile.Parse(KnownHosts);

    [Test]
    public async Task TheConstraint_IsEncodedByteForByteAsSshAddEncodesIt()
    {
        await using var fake = new FakeAgent();
        var agent = new SshAgent(fake.Path);
        using var key = SshPrivateKey.Generate(SshKeyType.Ed25519, "id");

        await agent.AddKeyAsync(key, new SshAgentKeyConstraints { Destinations = [SshAgentDestination.Parse("dest.example", Hosts)] }, Timeout());
        await agent.AddKeyAsync(key, new SshAgentKeyConstraints
        {
            Lifetime = TimeSpan.FromSeconds(600),
            Confirm = true,
            Destinations = [SshAgentDestination.Parse("jump.example>alice@dest.example", Hosts), SshAgentDestination.Parse("bob@host1.corp.test", Hosts)],
        }, Timeout());

        await Assert.That(Convert.ToHexString(fake.AddRequests[0].Extensions["restrict-destination-v00@openssh.com"])).IsEqualTo(OneDestination);
        var second = fake.AddRequests[1];
        await Assert.That(Convert.ToHexString(second.Extensions["restrict-destination-v00@openssh.com"])).IsEqualTo(HopAndAuthority);
        await Assert.That((second.LifetimeSeconds, second.Confirm)).IsEqualTo((600u, true));
    }

    [Test]
    public async Task Parse_ReadsUsersHopsAndAuthorities_AndLeavesRevokedKeysOut()
    {
        var hop = SshAgentDestination.Parse("jump.example>alice@dest.example", Hosts);
        await Assert.That(hop.From!.HostName).IsEqualTo("jump.example");
        await Assert.That(hop.From.UserName).IsNull();
        await Assert.That(hop.To.HostName).IsEqualTo("dest.example");
        await Assert.That(hop.To.UserName).IsEqualTo("alice");
        await Assert.That(hop.To.HostKeys.Count).IsEqualTo(1); // the @revoked line is left out

        var authority = SshAgentDestination.Parse("host1.corp.test", Hosts);
        await Assert.That(authority.From).IsNull();
        await Assert.That(authority.To.HostKeys.Single().IsCertificateAuthority).IsTrue();
    }

    [Test]
    [Arguments("unknown.example")]
    [Arguments("a>b>c")]
    [Arguments("root@jump.example>dest.example")]
    [Arguments("@dest.example")]
    [Arguments("dest.example>")]
    public async Task MalformedOrUnknownDestinations_AreRejected(string specification)
    {
        await Assert.That(() => SshAgentDestination.Parse(specification, Hosts)).Throws<FormatException>();
    }

    [Test]
    public async Task HostsWithoutKeys_OrAUserOnTheFromHost_AreRejectedByTheConstraints()
    {
        var keyless = new SshAgentDestination { To = new SshAgentHost("dest.example", []) };
        await Assert.That(() => new SshAgentKeyConstraints { Destinations = [keyless] }).Throws<ArgumentException>();

        var key = new SshAgentHostKey(Hosts.Entries[0].PublicKey);
        var userOnFrom = new SshAgentDestination { From = new SshAgentHost("jump.example", [key]) { UserName = "root" }, To = new SshAgentHost("dest.example", [key]) };
        await Assert.That(() => new SshAgentKeyConstraints { Destinations = [userOnFrom] }).Throws<ArgumentException>();
    }
}
