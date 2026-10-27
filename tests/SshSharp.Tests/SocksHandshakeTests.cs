using System.Net;
using System.Text;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// The SOCKS server's handshake on its own, byte by byte: what each malformed or refused request gets back, which the tests through a
/// real forwarder cannot all reach.
/// </summary>
public sealed class SocksHandshakeTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>Runs the handshake on <paramref name="client"/>'s bytes; returns its result and what it sent back.</summary>
    private static async Task<(SocksRequest? Request, byte[] Reply)> HandshakeAsync(byte[] client, SocksCredentials? credentials = null)
    {
        using var reply = new MemoryStream();
        await using var stream = new DuplexStream(new MemoryStream(client), reply);
        var request = await SocksHandshake.ReadRequestAsync(stream, credentials, Timeout());
        return (request, reply.ToArray());
    }

    /// <summary>A SOCKS 4 request: VN=4 | CD | port | address | user id | NUL, then <paramref name="name"/> | NUL for 4a.</summary>
    private static byte[] Socks4(byte command, int port, byte[] address, string? name = null) =>
        [4, command, (byte)(port >> 8), (byte)port, .. address, (byte)'u', 0, .. name is null ? Array.Empty<byte>() : [.. Encoding.ASCII.GetBytes(name), 0]];

    private static readonly byte[] Socks4Refused = [0, 0x5B, 0, 0, 0, 0, 0, 0];

    private static SocksCredentials Credentials(string password) => new(new NetworkCredential("user", password), "credentials");

    [Test]
    public async Task Socks4_AnAddressWithZerosInIt_IsAnAddress_NotA4aName()
    {
        // Only 0.0.0.x (x not 0) announces a 4a name; 10.0.0.5 and 0.0.1.5 are plain addresses.
        foreach (var address in new[] { new byte[] { 10, 0, 0, 5 }, [0, 0, 1, 5], [0, 1, 0, 5] })
        {
            var (request, reply) = await HandshakeAsync(Socks4(1, 80, address));
            await Assert.That(request).IsEqualTo(new SocksRequest(new IPAddress(address).ToString(), 80, 4));
            await Assert.That(reply).IsEmpty(); // the caller replies once it has connected
        }

        var (named, _) = await HandshakeAsync(Socks4(1, 80, [0, 0, 0, 1], "db.example.com"));
        await Assert.That(named).IsEqualTo(new SocksRequest("db.example.com", 80, 4));
    }

    [Test]
    [Arguments(2, 80)] // BIND
    [Arguments(1, 0)] // port 0
    public async Task Socks4_WhatThisProxyDoesNotDo_IsRefusedInTheReply(int command, int port)
    {
        var (request, reply) = await HandshakeAsync(Socks4((byte)command, port, [192, 0, 2, 1]));
        await Assert.That(request).IsNull();
        await Assert.That(reply).IsEquivalentTo(Socks4Refused);
    }

    [Test]
    public async Task Socks5_WithCredentials_AClientThatOffersNoPassword_IsTurnedAway()
    {
        // The refusal (no acceptable method) is sent before the exception, which makes the caller close the connection.
        var credentials = Credentials(TestSecrets.New());
        using var reply = new MemoryStream();
        await using var duplex = new DuplexStream(new MemoryStream([5, 1, 0]), reply);
        await Assert.That(async () => await SocksHandshake.ReadRequestAsync(duplex, credentials, Timeout())).Throws<SocksAuthenticationException>();
        await Assert.That(reply.ToArray()).IsEquivalentTo(new byte[] { 5, 0xFF });
    }

    [Test]
    public async Task Socks5_ARequestOrPasswordMessageOfAnotherVersion_IsMalformed()
    {
        // Greeting with no authentication, then a request that claims version 4.
        await Assert.That(async () => await HandshakeAsync([5, 1, 0, 4, 1, 0, 1, 192, 0, 2, 1, 0, 80])).Throws<IOException>();

        // Greeting with username/password, then a password message of version 2 (RFC 1929 has version 1).
        var credentials = Credentials(TestSecrets.New());
        var error = await Assert.ThrowsAsync<IOException>(async () => await HandshakeAsync([5, 1, 2, 2, 1, (byte)'u', 1, (byte)'p'], credentials));
        await Assert.That(error).IsNotTypeOf<SocksAuthenticationException>();
    }

    [Test]
    public async Task AClientThatStopsMidRequest_IsAnError() =>
        await Assert.That(async () => await HandshakeAsync([5, 1])).Throws<IOException>();
}
