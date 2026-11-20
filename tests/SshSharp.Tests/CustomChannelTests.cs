using System.Buffers.Binary;
using System.Text;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>Channels of any type and global requests of any name (<see cref="SshClient.OpenChannelAsync"/>,
/// <see cref="SshClient.SendGlobalRequestAsync"/>), against the fake server.</summary>
public class CustomChannelTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        var options = new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        };
        return await SshClient.ConnectAsync(server.ClientStream, options, leaveOpen: true, Timeout());
    }

    /// <summary>An SSH string: a big-endian uint32 length, then the bytes.</summary>
    private static byte[] SshString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var result = new byte[4 + bytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(result, (uint)bytes.Length);
        bytes.CopyTo(result, 4);
        return result;
    }

    /// <summary>A service at the far end: reads until end of input, then answers with a prefix and what it read, and hangs up.</summary>
    private static DuplexStream PrefixService(string prefix)
    {
        var (near, far) = DuplexStream.CreatePair();
        _ = Task.Run(async () =>
        {
            var input = new MemoryStream();
            await far.CopyToAsync(input);
            await far.WriteAsync(Encoding.ASCII.GetBytes(prefix + Encoding.ASCII.GetString(input.ToArray())));
            await far.DisposeAsync();
        });
        return near;
    }

    [Test]
    public async Task ACustomChannel_CarriesItsTypeAndData_AndRelaysBothWays()
    {
        string? openedType = null;
        byte[]? openedData = null;
        await using var server = new FakeSessionServer
        {
            CustomChannel = (type, data) =>
            {
                openedType = type;
                openedData = data;
                return PrefixService("hello ");
            },
        };
        await using var client = await ConnectAsync(server);

        // The service answers only after end of input: half-close, then read the answer on the same channel.
        await using var channel = await client.OpenChannelAsync("my-channel@example.com", SshString("v1"), Timeout());
        await Assert.That(channel.ChannelType).IsEqualTo("my-channel@example.com");
        await channel.Stream.WriteAsync("world"u8.ToArray(), Timeout());
        await channel.ShutdownSendAsync(Timeout());
        await Assert.That(() => channel.Stream.WriteAsync("x"u8.ToArray(), Timeout()).AsTask()).Throws<InvalidOperationException>();

        var answer = new MemoryStream();
        await channel.Stream.CopyToAsync(answer, Timeout());
        await Assert.That(Encoding.ASCII.GetString(answer.ToArray())).IsEqualTo("hello world");
        await Assert.That(openedType).IsEqualTo("my-channel@example.com");
        await Assert.That(openedData).IsEquivalentTo(SshString("v1"));
    }

    [Test]
    public async Task ACustomChannelWithoutData_SendsNothingAfterTheType()
    {
        byte[]? openedData = null;
        await using var server = new FakeSessionServer
        {
            CustomChannel = (_, data) =>
            {
                openedData = data;
                return PrefixService("");
            },
        };
        await using var client = await ConnectAsync(server);
        using (await client.OpenChannelAsync("my-channel@example.com", cancellationToken: Timeout()))
        {
            await Assert.That(openedData).IsEmpty();
        }

        await client.PingAsync(Timeout());
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    public async Task AnUnknownChannelType_IsAChannelError_AndTheConnectionStaysUp()
    {
        await using var server = new FakeSessionServer { CustomChannel = (_, _) => null };
        await using var client = await ConnectAsync(server);

        var error = await Assert.ThrowsAsync<SshException>(() => client.OpenChannelAsync("nobody-knows@example.com", cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ChannelClosed);
        await Assert.That(client.IsConnected).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments("has space")]
    [Arguments("comma,separated")]
    [Arguments("two@at@example.com")]
    [Arguments("@example.com")]
    [Arguments("trailing@")]
    [Arguments("non-ascii-é")]
    [Arguments("session")]
    public async Task InvalidChannelTypes_AreRejectedBeforeAnythingIsSent(string channelType)
    {
        await using var server = new FakeSessionServer { CustomChannel = (_, _) => PrefixService("") };
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenChannelAsync(channelType, cancellationToken: Timeout()));
        await Assert.That(server.Channels).IsEmpty();
    }

    [Test]
    public async Task NamesAndData_AreLimited()
    {
        await using var server = new FakeSessionServer();
        await using var client = await ConnectAsync(server);
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenChannelAsync(new string('a', 65), cancellationToken: Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.SendGlobalRequestAsync(new string('a', 65), cancellationToken: Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.OpenChannelAsync("a@example.com", new byte[32_001], Timeout()));
        await Assert.ThrowsAsync<ArgumentException>(() => client.SendGlobalRequestAsync("a@example.com", new byte[32_001], Timeout()));
        await Assert.That(server.GlobalRequests).DoesNotContain("a@example.com");

        // 64 characters is the limit, not over it.
        var result = await client.SendGlobalRequestAsync(new string('a', 64), cancellationToken: Timeout());
        await Assert.That(result.Success).IsFalse();
    }

    [Test]
    public async Task AGlobalRequest_ReturnsTheServersAnswerAndItsData()
    {
        byte[]? received = null;
        await using var server = new FakeSessionServer
        {
            CustomGlobalRequest = (name, data) =>
            {
                if (name != "status@example.com")
                {
                    return null;
                }

                received = data;
                return SshString("ready");
            },
        };
        await using var client = await ConnectAsync(server);

        var granted = await client.SendGlobalRequestAsync("status@example.com", SshString("q"), Timeout());
        await Assert.That(granted.Success).IsTrue();
        await Assert.That(granted.Data.ToArray()).IsEquivalentTo(SshString("ready"));
        await Assert.That(received).IsEquivalentTo(SshString("q"));

        // A request the server does not know is answered with a failure, returned rather than thrown.
        var refused = await client.SendGlobalRequestAsync("unknown@example.com", cancellationToken: Timeout());
        await Assert.That(refused.Success).IsFalse();
        await Assert.That(refused.Data.IsEmpty).IsTrue();
        await Assert.That(client.IsConnected).IsTrue();
    }
}
