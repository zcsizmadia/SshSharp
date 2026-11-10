using Microsoft.Extensions.Logging;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests;

/// <summary>
/// Text the server chose reaches exception messages and logs only cleaned (<see cref="ServerText"/>): no line break to forge a log line,
/// no terminal escape, no bidirectional override.
/// </summary>
public class ServerTextTests
{
    // A forged log line, a terminal escape (erase line, set the window title, bell) and a right-to-left override.
    private const string Hostile = "bye\r\n2026-11-07 info: Authenticated as admin\u001b[2K\u001b]0;pwned\u0007 \u202Eevil";

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static bool IsClean(string text) =>
        !text.EnumerateRunes().Any(r => System.Text.Rune.GetUnicodeCategory(r) is System.Globalization.UnicodeCategory.Control
            or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.LineSeparator
            or System.Globalization.UnicodeCategory.ParagraphSeparator);

    [Test]
    [Arguments(null, "")]
    [Arguments("", "")]
    [Arguments("  Permission denied  ", "Permission denied")]
    [Arguments("No such file\r\nor directory", "No such file or directory")]
    [Arguments("a\t\tb\n\nc", "a b c")]
    [Arguments("red\u001b[31m text", "red[31m text")]
    [Arguments("left\u202Eright\u2066x\u2069", "leftrightx")]
    [Arguments("zero\u200Bwidth", "zerowidth")]
    [Arguments("line\u2028para\u2029end", "line para end")]
    [Arguments("caf\u00E9 \u4E2D\u6587", "caf\u00E9 \u4E2D\u6587")]
    public async Task Clean_TurnsBreaksIntoOneSpace_AndDropsControlAndFormatCharacters(string? text, string expected)
    {
        await Assert.That(ServerText.Clean(text)).IsEqualTo(expected);
    }

    [Test]
    public async Task Clean_CutsAtTheLimit_NeverInsideASurrogatePair_AndReplacesAnUnpairedOne()
    {
        await Assert.That(ServerText.Clean(new string('x', 500))).IsEqualTo(new string('x', ServerText.MaxLength));

        // 199 characters, then an emoji (two UTF-16 units): it would end past 200, so it is left out whole.
        var text = new string('x', 199) + "\U0001F600" + "tail";
        await Assert.That(ServerText.Clean(text)).IsEqualTo(new string('x', 199));
        await Assert.That(ServerText.Clean("x\U0001F600", 3)).IsEqualTo("x\U0001F600");

        await Assert.That(ServerText.Clean("a\uD800b")).IsEqualTo("a\uFFFDb");
    }

    [Test]
    public async Task ADisconnectReason_ReachesTheExceptionCleaned()
    {
        await using var server = new FakeSshServer(new FakeServerOptions { DisconnectInsteadOfReply = Hostile });
        await using var transport = new SshSharp.Protocol.SshTransport(server.ClientStream, new SshSharp.Protocol.SshTransportOptions
        {
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
        });
        _ = server.StartAsync(Timeout());

        var error = await Assert.That(async () => await transport.ConnectAsync(Timeout())).Throws<SshException>();

        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.ConnectionClosed);
        await Assert.That(IsClean(error.Message)).IsTrue();
        await Assert.That(error.Message).Contains("bye 2026-11-07 info: Authenticated as admin[2K]0;pwned evil");
    }

    [Test]
    public async Task AChannelRefusal_ReachesTheExceptionCleaned()
    {
        await using var server = new FakeSessionServer { RefuseChannels = true, RefusalDescription = Hostile };
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, Options(), leaveOpen: true, Timeout());

        var error = await Assert.That(async () => await client.RunCommandAsync("true", Timeout())).Throws<SshException>();

        await Assert.That(IsClean(error!.Message)).IsTrue();
        await Assert.That(error.Message).Contains("bye 2026-11-07 info");
    }

    [Test]
    public async Task TheServersIdentification_IsLoggedCleaned_WhileTheExchangeHashUsesItAsSent()
    {
        // The comment part of the identification line is free text (ASCII, as the line is); the key exchange still succeeds, as the
        // hash covers the raw line.
        var logger = new ListLogger();
        await using var server = new FakeSessionServer(new FakeServerOptions { Identification = "SSH-2.0-FakeServer_1.0 x\u001b]0;pwned\u0007y\u001b[2Kz" });
        _ = server.StartAsync();
        await using var client = await SshClient.ConnectAsync(server.ClientStream, Options(logger), leaveOpen: true, Timeout());

        var logged = logger.Messages.Single(m => m.StartsWith("Server identification", StringComparison.Ordinal));
        await Assert.That(IsClean(logged)).IsTrue();
        await Assert.That(logged).EndsWith("SSH-2.0-FakeServer_1.0 x]0;pwnedy[2Kz");
    }

    [Test]
    public async Task AMalformedIdentification_IsEchoedCleaned()
    {
        await using var server = new FakeSshServer(new FakeServerOptions { Identification = "SSH-2.0-\u001b[2Kforged\u0007line" });
        await using var transport = new SshSharp.Protocol.SshTransport(server.ClientStream, new SshSharp.Protocol.SshTransportOptions
        {
            VerifyHostKey = (_, _) => ValueTask.FromResult(true),
        });
        _ = server.StartAsync(Timeout());

        var error = await Assert.That(async () => await transport.ConnectAsync(Timeout())).Throws<SshException>();

        await Assert.That(IsClean(error!.Message)).IsTrue();
        await Assert.That(error.Message).Contains("[2Kforgedline");
    }

    private static SshClientOptions Options(ILogger? logger = null) => new()
    {
        UserName = "tester",
        Password = TestSecrets.Password,
        HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        Logger = logger,
    };

    /// <summary>Collects log messages.</summary>
    private sealed class ListLogger : ILogger
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return [.. _messages];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception));
            }
        }
    }
}
