using System.Text;
using SshSharp.Scp;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Scp;

/// <summary>SCP uploads and downloads against a scripted remote scp (sink and source modes), including a hostile one.</summary>
public sealed class ScpTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "sshsharp-scp-" + Guid.NewGuid().ToString("N"));

    public ScpTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static async Task<SshClient> ConnectAsync(FakeSessionServer server)
    {
        _ = server.StartAsync();
        return await SshClient.ConnectAsync(server.ClientStream, new SshClientOptions
        {
            UserName = "tester",
            Password = TestSecrets.Password,
            HostKeyVerifier = SshHostKeyVerifier.FromDelegate((_, _) => ValueTask.FromResult(true)),
        }, leaveOpen: true, Timeout());
    }

    /// <summary>Reads what the client sends to the remote scp: bytes, lines and blocks, across channel packets.</summary>
    private sealed class Input(ExecScript script)
    {
        private readonly Queue<byte> _pending = new();

        public async Task<int> ByteAsync()
        {
            while (_pending.Count == 0)
            {
                if (await script.ReadInputAsync() is not { } data)
                {
                    return -1;
                }

                foreach (var b in data)
                {
                    _pending.Enqueue(b);
                }
            }

            return _pending.Dequeue();
        }

        public async Task<string?> LineAsync()
        {
            var line = new List<byte>();
            while (await ByteAsync() is var b and not -1)
            {
                if (b == '\n')
                {
                    return Encoding.UTF8.GetString([.. line]);
                }

                line.Add((byte)b);
            }

            return line.Count == 0 ? null : throw new InvalidOperationException("Input ended mid-line.");
        }

        public async Task<byte[]> BytesAsync(long count)
        {
            var data = new byte[count];
            for (var i = 0; i < count; i++)
            {
                data[i] = (byte)await ByteAsync();
            }

            return data;
        }
    }

    /// <summary>The remote scp in sink mode (-t): records what arrives, as a list of entries, into <paramref name="received"/>.</summary>
    internal static Func<ExecScript, Task> Sink(List<string> received, Dictionary<string, byte[]> files, string? refuseWith = null) => async script =>
    {
        var input = new Input(script);
        var path = new List<string>();
        await script.StdoutAsync([0]); // ready
        while (await input.LineAsync() is { } line)
        {
            received.Add(line);
            switch (line[0])
            {
                case 'C':
                {
                    if (refuseWith is not null)
                    {
                        await script.StdoutAsync(Encoding.UTF8.GetBytes($"\x01{refuseWith}\n"));
                        continue;
                    }

                    var parts = line.Split(' ', 3);
                    await script.StdoutAsync([0]);
                    files[string.Join("/", [.. path, parts[2]])] = await input.BytesAsync(long.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture));
                    await input.ByteAsync(); // the end-of-data byte
                    await script.StdoutAsync([0]);
                    break;
                }

                case 'D':
                    path.Add(line.Split(' ', 3)[2]);
                    await script.StdoutAsync([0]);
                    break;
                case 'E':
                    path.RemoveAt(path.Count - 1);
                    await script.StdoutAsync([0]);
                    break;
                default:
                    await script.StdoutAsync([0]); // T
                    break;
            }
        }

        await script.FinishAsync(0);
    };

    /// <summary>The remote scp in source mode (-f): sends <paramref name="messages"/>, waiting for the client's acknowledgement before each.</summary>
    internal static Func<ExecScript, Task> Source(params byte[][] messages) => async script =>
    {
        var input = new Input(script);
        await input.ByteAsync(); // the client's "ready"
        foreach (var message in messages)
        {
            await script.StdoutAsync(message);
            if (message.Length > 0 && message[0] is not (1 or 2))
            {
                await input.ByteAsync(); // acknowledged (errors are not)
            }
        }

        await script.FinishAsync(0);
    };

    internal static byte[] Text(string text) => Encoding.UTF8.GetBytes(text);

    /// <summary>A file in source mode: its C line, then (after the acknowledgement) the data and the end-of-data byte.</summary>
    internal static byte[][] File(string name, string content, string mode = "0644") =>
        [Text($"C{mode} {Encoding.UTF8.GetByteCount(content)} {name}\n"), [.. Text(content), 0]];

    [Test]
    public async Task UploadingAFile_SendsItsLineAndData()
    {
        var received = new List<string>();
        var files = new Dictionary<string, byte[]>();
        await using var server = new FakeSessionServer { OnExec = Sink(received, files) };
        await using var client = await ConnectAsync(server);
        var local = Path.Combine(_dir, "report.csv");
        await System.IO.File.WriteAllTextAsync(local, "a,b\n1,2\n");
        var progress = new List<SshScpProgress>();
        await client.UploadFileAsync(local, "/srv/in box/it's.csv", new SshScpOptions { Progress = new SynchronousProgress(progress) }, Timeout());

        // The remote path is one shell word, whatever it contains.
        await Assert.That(server.Commands.Single()).IsEqualTo("scp -t -- '/srv/in box/it'\\''s.csv'");
        await Assert.That(received).IsEquivalentTo(new[] { "C0644 8 report.csv" });
        await Assert.That(Encoding.UTF8.GetString(files["report.csv"])).IsEqualTo("a,b\n1,2\n");
        await Assert.That(progress.Last()).IsEqualTo(new SshScpProgress("/srv/in box/it's.csv", 8, 8));
    }

    [Test]
    public async Task UploadingAStream_NeedsItsLength_AndPreservesTimesWhenAsked()
    {
        var received = new List<string>();
        var files = new Dictionary<string, byte[]>();
        await using var server = new FakeSessionServer { OnExec = Sink(received, files) };
        await using var client = await ConnectAsync(server);

        await client.UploadAsync(new MemoryStream(Text("hello")), "/tmp/greeting.txt", cancellationToken: Timeout());
        await Assert.That(received.Last()).IsEqualTo("C0644 5 greeting.txt");

        var unseekable = new UnseekableStream(Text("x"));
        await Assert.That(() => client.UploadAsync(unseekable, "/tmp/x", cancellationToken: Timeout())).Throws<ArgumentException>();
        await client.UploadAsync(unseekable, "/tmp/x", length: 1, new SshScpOptions { FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite }, Timeout());
        await Assert.That(received.Last()).IsEqualTo("C0600 1 x");

        // A stream shorter than it claimed fails rather than sending a short file.
        await Assert.That(() => client.UploadAsync(new MemoryStream(Text("ab")), "/tmp/short", length: 10, cancellationToken: Timeout())).Throws<IOException>();
    }

    [Test]
    public async Task UploadingADirectory_SendsItsTree()
    {
        var received = new List<string>();
        var files = new Dictionary<string, byte[]>();
        await using var server = new FakeSessionServer { OnExec = Sink(received, files) };
        await using var client = await ConnectAsync(server);
        var root = Directory.CreateDirectory(Path.Combine(_dir, "site"));
        await System.IO.File.WriteAllTextAsync(Path.Combine(root.FullName, "index.html"), "<h1>hi</h1>");
        Directory.CreateDirectory(Path.Combine(root.FullName, "css"));
        await System.IO.File.WriteAllTextAsync(Path.Combine(root.FullName, "css", "site.css"), "body{}");
        Directory.CreateDirectory(Path.Combine(root.FullName, "empty"));

        await client.UploadDirectoryAsync(root.FullName, "/var/www", new SshScpOptions { Preserve = true }, Timeout());

        await Assert.That(server.Commands.Single()).IsEqualTo("scp -r -t -p -- '/var/www'");
        await Assert.That(received.Where(l => l[0] != 'T')).IsEquivalentTo(new[] { "D0755 0 site", "C0644 11 index.html", "D0755 0 css", "C0644 6 site.css", "E", "D0755 0 empty", "E", "E" }, TUnit.Assertions.Enums.CollectionOrdering.Matching);
        await Assert.That(received.Count(l => l[0] == 'T')).IsEqualTo(5); // before each directory and file
        await Assert.That(Encoding.UTF8.GetString(files["site/css/site.css"])).IsEqualTo("body{}");
    }

    [Test]
    public async Task ARefusedUpload_ReportsTheServersMessage()
    {
        await using var server = new FakeSessionServer { OnExec = Sink([], [], refuseWith: "scp: /root/x: Permission denied") };
        await using var client = await ConnectAsync(server);
        var error = await Assert.ThrowsAsync<SshException>(() => client.UploadAsync(new MemoryStream(Text("x")), "/root/x", cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.TransferFailed);
        await Assert.That(error.Message).IsEqualTo("scp: /root/x: Permission denied");
    }

    [Test]
    public async Task DownloadingAFile_IntoAPath_IntoADirectory_AndIntoAStream()
    {
        await using var server = new FakeSessionServer { OnExec = Source(File("notes.txt", "remember\n")) };
        await using var client = await ConnectAsync(server);

        var target = Path.Combine(_dir, "copy.txt");
        await client.DownloadFileAsync("/home/u/notes.txt", target, cancellationToken: Timeout());
        await Assert.That(await System.IO.File.ReadAllTextAsync(target)).IsEqualTo("remember\n");
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -f -- '/home/u/notes.txt'");

        await client.DownloadFileAsync("/home/u/notes.txt", _dir, cancellationToken: Timeout()); // an existing directory: the remote name
        await Assert.That(await System.IO.File.ReadAllTextAsync(Path.Combine(_dir, "notes.txt"))).IsEqualTo("remember\n");

        using var memory = new MemoryStream();
        await client.DownloadAsync("/home/u/notes.txt", memory, cancellationToken: Timeout());
        await Assert.That(Encoding.UTF8.GetString(memory.ToArray())).IsEqualTo("remember\n");
        await Assert.That(memory.CanWrite).IsTrue(); // the caller's stream is left open
    }

    [Test]
    public async Task DownloadingADirectory_RebuildsTheTree_AndPreservesTimes()
    {
        var modified = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        var seconds = (long)(modified - DateTime.UnixEpoch).TotalSeconds;
        await using var server = new FakeSessionServer
        {
            OnExec = Source([
                Text("D0755 0 logs\n"),
                Text($"T{seconds} 0 {seconds} 0\n"), .. File("app.log", "started\n", "0600"),
                Text("D0700 0 old\n"), .. File("app.1.log", "before\n"), Text("E\n"),
                Text("E\n")]),
        };
        await using var client = await ConnectAsync(server);
        var target = Path.Combine(_dir, "fresh"); // does not exist: becomes the directory
        await client.DownloadDirectoryAsync("/var/log/app", target, new SshScpOptions { Preserve = true }, Timeout());

        await Assert.That(await System.IO.File.ReadAllTextAsync(Path.Combine(target, "app.log"))).IsEqualTo("started\n");
        await Assert.That(await System.IO.File.ReadAllTextAsync(Path.Combine(target, "old", "app.1.log"))).IsEqualTo("before\n");
        await Assert.That(System.IO.File.GetLastWriteTimeUtc(Path.Combine(target, "app.log"))).IsEqualTo(modified);
        if (!OperatingSystem.IsWindows())
        {
            await Assert.That(System.IO.File.GetUnixFileMode(Path.Combine(target, "app.log"))).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        await Assert.That(server.Commands.Single()).IsEqualTo("scp -r -f -p -- '/var/log/app'");
    }

    [Test]
    [Arguments("../escape.txt")]
    [Arguments("..")]
    [Arguments(".")]
    [Arguments("sub/escape.txt")]
    [Arguments("sub\\escape.txt")]
    [Arguments("C:escape.txt")]
    [Arguments("")]
    public async Task AHostileServer_CannotWriteOutsideTheTarget(string name)
    {
        // CVE-2019-6111: a server that answers a download with names of its choosing.
        await using var server = new FakeSessionServer { OnExec = Source(File(name, "owned")) };
        await using var client = await ConnectAsync(server);
        var target = Directory.CreateDirectory(Path.Combine(_dir, "target")).FullName;
        var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadFileAsync("/innocent.txt", target, cancellationToken: Timeout()));
        await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.TransferFailed);
        await Assert.That(Directory.EnumerateFileSystemEntries(_dir, "*", SearchOption.AllDirectories).Where(p => !p.StartsWith(target, StringComparison.Ordinal) || p != target)).IsEmpty();
    }

    [Test]
    [Arguments("CON", true)]
    [Arguments("nul.txt", true)]
    [Arguments("Com1", true)]
    [Arguments("LPT9.log", true)]
    [Arguments("COM¹", true)]
    [Arguments("aux .txt", true)]
    [Arguments("report.", true)] // Windows strips the dot: it would overwrite "report"
    [Arguments("report ", true)]
    [Arguments("CON", false)] // ordinary names elsewhere
    [Arguments("report.", false)]
    [Arguments("console.txt", null)]
    [Arguments("COM10", null)]
    [Arguments("LPT", null)]
    public async Task WindowsDeviceNames_AndTrailingDotsOrSpaces_AreRefusedOnWindows(string name, bool? windows)
    {
        if (windows is null)
        {
            await Assert.That(SshScpExtensions.CheckName(name, windows: true)).IsEqualTo(name);
            await Assert.That(SshScpExtensions.CheckName(name, windows: false)).IsEqualTo(name);
        }
        else if (windows.Value)
        {
            await Assert.That(() => SshScpExtensions.CheckName(name, windows: true)).Throws<SshException>();
        }
        else
        {
            await Assert.That(SshScpExtensions.CheckName(name, windows: false)).IsEqualTo(name);
        }
    }

    [Test]
    public async Task AHostileServer_CannotTurnAFileDownloadIntoMany_OrADirectory()
    {
        // Asked for one file, the server sends two (an extra file is how CVE-2019-6111 overwrote .bashrc), or a directory.
        await using (var server = new FakeSessionServer { OnExec = Source([.. File("a.txt", "1"), .. File("b.txt", "2")]) })
        {
            await using var client = await ConnectAsync(server);
            var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadFileAsync("/a.txt", _dir, cancellationToken: Timeout()));
            await Assert.That(error!.Message).Contains("more than one file");
            await Assert.That(System.IO.File.Exists(Path.Combine(_dir, "b.txt"))).IsFalse();
        }

        await using (var server = new FakeSessionServer { OnExec = Source(Text("D0755 0 dir\n"), Text("E\n")) })
        {
            await using var client = await ConnectAsync(server);
            var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadFileAsync("/a.txt", _dir, cancellationToken: Timeout()));
            await Assert.That(error!.Message).Contains("directory");
        }
    }

    [Test]
    public async Task MissingFilesAndMalformedMessages_AreTransferErrors()
    {
        // What OpenSSH's scp sends for a missing file, then exits 1.
        await using (var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                await script.ReadInputAsync();
                await script.StdoutAsync(Text("\x01scp: /nope: No such file or directory\n"));
                await script.FinishAsync(1);
            },
        })
        {
            await using var client = await ConnectAsync(server);
            using var sink = new MemoryStream();
            var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadAsync("/nope", sink, cancellationToken: Timeout()));
            await Assert.That(error!.Message).Contains("No such file or directory");
        }

        foreach (var bad in new[] { "C064 5 x\n", "C0644 -5 x\n", "C0644 five x\n", "C0899 5 x\n", "X0644 5 x\n", "T1 0\n" })
        {
            await using var server = new FakeSessionServer { OnExec = Source(Text(bad)) };
            await using var client = await ConnectAsync(server);
            using var sink = new MemoryStream();
            var error = await Assert.ThrowsAsync<SshException>(() => client.DownloadAsync("/x", sink, cancellationToken: Timeout()));
            await Assert.That(error!.Reason).IsEqualTo(SshFailureReason.TransferFailed);
        }
    }

    [Test]
    public async Task RemotePathsAreQuoted_AndUnquotablePathsRejected()
    {
        await Assert.That(ScpChannel.QuoteForShell("/a b/$(rm -rf ~)/`x`;'q'")).IsEqualTo("'/a b/$(rm -rf ~)/`x`;'\\''q'\\'''");
        await Assert.That(() => ScpChannel.QuoteForShell("a\nb")).Throws<ArgumentException>();
        await Assert.That(() => ScpChannel.QuoteForShell("")).Throws<ArgumentException>();
    }

    // ---- path quoting modes ----

    [Test]
    public async Task WithoutQuoting_ThePathGoesAsGiven_WithoutDoubleDash()
    {
        var received = new List<string>();
        await using var server = new FakeSessionServer
        {
            OnExec = script => script.Command.Contains(" -f ", StringComparison.Ordinal)
                ? Source(File("startup-config", "hostname r1\n"))(script)
                : Sink(received, [])(script),
        };
        await using var client = await ConnectAsync(server);
        var none = new SshScpOptions { PathQuoting = SshScpPathQuoting.None };

        await client.UploadAsync(new MemoryStream(Text("x")), "flash:/backup-2024_05.cfg", cancellationToken: Timeout(), options: none);
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -t flash:/backup-2024_05.cfg");

        await client.UploadAsync(new MemoryStream(Text("x")), "disk0:/a+b@c=d.rsc", length: 1,
            new SshScpOptions { PathQuoting = SshScpPathQuoting.None, Preserve = true }, Timeout());
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -t -p disk0:/a+b@c=d.rsc");

        // A device's file system prefix is not part of the name sent for a stream.
        await client.UploadAsync(new MemoryStream(Text("x")), "flash:running.cfg", cancellationToken: Timeout(), options: none);
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -t flash:running.cfg");
        await Assert.That(received.Where(l => l[0] == 'C')).IsEquivalentTo(new[] { "C0644 1 backup-2024_05.cfg", "C0644 1 a+b@c=d.rsc", "C0644 1 running.cfg" });

        using var memory = new MemoryStream();
        await client.DownloadAsync("nvram:startup-config", memory, none, Timeout());
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -f nvram:startup-config");
        await Assert.That(Encoding.UTF8.GetString(memory.ToArray())).IsEqualTo("hostname r1\n");

        var tree = Directory.CreateDirectory(Path.Combine(_dir, "cfg"));
        await System.IO.File.WriteAllTextAsync(Path.Combine(tree.FullName, "a.rsc"), "A");
        await client.UploadDirectoryAsync(tree.FullName, "flash/cfg", none, Timeout());
        await Assert.That(server.Commands.Last()).IsEqualTo("scp -r -t flash/cfg");
    }

    [Test]
    public async Task DoubleQuoting_WritesOneDoubleQuotedWord()
    {
        var received = new List<string>();
        await using var server = new FakeSessionServer
        {
            OnExec = script => script.Command.Contains(" -f ", StringComparison.Ordinal)
                ? Source(File("app.log", "ok\n"))(script)
                : Sink(received, [])(script),
        };
        await using var client = await ConnectAsync(server);
        var quoted = new SshScpOptions { PathQuoting = SshScpPathQuoting.DoubleQuote };

        // cmd.exe's & ^ ( ) ; and spaces, and a single quote, are all literal inside the double quotes.
        await client.UploadAsync(new MemoryStream(Text("x")), @"C:\Users\deploy\in box\a&b (1)'s;^.csv", cancellationToken: Timeout(), options: quoted);
        await Assert.That(server.Commands.Last()).IsEqualTo(@"scp -t -- ""C:\Users\deploy\in box\a&b (1)'s;^.csv""");
        await client.UploadAsync(new MemoryStream(Text("x")), "C:report.csv", cancellationToken: Timeout(), options: quoted);
        await Assert.That(received.Where(l => l[0] == 'C')).IsEquivalentTo(new[] { "C0644 1 a&b (1)'s;^.csv", "C0644 1 report.csv" }); // a Windows path's name

        using var memory = new MemoryStream();
        await client.DownloadAsync("C:/logs/app.log", memory,
            new SshScpOptions { PathQuoting = SshScpPathQuoting.DoubleQuote, Preserve = true, ScpCommand = "scp.exe" }, Timeout());
        await Assert.That(server.Commands.Last()).IsEqualTo(@"scp.exe -f -p -- ""C:/logs/app.log""");

        var tree = Directory.CreateDirectory(Path.Combine(_dir, "site"));
        await System.IO.File.WriteAllTextAsync(Path.Combine(tree.FullName, "index.html"), "hi");
        await client.UploadDirectoryAsync(tree.FullName, @"D:\www\site", quoted, Timeout());
        await Assert.That(server.Commands.Last()).IsEqualTo(@"scp -r -t -- ""D:\www\site""");
    }

    [Test]
    [Arguments("")]
    [Arguments("flash:/a b.cfg")]       // whitespace would split the path
    [Arguments("flash:/a\tb.cfg")]
    [Arguments("flash:/a\u00A0b.cfg")]  // so would Unicode spaces
    [Arguments("flash:/a\nreload")]     // control characters, always
    [Arguments("flash:/a\u0085b")]
    [Arguments("flash:/a\u2028b")]
    [Arguments("-oProxyCommand=x")]     // taken for an option, with no "--" before it
    [Arguments("flash:/a;reload")]      // and everything a shell would read, in case there is one after all
    [Arguments("flash:/$(id)")]
    [Arguments("flash:/`id`")]
    [Arguments("flash:/a|b")]
    [Arguments("flash:/a&b")]
    [Arguments("flash:/a>b")]
    [Arguments("flash:/'a'")]
    [Arguments("flash:/\"a\"")]
    [Arguments(@"flash:\a")]
    [Arguments("~/a")]
    [Arguments("a*")]
    [Arguments("a#b")]
    [Arguments("a%PATH%")]
    [Arguments("flash:/a,b")]           // PowerShell splits a word at a comma
    [Arguments("=ls")]                  // zsh and tcsh expand a leading =
    [Arguments("@args")]                // PowerShell splats a leading @
    [Arguments("a\U0001F600")]          // not a letter
    public async Task WithoutQuoting_ARiskyPath_IsRefusedBeforeAnythingIsSent(string path)
    {
        await using var server = new FakeSessionServer { OnExec = Sink([], []) };
        await using var client = await ConnectAsync(server);
        var options = new SshScpOptions { PathQuoting = SshScpPathQuoting.None };

        await Assert.That(() => ScpChannel.CheckUnquoted(path)).Throws<ArgumentException>();
        if (path.Length > 0)
        {
            var error = await Assert.ThrowsAsync<ArgumentException>(() => client.UploadAsync(new MemoryStream(Text("x")), path, cancellationToken: Timeout(), options: options));
            await Assert.That(error!.ParamName).IsEqualTo("remotePath");
            using var sink = new MemoryStream();
            await Assert.That(() => client.DownloadAsync(path, sink, options, Timeout())).Throws<ArgumentException>();
        }

        await Assert.That(server.Commands).IsEmpty();
    }

    [Test]
    [Arguments("")]
    [Arguments("C:\\a\r\nb")]           // control characters, always
    [Arguments("C:\\a\u001Bb")]
    [Arguments("C:\\a\u2029b")]
    [Arguments("C:\\a\" & calc & \"")]  // a quote would end the word
    [Arguments("C:\\%USERPROFILE%\\x")] // cmd.exe expands inside double quotes
    [Arguments("C:\\!x!")]              // so does delayed expansion
    [Arguments("C:\\$env:x")]           // and PowerShell
    [Arguments("C:\\$(calc)")]
    [Arguments("C:\\`x")]
    [Arguments("C:\\\u201Cx")]          // PowerShell's typographic double quotes end a string too
    [Arguments("C:\\\u201Dx")]
    [Arguments("C:\\\u201Ex")]
    [Arguments("C:\\a<b")]              // not in Windows names
    [Arguments("C:\\a>b")]
    [Arguments("C:\\a|b")]
    [Arguments("C:\\a*")]
    [Arguments("C:\\a?")]
    [Arguments("C:\\dir\\")]            // \" would be a literal quote to scp.exe
    [Arguments("C:\\")]
    [Arguments("-oProxyCommand=x")]     // an option, should the shell drop the "--" before it
    public async Task DoubleQuoting_ARiskyPath_IsRefusedBeforeAnythingIsSent(string path)
    {
        await using var server = new FakeSessionServer { OnExec = Sink([], []) };
        await using var client = await ConnectAsync(server);
        var options = new SshScpOptions { PathQuoting = SshScpPathQuoting.DoubleQuote };

        await Assert.That(() => ScpChannel.QuoteForCmd(path)).Throws<ArgumentException>();
        if (path.Length > 0)
        {
            var error = await Assert.ThrowsAsync<ArgumentException>(() => client.UploadAsync(new MemoryStream(Text("x")), path, cancellationToken: Timeout(), options: options));
            await Assert.That(error!.ParamName).IsEqualTo("remotePath");
            using var sink = new MemoryStream();
            await Assert.That(() => client.DownloadAsync(path, sink, options, Timeout())).Throws<ArgumentException>();
        }

        await Assert.That(server.Commands).IsEmpty();
    }

    [Test]
    public async Task EachMode_KeepsWhatItAllows_AndAnUnknownModeIsRefused()
    {
        await Assert.That(new SshScpOptions().PathQuoting).IsEqualTo(SshScpPathQuoting.Posix);
        await Assert.That(ScpChannel.CommandLine(new SshScpOptions(), "-t", "/a b")).IsEqualTo("scp -t -- '/a b'");
        await Assert.That(ScpChannel.CheckUnquoted("flash:/a-b_c.d")).IsEqualTo("flash:/a-b_c.d");
        await Assert.That(ScpChannel.CheckUnquoted("Konfiguráció/ünnep.rsc")).IsEqualTo("Konfiguráció/ünnep.rsc"); // letters of any script
        await Assert.That(ScpChannel.QuoteForCmd(@"C:\a b\c")).IsEqualTo(@"""C:\a b\c""");
        await Assert.That(ScpChannel.QuoteForCmd("C:/dir/")).IsEqualTo(@"""C:/dir/""");
        await Assert.That(ScpChannel.QuoteForCmd(@"\\server\share\x")).IsEqualTo(@"""\\server\share\x""");
        await Assert.That(() => ScpChannel.CommandLine(new SshScpOptions { PathQuoting = (SshScpPathQuoting)7 }, "-t", "/a"))
            .Throws<ArgumentOutOfRangeException>();
    }

    // ---- pooled buffers ----

    /// <summary>
    /// A pool that hands out fresh arrays and checks how they come back: each once, and none touched after its return (returned arrays
    /// are filled with a marker, and a later read would see the marker as data, a later write would change it).
    /// </summary>
    private sealed class CheckingPool : System.Buffers.ArrayPool<byte>
    {
        private const byte Returned = 0xCD;
        private readonly object _lock = new();
        private readonly HashSet<byte[]> _out = new(ReferenceEqualityComparer.Instance);
        private readonly List<byte[]> _returned = [];
        private int _rented;
        private int _doubleReturns;

        public int Rented { get { lock (_lock) { return _rented; } } }

        public int Outstanding { get { lock (_lock) { return _out.Count; } } }

        public int DoubleReturns { get { lock (_lock) { return _doubleReturns; } } }

        public bool ReturnedUntouched
        {
            get
            {
                lock (_lock)
                {
                    return _returned.All(a => a.All(b => b == Returned));
                }
            }
        }

        public override byte[] Rent(int minimumLength)
        {
            var array = new byte[minimumLength];
            lock (_lock)
            {
                _out.Add(array);
                _rented++;
            }

            return array;
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            lock (_lock)
            {
                if (!_out.Remove(array))
                {
                    _doubleReturns++;
                    return;
                }

                array.AsSpan().Fill(Returned);
                _returned.Add(array);
            }
        }

        /// <summary>Waits for every buffer to come back: the stderr reader returns its own when the session's end reaches it.</summary>
        public async Task<int> OutstandingAfterAsync(TimeSpan limit)
        {
            var deadline = DateTime.UtcNow + limit;
            while (Outstanding > 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            return Outstanding;
        }
    }

    private static async Task AssertAllReturnedAsync(CheckingPool pool, int atLeast)
    {
        await Assert.That(await pool.OutstandingAfterAsync(TimeSpan.FromSeconds(30))).IsEqualTo(0);
        await Assert.That(pool.Rented).IsGreaterThanOrEqualTo(atLeast);
        await Assert.That(pool.DoubleReturns).IsEqualTo(0);
        await Assert.That(pool.ReturnedUntouched).IsTrue();
    }

    [Test]
    public async Task PooledBuffers_AreReturnedOnce_AndNotUsedAfterwards_AfterAnUploadAndADownload()
    {
        var files = new Dictionary<string, byte[]>();
        var content = new byte[300_000];
        new Random(3).NextBytes(content);
        content[0] = 0x42; // not 1 or 2, which the scripted source would take for an error message
        await using var server = new FakeSessionServer
        {
            OnExec = script => script.Command.Contains(" -t ", StringComparison.Ordinal)
                ? Sink([], files)(script)
                : Source(Text($"C0644 {content.Length} big.bin\n"), [.. content, 0])(script),
        };
        await using var client = await ConnectAsync(server);
        var pool = new CheckingPool();

        // Upload: the read buffer, the stderr reader's and the file's data buffer.
        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-t", "/tmp/big.bin", Timeout(), pool))
        {
            await scp.ReadAckAsync(Timeout());
            await scp.SendLineAsync($"C0644 {content.Length} big.bin", Timeout());
            await scp.ReadAckAsync(Timeout());
            await scp.SendDataAsync(new MemoryStream(content), content.Length, _ => { }, Timeout());
            await scp.ReadAckAsync(Timeout());
            await scp.FinishAsync(Timeout());
        }

        await Assert.That(Convert.ToHexString(files["big.bin"])).IsEqualTo(Convert.ToHexString(content));
        await AssertAllReturnedAsync(pool, atLeast: 3);

        // Download: what was read into the pooled buffer arrives intact.
        using var sink = new MemoryStream();
        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-f", "/tmp/big.bin", Timeout(), pool))
        {
            await scp.SendAckAsync(Timeout());
            await Assert.That(await scp.ReadLineAsync(Timeout())).IsEqualTo($"C0644 {content.Length} big.bin");
            await scp.SendAckAsync(Timeout());
            await scp.ReadDataAsync(sink, content.Length, _ => { }, Timeout());
            await scp.ReadAckAsync(Timeout());
            await scp.SendAckAsync(Timeout());
            await scp.FinishAsync(Timeout());
        }

        await Assert.That(Convert.ToHexString(sink.ToArray())).IsEqualTo(Convert.ToHexString(content));
        await AssertAllReturnedAsync(pool, atLeast: 5);
    }

    [Test]
    public async Task PooledBuffers_AreReturned_WhenTheTransferFails_OrIsCancelled()
    {
        // The remote scp refuses the file; the local source is shorter than it claimed; the source stalls and the caller gives up; the
        // caller gives up waiting for an answer that never comes. Each time, every buffer goes back once, and none is used after that.
        await using var server = new FakeSessionServer
        {
            OnExec = async script =>
            {
                if (script.Command.Contains("refused", StringComparison.Ordinal))
                {
                    await Sink([], [], refuseWith: "scp: refused: Permission denied")(script);
                    return;
                }

                if (script.Command.Contains("silent", StringComparison.Ordinal))
                {
                    while (await script.ReadInputAsync() is not null)
                    {
                        // Never answers; ends when the client closes the channel.
                    }

                    await script.FinishAsync(1);
                    return;
                }

                await Sink([], [])(script);
            },
        };
        await using var client = await ConnectAsync(server);
        var pool = new CheckingPool();

        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-t", "/refused", Timeout(), pool))
        {
            await scp.ReadAckAsync(Timeout());
            await scp.SendLineAsync("C0644 5 x", Timeout());
            await Assert.That(async () => await scp.ReadAckAsync(Timeout())).Throws<SshException>();
        }

        await AssertAllReturnedAsync(pool, atLeast: 2);

        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-t", "/short", Timeout(), pool))
        {
            await scp.ReadAckAsync(Timeout());
            await scp.SendLineAsync("C0644 10 x", Timeout());
            await scp.ReadAckAsync(Timeout());
            await Assert.That(async () => await scp.SendDataAsync(new MemoryStream(Text("ab")), 10, _ => { }, Timeout())).Throws<IOException>();
        }

        await AssertAllReturnedAsync(pool, atLeast: 5);

        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-t", "/stalled", Timeout(), pool))
        {
            await scp.ReadAckAsync(Timeout());
            await scp.SendLineAsync("C0644 10 x", Timeout());
            await scp.ReadAckAsync(Timeout());
            using var giveUp = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await Assert.That(async () => await scp.SendDataAsync(new StallingStream(), 10, _ => { }, giveUp.Token)).Throws<OperationCanceledException>();
        }

        await AssertAllReturnedAsync(pool, atLeast: 8);

        await using (var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-f", "/silent", Timeout(), pool))
        {
            using var giveUp = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await Assert.That(async () => await scp.ReadAckAsync(giveUp.Token)).Throws<OperationCanceledException>();
        }

        await AssertAllReturnedAsync(pool, atLeast: 10);
    }

    [Test]
    public async Task AChannelUsedAfterDisposal_ThrowsRatherThanReadingAReturnedBuffer()
    {
        await using var server = new FakeSessionServer { OnExec = Sink([], []) };
        await using var client = await ConnectAsync(server);
        var pool = new CheckingPool();
        var scp = await ScpChannel.StartAsync(client, new SshScpOptions(), "-t", "/tmp/x", Timeout(), pool);
        await scp.DisposeAsync();
        await scp.DisposeAsync(); // once is enough; twice returns nothing twice
        await Assert.That(async () => await scp.ReadByteAsync(Timeout())).Throws<ObjectDisposedException>();
        await AssertAllReturnedAsync(pool, atLeast: 2);
    }

    /// <summary>A source whose reads never complete until cancelled.</summary>
    private sealed class StallingStream : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.Infinite, cancellationToken);
            return 0;
        }
    }
    private sealed class SynchronousProgress(List<SshScpProgress> sink) : IProgress<SshScpProgress>
    {
        public void Report(SshScpProgress value) => sink.Add(value);
    }

    private sealed class UnseekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }
}
