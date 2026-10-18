using System.Buffers;
using System.Text;
using SharpFuzz;
using SshSharp;
using SshSharp.Config;
using SshSharp.Keys;
using SshSharp.Protocol;

// Coverage-guided fuzz targets for every parser that reads untrusted input. Each target lets only the parser's documented
// exception through as a clean rejection; anything else escapes and libFuzzer reports it as a crash with the input that caused it.
// Run (Linux; see .github/workflows/fuzz.yml): libfuzzer-dotnet --target_path=SshSharp.Fuzz --target_arg=<target> corpus/
if (args.Length != 1 || !Targets.All.TryGetValue(args[0], out var target))
{
    Console.Error.WriteLine("Usage: SshSharp.Fuzz <target>. Targets: " + string.Join(", ", Targets.All.Keys));
    return 2;
}

Fuzzer.LibFuzzer.Run(span => target(span.ToArray()));
return 0;

/// <summary>The fuzz targets.</summary>
internal static class Targets
{
    public static readonly Dictionary<string, Action<byte[]>> All = new(StringComparer.Ordinal)
    {
        ["packet"] = Packet,
        ["kexinit"] = data => Protocol(() => KexInitMessage.Parse(data)),
        ["publickey"] = data => Protocol(() => VerifyingKey.Parse(data).VerifySignature(SshAlgorithms.SshEd25519, data, data)),
        ["publickey-text"] = data => Format(() => PublicKeyText(Encoding.UTF8.GetString(data), data)),
        ["certificate"] = data => Protocol(() => SshCertificate.FromBlob(data).CheckForHost("host", DateTimeOffset.UtcNow)),
        ["privatekey"] = data => Format(() => SshPrivateKey.Parse(Encoding.UTF8.GetString(data), "passphrase").Dispose()),
        ["privatekey-binary"] = data => Format(() => SshPrivateKey.Parse(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(data) + "\n-----END OPENSSH PRIVATE KEY-----\n", "passphrase").Dispose()),
        ["knownhosts"] = data => Format(() => KnownHostsFile.Parse(Encoding.UTF8.GetString(data)).Check("host", 22, "ssh-ed25519", data)),
        ["sshconfig"] = data => Format(() => SshConfig.Parse(Encoding.UTF8.GetString(data), "/nonexistent")
            .Resolve("host", new SshConfigResolveOptions { LocalUser = "u", HomeDirectory = "/nonexistent", LocalHostName = "l", GetEnvironmentVariable = _ => "v" })),
        ["identification"] = data => _ = SshIdentification.TryParse(Encoding.Latin1.GetString(data), out _),
        ["sftp"] = Sftp,
        ["krl"] = data => Format(() => RevokedKeyList.Parse(data).IsRevoked(data, null)),
    };

    /// <summary>Every reply an SFTP server can send; SftpException is an SshException, which is the documented rejection.</summary>
    private static void Sftp(byte[] data)
    {
        try
        {
            SshSharp.Sftp.SftpClient.ParseAnyReply(data);
        }
        catch (SshException)
        {
            // A clean rejection.
        }
    }

    private static void Packet(byte[] data)
    {
        var sequence = new ReadOnlySequence<byte>(data);
        Protocol(() =>
        {
            while (PacketCodec.TryDecode(sequence, PacketProtector.None, 0, out var packet, out var consumed))
            {
                packet!.Dispose();
                sequence = sequence.Slice(consumed);
            }
        });
    }

    /// <summary>A .pub or authorized_keys line through the public SshPublicKey: whatever parses must survive fingerprints and verifying garbage.</summary>
    private static void PublicKeyText(string line, byte[] data)
    {
        var key = SshPublicKey.Parse(line);
        _ = key.GetFingerprint(System.Security.Cryptography.HashAlgorithmName.MD5);
        _ = key.ToAuthorizedKeysLine();
        if (!key.KeyType.StartsWith("sk-", StringComparison.Ordinal))
        {
            key.VerifySignature(data, data);
        }
    }

    private static void Protocol(Action parse)
    {
        try
        {
            parse();
        }
        catch (SshProtocolException)
        {
            // A clean rejection.
        }
    }

    private static void Format(Action parse)
    {
        try
        {
            parse();
        }
        catch (FormatException)
        {
            // A clean rejection.
        }
    }
}
