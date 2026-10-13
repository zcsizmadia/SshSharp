using SshSharp.Config;

namespace SshSharp.Protocol;

/// <summary>The client's ordered algorithm preferences.</summary>
internal sealed class AlgorithmPreferences
{
    public IReadOnlyList<string> Kex { get; init; } = SshAlgorithms.DefaultKex;

    public IReadOnlyList<string> HostKeys { get; init; } = SshAlgorithms.DefaultHostKeys;

    public IReadOnlyList<string> Ciphers { get; init; } = SshAlgorithms.DefaultCiphers;

    public IReadOnlyList<string> Macs { get; init; } = SshAlgorithms.DefaultMacs;

    public IReadOnlyList<string> Compression { get; init; } = SshAlgorithms.DefaultCompression;

    /// <summary>The default preferences restricted to FIPS-approved algorithms.</summary>
    public static AlgorithmPreferences Fips() => new()
    {
        Kex = SshAlgorithms.FilterFips(SshAlgorithms.DefaultKex, AlgorithmKind.Kex),
        HostKeys = SshAlgorithms.FilterFips(SshAlgorithms.DefaultHostKeys, AlgorithmKind.HostKey),
        Ciphers = SshAlgorithms.FilterFips(SshAlgorithms.DefaultCiphers, AlgorithmKind.Cipher),
        Macs = SshAlgorithms.FilterFips(SshAlgorithms.DefaultMacs, AlgorithmKind.Mac),
    };

    /// <summary>
    /// Builds preferences from the algorithm specifications of a resolved <c>ssh_config</c> host (<c>+</c>, <c>-</c>, <c>^</c> and plain lists)
    /// applied to the defaults, optionally restricted to FIPS-approved algorithms. Names this library does not implement are dropped.
    /// </summary>
    public static AlgorithmPreferences FromConfig(SshHostConfig config, bool fipsMode = false)
    {
        ArgumentNullException.ThrowIfNull(config);
        IReadOnlyList<string> Resolve(string? spec, IReadOnlyList<string> defaults, AlgorithmKind kind)
        {
            var list = spec is null ? defaults : SshAlgorithmList.Apply(spec, defaults);
            list = [.. list.Where(n => IsImplemented(n, kind))];
            return fipsMode ? SshAlgorithms.FilterFips(list, kind) : list;
        }

        return new AlgorithmPreferences
        {
            Kex = Resolve(config.KexAlgorithms, SshAlgorithms.DefaultKex, AlgorithmKind.Kex),
            HostKeys = Resolve(config.HostKeyAlgorithms, SshAlgorithms.DefaultHostKeys, AlgorithmKind.HostKey),
            Ciphers = Resolve(config.Ciphers, SshAlgorithms.DefaultCiphers, AlgorithmKind.Cipher),
            Macs = Resolve(config.Macs, SshAlgorithms.DefaultMacs, AlgorithmKind.Mac),
        };
    }

    private static bool IsImplemented(string name, AlgorithmKind kind) => kind switch
    {
        AlgorithmKind.Cipher => SshAlgorithms.IsKnownCipher(name),
        AlgorithmKind.Mac => SshAlgorithms.IsKnownMac(name),
        AlgorithmKind.Kex => SshAlgorithms.DefaultKex.Contains(name),
        AlgorithmKind.HostKey => SshAlgorithms.DefaultHostKeys.Contains(name),
        _ => true,
    };
}

/// <summary>The algorithms chosen for a key exchange.</summary>
internal sealed record NegotiatedAlgorithms(
    string Kex,
    string HostKey,
    string CipherClientToServer,
    string CipherServerToClient,
    string MacClientToServer,
    string MacServerToClient,
    string CompressionClientToServer,
    string CompressionServerToClient,
    bool StrictKex,
    bool ServerSupportsExtInfo,
    bool ServerGuessedWrong);

/// <summary>Picks algorithms per RFC 4253 section 7.1: the first algorithm in the client's list that the server also offers.</summary>
internal static class AlgorithmNegotiator
{
    public static NegotiatedAlgorithms Negotiate(KexInitMessage client, KexInitMessage server)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(server);

        var kex = Pick("key exchange", client.KexAlgorithms, server.KexAlgorithms, IsRealKex);
        var hostKey = Pick("host key", client.ServerHostKeyAlgorithms, server.ServerHostKeyAlgorithms);
        var cipherC2S = Pick("encryption (client to server)", client.EncryptionClientToServer, server.EncryptionClientToServer);
        var cipherS2C = Pick("encryption (server to client)", client.EncryptionServerToClient, server.EncryptionServerToClient);

        // AEAD ciphers authenticate themselves, but the MAC list must still be negotiable (OpenSSH always offers some).
        var macC2S = Pick("MAC (client to server)", client.MacClientToServer, server.MacClientToServer);
        var macS2C = Pick("MAC (server to client)", client.MacServerToClient, server.MacServerToClient);
        var compC2S = Pick("compression (client to server)", client.CompressionClientToServer, server.CompressionClientToServer);
        var compS2C = Pick("compression (server to client)", client.CompressionServerToClient, server.CompressionServerToClient);

        var strict = client.KexAlgorithms.Contains(SshAlgorithms.StrictKexClient) && server.KexAlgorithms.Contains(SshAlgorithms.StrictKexServer);
        var extInfo = server.KexAlgorithms.Contains(SshAlgorithms.ExtInfoServer);

        // If the server's first-packet guess used a different kex or host key than the negotiated ones, that packet must be discarded.
        var guessedWrong = server.FirstKexPacketFollows
            && (server.KexAlgorithms.FirstOrDefault(IsRealKex) != kex || server.ServerHostKeyAlgorithms[0] != hostKey);

        return new NegotiatedAlgorithms(kex, hostKey, cipherC2S, cipherS2C, macC2S, macS2C, compC2S, compS2C, strict, extInfo, guessedWrong);
    }

    private static bool IsRealKex(string name) =>
        name is not (SshAlgorithms.ExtInfoClient or SshAlgorithms.ExtInfoServer or SshAlgorithms.StrictKexClient or SshAlgorithms.StrictKexServer);

    private static string Pick(string what, IReadOnlyList<string> client, IReadOnlyList<string> server, Func<string, bool>? accept = null)
    {
        foreach (var name in client)
        {
            if ((accept is null || accept(name)) && server.Contains(name))
            {
                return name;
            }
        }

        throw new SshException(
            SshFailureReason.KeyExchangeFailed,
            $"No matching {what} algorithm. Client offered: {string.Join(',', client)}. Server offered: {string.Join(',', server)}.");
    }
}