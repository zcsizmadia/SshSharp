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
    /// <paramref name="compression"/>, when set, takes the place of the host's <c>Compression</c>.
    /// </summary>
    public static AlgorithmPreferences FromConfig(SshHostConfig config, bool fipsMode = false, bool? compression = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        return From(SshAlgorithmList.FromConfig(config.KexAlgorithms), SshAlgorithmList.FromConfig(config.HostKeyAlgorithms),
            SshAlgorithmList.FromConfig(config.Ciphers), SshAlgorithmList.FromConfig(config.Macs), compression ?? config.Compression, fipsMode);
    }

    /// <summary>Builds preferences from the typed lists of <see cref="SshClientOptions"/>, whose names were checked when they were set.</summary>
    /// <exception cref="ArgumentException">A list leaves no algorithm of its kind that this platform (and FIPS mode) allows.</exception>
    public static AlgorithmPreferences FromOptions(SshClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var preferences = From(options.KexAlgorithms, options.HostKeyAlgorithms, options.Ciphers, options.Macs, options.Compression, options.FipsMode);
        var mode = options.FipsMode ? " in FIPS mode" : string.Empty;
        foreach (var (list, name, kind) in new[]
        {
            (preferences.Kex, nameof(SshClientOptions.KexAlgorithms), "key exchange"),
            (preferences.HostKeys, nameof(SshClientOptions.HostKeyAlgorithms), "host key"),
            (preferences.Ciphers, nameof(SshClientOptions.Ciphers), "cipher"),
            (preferences.Macs, nameof(SshClientOptions.Macs), "MAC"),
        })
        {
            // Said now, with the option named, rather than as a negotiation failure that looks like the server's doing.
            if (list.Count == 0)
            {
                throw new ArgumentException($"SshClientOptions.{name} leaves no {kind} algorithm that SshSharp can use on this platform{mode}.",
                    nameof(options));
            }
        }

        return preferences;
    }

    /// <summary>
    /// The defaults with each list applied, without the algorithms this platform lacks (ML-KEM before .NET 10), restricted to FIPS-approved
    /// ones in FIPS mode. The one path for both ssh_config and <see cref="SshClientOptions"/>. Compression is not restricted in FIPS mode:
    /// zlib is not a cryptographic algorithm, and FIPS 140 says nothing about it.
    /// </summary>
    private static AlgorithmPreferences From(SshAlgorithmList? kex, SshAlgorithmList? hostKeys, SshAlgorithmList? ciphers, SshAlgorithmList? macs,
        bool compression, bool fipsMode)
    {
        IReadOnlyList<string> Resolve(SshAlgorithmList? spec, IReadOnlyList<string> defaults, AlgorithmKind kind)
        {
            var list = spec is null ? defaults : spec.Apply(defaults);
            list = [.. list.Where(n => IsImplemented(n, kind))];
            return fipsMode ? SshAlgorithms.FilterFips(list, kind) : list;
        }

        return new AlgorithmPreferences
        {
            Kex = Resolve(kex, SshAlgorithms.DefaultKex, AlgorithmKind.Kex),
            HostKeys = Resolve(hostKeys, SshAlgorithms.DefaultHostKeys, AlgorithmKind.HostKey),
            Ciphers = Resolve(ciphers, SshAlgorithms.DefaultCiphers, AlgorithmKind.Cipher),
            Macs = Resolve(macs, SshAlgorithms.DefaultMacs, AlgorithmKind.Mac),
            Compression = compression ? SshAlgorithms.EnabledCompression : SshAlgorithms.DefaultCompression,
        };
    }

    /// <summary>
    /// Checks a list set on <see cref="SshClientOptions"/>: every name (and every pattern without wildcards) must be an algorithm of
    /// <paramref name="kind"/> that SshSharp knows, so a typo is reported rather than quietly matching nothing.
    /// </summary>
    /// <exception cref="ArgumentException">A name is not one SshSharp knows for this kind.</exception>
    public static SshAlgorithmList? Validate(SshAlgorithmList? list, AlgorithmKind kind, string parameterName)
    {
        if (list is null)
        {
            return null;
        }

        var known = Known(kind);
        foreach (var name in list.Algorithms)
        {
            if (list.IsRemoval && name.AsSpan().IndexOfAny('*', '?') >= 0)
            {
                continue;
            }

            if (!known.Contains(name, StringComparer.Ordinal))
            {
                var what = kind switch
                {
                    AlgorithmKind.Kex => "key exchange algorithm",
                    AlgorithmKind.HostKey => "host key algorithm",
                    AlgorithmKind.Cipher => "cipher",
                    _ => "MAC",
                };
                throw new ArgumentException($"'{name}' is not a {what} SshSharp supports. Supported: {string.Join(", ", known)}.", parameterName);
            }
        }

        return list;
    }

    /// <summary>Every name SshSharp knows for <paramref name="kind"/>, also those this platform lacks (they are dropped when resolved).</summary>
    private static IReadOnlyList<string> Known(AlgorithmKind kind) => kind switch
    {
        AlgorithmKind.Kex => SshAlgorithms.AllKex,
        AlgorithmKind.HostKey => [.. SshAlgorithms.DefaultHostKeys, .. SshAlgorithms.CertificateHostKeys],
        AlgorithmKind.Cipher => SshAlgorithms.CipherNames,
        AlgorithmKind.Mac => SshAlgorithms.MacNames,
        _ => [],
    };

    /// <summary>These preferences with the certificate versions of the host key algorithms in front (only for algorithms already allowed).</summary>
    public AlgorithmPreferences WithCertificateHostKeysFirst() => new()
    {
        Kex = Kex,
        HostKeys = [.. SshAlgorithms.CertificateHostKeys.Where(c => HostKeys.Contains(SshCertificate.BaseAlgorithm(c))),
            .. HostKeys.Where(h => !SshCertificate.IsCertificateAlgorithm(h))],
        Ciphers = Ciphers,
        Macs = Macs,
        Compression = Compression,
    };

    private static bool IsImplemented(string name, AlgorithmKind kind) => kind switch
    {
        AlgorithmKind.Cipher => SshAlgorithms.IsKnownCipher(name),
        AlgorithmKind.Mac => SshAlgorithms.IsKnownMac(name),
        AlgorithmKind.Kex => SshAlgorithms.DefaultKex.Contains(name),
        AlgorithmKind.HostKey => SshAlgorithms.DefaultHostKeys.Contains(name) || SshAlgorithms.CertificateHostKeys.Contains(name),
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

        // AEAD ciphers authenticate themselves: the MAC is not used, so (like OpenSSH) a MAC list without a match is no reason to fail.
        var macC2S = IsAead(cipherC2S)
            ? TryPick(client.MacClientToServer, server.MacClientToServer) ?? string.Empty
            : Pick("MAC (client to server)", client.MacClientToServer, server.MacClientToServer);
        var macS2C = IsAead(cipherS2C)
            ? TryPick(client.MacServerToClient, server.MacServerToClient) ?? string.Empty
            : Pick("MAC (server to client)", client.MacServerToClient, server.MacServerToClient);
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

    private static bool IsAead(string cipher) => SshAlgorithms.TryGetCipher(cipher, out var info) && info.IsAead;

    private static string? TryPick(IReadOnlyList<string> client, IReadOnlyList<string> server, Func<string, bool>? accept = null)
    {
        foreach (var name in client)
        {
            if ((accept is null || accept(name)) && server.Contains(name))
            {
                return name;
            }
        }

        return null;
    }

    private static string Pick(string what, IReadOnlyList<string> client, IReadOnlyList<string> server, Func<string, bool>? accept = null)
    {
        if (TryPick(client, server, accept) is { } name)
        {
            return name;
        }

        throw new SshException(
            SshFailureReason.KeyExchangeFailed,
            $"No matching {what} algorithm. Client offered: {string.Join(',', client)}. Server offered: {string.Join(',', server)}.");
    }
}