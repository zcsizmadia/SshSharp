using SshSharp;
using SshSharp.Config;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/algorithms-and-authentication-order.md.</summary>
internal static class Algorithms
{
    public static async Task RemoveAsync(SshPrivateKey key, CancellationToken cancellationToken)
    {
        // <algorithms-remove>
        // SshSharp's defaults, less what this policy rules out. New defaults in later versions still apply.
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            KexAlgorithms = SshAlgorithmList.Remove("diffie-hellman-*"),
            Macs = SshAlgorithmList.Remove("hmac-sha2-256", "hmac-sha2-512"),   // encrypt-then-MAC only
        }, cancellationToken);
        // </algorithms-remove>
    }

    public static async Task OnlyAsync(SshPrivateKey key, CancellationToken cancellationToken)
    {
        // <algorithms-only>
        // Exactly these, in this order: a server that has none of a list's algorithms fails with KeyExchangeFailed.
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            KexAlgorithms = SshAlgorithmList.Only("mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256"),
            HostKeyAlgorithms = SshAlgorithmList.Only("ssh-ed25519", "ecdsa-sha2-nistp256"),
            Ciphers = SshAlgorithmList.Only("aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"),
        }, cancellationToken);

        Console.WriteLine($"{client.Algorithms.KeyExchange}, {client.Algorithms.EncryptionClientToServer}");
        // </algorithms-only>
    }

    public static SshClientOptions Prefer(SshPrivateKey key)
    {
        // <algorithms-prefer>
        // The defaults, with AES-128-GCM moved to the front (ssh_config's "^").
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            Ciphers = SshAlgorithmList.Prepend("aes128-gcm@openssh.com"),
        };
        // </algorithms-prefer>
        return options;
    }

    public static SshClientOptions FromSettings(SshPrivateKey key)
    {
        // <algorithms-parse>
        // A list from your own settings, in ssh_config's syntax ("-chacha20-poly1305@openssh.com", "+...", "^...", or a plain list).
        // A name SshSharp does not implement throws ArgumentException here, rather than being ignored.
        var ciphers = Environment.GetEnvironmentVariable("SSH_CIPHERS");
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            Ciphers = string.IsNullOrEmpty(ciphers) ? null : SshAlgorithmList.Parse(ciphers),
        };
        // </algorithms-parse>
        return options;
    }

    public static SshClientOptions KeysOnly(SshPrivateKey key)
    {
        // <auth-order>
        // A service account: log in with the key or not at all, even if a password is configured somewhere.
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            PreferredAuthentications = ["publickey"],
        };
        // </auth-order>
        return options;
    }

    public static SshClientOptions LargerRsa(SshPrivateKey key)
    {
        // <required-rsa-size>
        // Refuse RSA host keys under 3072 bits (the default minimum is 2048).
        var options = new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = [key],
            HostKeyVerifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes),
            RequiredRsaSize = 3072,
        };
        // </required-rsa-size>
        return options;
    }
}
