using Microsoft.Extensions.Logging;
using SshSharp.Config;
using SshSharp.Keys;
using SshSharp.Protocol;

namespace SshSharp;

public sealed partial class SshClient
{
    private const string ProveRequest = "hostkeys-prove-00@openssh.com";

    /// <summary>Subscribes to the server's host key announcements when the verifier records updates (OpenSSH's UpdateHostKeys).</summary>
    private static void WatchHostKeyUpdates(SshConnection connection, SshClientOptions options, string? host, int port, SshHostKey hostKey, ILogger logger)
    {
        if (options.HostKeyVerifier is not KnownHostsVerifier { UpdateHostKeys: true } knownHosts || hostKey.Certificate is not null)
        {
            return;
        }

        if (new SshHostKeyContext(host, port, options.HostKeyAlias, hostKey).KnownHostsLookup is not var (name, lookupPort)
            || !KnownHostsEntry.IsLiteralHost(name))
        {
            return;
        }

        // The announcement arrives on the receive loop, which must not wait: the update runs on its own.
        var current = hostKey.PublicKey.ToArray();
        connection.HostKeysAnnounced = keys => _ = Task.Run(() => UpdateHostKeysAsync(connection, knownHosts, name, lookupPort, current, keys, logger));
    }

    /// <summary>
    /// PROTOCOL 2.5: asks the server to prove it holds the announced keys that known_hosts does not have (a signature over the request
    /// name, the session id and the key), and records the ones it proves. Any invalid proof cancels the whole update.
    /// </summary>
    private static async Task UpdateHostKeysAsync(SshConnection connection, KnownHostsVerifier knownHosts, string name, int port, byte[] current,
        IReadOnlyList<byte[]> announced, ILogger logger)
    {
        try
        {
            var supported = announced.Where(IsSupportedKey).ToList();
            if (supported.Count == 0)
            {
                return; // nothing usable announced: no reason to touch known_hosts, least of all to remove from it
            }

            // The key this connection was verified with stays, whatever the announcement says.
            supported.Add(current);
            var unknown = await knownHosts.UnknownHostKeysAsync(name, port, supported, connection.Closed).ConfigureAwait(false);
            if (unknown.Any(key => key.AsSpan().SequenceEqual(current)))
            {
                // The connection's own key is not in known_hosts: it was accepted although it changed (StrictHostKeyChecking no). The
                // server is unauthenticated, so it must not add keys, and above all must not have the real ones removed as stale.
                SshLog.HostKeyUpdateSkipped(logger, "the connection's host key is not in known_hosts");
                return;
            }

            var stale = await knownHosts.StaleHostKeysAsync(name, port, supported, connection.Closed).ConfigureAwait(false);
            if (unknown.Count == 0 && stale.Count == 0)
            {
                return;
            }

            List<byte[]> proven = [];
            if (unknown.Count > 0)
            {
                var reply = await connection.SendGlobalRequestAsync(ProveRequest, wantReply: true, w =>
                {
                    foreach (var key in unknown)
                    {
                        w.WriteString(key);
                    }
                }, connection.Closed).ConfigureAwait(false);
                if (!reply.Success)
                {
                    SshLog.HostKeyUpdateSkipped(logger, "the server declined to prove its keys");
                    return;
                }

                if (ProvenKeys(unknown, reply.Data, connection.SessionId.ToArray()) is not { } verified)
                {
                    SshLog.HostKeyUpdateSkipped(logger, "a proof did not verify"); // nothing is trusted, and nothing removed either
                    return;
                }

                proven = verified;
            }

            if (proven.Count == 0 && stale.Count == 0)
            {
                return;
            }

            if (knownHosts.ConfirmHostKeyUpdate is { } confirm
                && !await confirm(new SshHostKeyUpdate(name, port, [.. proven.Select(Describe)], [.. stale.Select(Describe)]), connection.Closed).ConfigureAwait(false))
            {
                SshLog.HostKeyUpdateSkipped(logger, "not confirmed");
                return;
            }

            await knownHosts.ApplyHostKeyUpdateAsync(name, port, proven, stale, connection.Closed).ConfigureAwait(false);
            SshLog.HostKeysUpdated(logger, proven.Count, stale.Count);
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException or FormatException
            or UnauthorizedAccessException)
        {
            var reason = ex.GetType().Name;
            SshLog.HostKeyUpdateSkipped(logger, reason);
        }
    }

    /// <summary>
    /// The keys whose proof verifies, or null when any proof is invalid (then nothing is trusted). Older OpenSSH proves RSA keys with
    /// SHA-1 "ssh-rsa" signatures when the connection's host key is not RSA; this client never trusts SHA-1, so such a key is just left
    /// out rather than counted as a forgery.
    /// </summary>
    private static List<byte[]>? ProvenKeys(List<byte[]> keys, byte[] proofs, byte[] sessionId)
    {
        var reader = new SshReader(proofs);
        var proven = new List<byte[]>();
        foreach (var key in keys)
        {
            var signature = reader.ReadString();
            var signed = SshPrivateKey.Encode(w =>
            {
                w.WriteString(ProveRequest);
                w.WriteString(sessionId);
                w.WriteString(key);
            });
            var algorithm = new SshReader(signature).ReadUtf8String();
            var publicKey = VerifyingKey.Parse(key);
            if (algorithm == "ssh-rsa" && publicKey.KeyType == "ssh-rsa")
            {
                continue;
            }

            if (!publicKey.VerifySignature(algorithm, signature, signed))
            {
                return null;
            }

            proven.Add(key);
        }

        return reader.IsEmpty ? proven : null;
    }

    /// <summary>A key as <c>ssh-keygen -l</c> names it: type and SHA-256 fingerprint.</summary>
    private static string Describe(byte[] blob)
    {
        var key = VerifyingKey.Parse(blob);
        return $"{key.KeyType} SHA256:{Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(blob)).TrimEnd('=')}";
    }

    internal static bool IsSupportedKey(byte[] blob)
    {
        try
        {
            VerifyingKey.Parse(blob);
            return true;
        }
        catch (SshProtocolException)
        {
            return false; // a type this client does not use (DSA, security keys); ssh skips those too
        }
    }
}
