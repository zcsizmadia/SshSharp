using Microsoft.Extensions.Logging;
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

        if (new SshHostKeyContext(host, port, options.HostKeyAlias, hostKey).KnownHostsLookup is not var (name, lookupPort))
        {
            return;
        }

        // The announcement arrives on the receive loop, which must not wait: the update runs on its own.
        connection.HostKeysAnnounced = keys => _ = Task.Run(() => UpdateHostKeysAsync(connection, knownHosts, name, lookupPort, keys, logger));
    }

    /// <summary>
    /// PROTOCOL 2.5: asks the server to prove it holds the announced keys that known_hosts does not have (a signature over the request
    /// name, the session id and the key), and records the ones it proves. Any invalid proof cancels the whole update.
    /// </summary>
    private static async Task UpdateHostKeysAsync(SshConnection connection, KnownHostsVerifier knownHosts, string name, int port,
        IReadOnlyList<byte[]> announced, ILogger logger)
    {
        try
        {
            var supported = announced.Where(IsSupportedKey).ToList();
            var unknown = await knownHosts.UnknownHostKeysAsync(name, port, supported, connection.Closed).ConfigureAwait(false);
            if (unknown.Count == 0)
            {
                return;
            }

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

            if (!AllProven(unknown, reply.Data, connection.SessionId.ToArray()))
            {
                SshLog.HostKeyUpdateSkipped(logger, "a proof did not verify");
                return;
            }

            await knownHosts.RecordProvenAsync(name, port, unknown, connection.Closed).ConfigureAwait(false);
            SshLog.HostKeysUpdated(logger, unknown.Count);
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException or FormatException
            or UnauthorizedAccessException)
        {
            var reason = ex.GetType().Name;
            SshLog.HostKeyUpdateSkipped(logger, reason);
        }
    }

    private static bool AllProven(List<byte[]> keys, byte[] proofs, byte[] sessionId)
    {
        var reader = new SshReader(proofs);
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
            if (!SshPublicKey.Parse(key).VerifySignature(algorithm, signature, signed))
            {
                return false;
            }
        }

        return reader.IsEmpty;
    }

    private static bool IsSupportedKey(byte[] blob)
    {
        try
        {
            SshPublicKey.Parse(blob);
            return true;
        }
        catch (SshProtocolException)
        {
            return false; // a type this client does not use (DSA, security keys); ssh skips those too
        }
    }
}
