# Host keys

Host key verification is what stops a man-in-the-middle, so `SshClientOptions.HostKeyVerifier` is required. The verifier
sees the host, port, alias and the key (or host certificate) the server proved it holds, and returns a verdict.

## `known_hosts`

```csharp
// ~/.ssh/known_hosts plus the system file, with OpenSSH's policies.
var verifier = KnownHostsVerifier.ForCurrentUser(StrictHostKeyChecking.Yes);

// Or name the files.
var custom = new KnownHostsVerifier(["/etc/myapp/known_hosts"])
{
    Policy = StrictHostKeyChecking.AcceptNew,
    HashNewEntries = true, // HashKnownHosts yes
};
```

| Policy | Known key | Unknown host | Changed key |
|---|---|---|---|
| `Yes` | accepted | rejected | rejected |
| `AcceptNew` | accepted | recorded and accepted, unless another key type is already known for the host | rejected |
| `Ask` (default) | accepted | `Ask` decides (rejected without it); recorded when accepted | rejected |
| `No` | accepted | accepted and recorded | accepted (not recorded) |

`No` turns off protection against a changed key, so use it only where interception is not a concern. `@revoked` entries
reject a key in every mode, and `@cert-authority`
entries accept host certificates signed by that authority for the host. The `known_hosts` format is fully supported:
hashed hosts, `[host]:port`, wildcards and negation.

```csharp
var verifier = new KnownHostsVerifier([knownHostsPath])
{
    Policy = StrictHostKeyChecking.Ask,
    Ask = (prompt, ct) =>
    {
        Console.WriteLine($"Unknown host key {prompt.Context.HostKey.KeyType} {prompt.Context.HostKey.Fingerprint}.");
        if (prompt.KnownKeyTypes.Count > 0)
        {
            Console.WriteLine($"Already known for this host: {string.Join(", ", prompt.KnownKeyTypes)}.");
        }

        return ValueTask.FromResult(Confirm("Trust it?"));
    },
};
```

`UpdateHostKeys = true` (`UpdateHostKeys yes`) keeps `known_hosts` in step with the keys the server announces after login:
keys it proves it holds are added, and this host's keys it no longer announces are removed, so a key rotation does not break
the next connection. Only the first user file changes, only lines for exactly this host (wildcard lines and `@cert-authority`
or `@revoked` lines are left alone), and never the key the connection was verified with. To confirm changes first (as
`UpdateHostKeys ask`), set `ConfirmHostKeyUpdate`:

```csharp
var verifier = new KnownHostsVerifier([knownHostsPath])
{
    UpdateHostKeys = true,
    ConfirmHostKeyUpdate = (update, ct) => ValueTask.FromResult(
        Confirm($"Update known_hosts for {update.Host}: add {string.Join(", ", update.Added)}; remove {string.Join(", ", update.Removed)}?")),
};
```

## Pinning

```csharp
var verifier = SshHostKeyVerifier.Pinned("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
```

## Your own rule

```csharp
var verifier = SshHostKeyVerifier.FromDelegate(async (context, ct) =>
    await myInventory.IsTrustedAsync(context.Host, context.HostKey.Fingerprint, ct));
```

Or derive from `SshHostKeyVerifier` and return `SshHostKeyVerdict.Accept()` or `SshHostKeyVerdict.Reject(reason)`; the
reason ends up in the `SshHostKeyException`.

## Scanning a server's keys

`SshClient.ScanHostKeysAsync` fetches a server's host keys without logging in, as `ssh-keyscan` does. It runs one key exchange
for each key type the server has and disconnects before authentication:

```csharp
var keys = await SshClient.ScanHostKeysAsync("new-server.example.com");
foreach (var key in keys)
{
    Console.WriteLine($"{key.KeyType} {key.Fingerprint}");
    await KnownHostsFile.AppendAsync(knownHostsPath, "new-server.example.com", 22, key.KeyType, key.PublicKey, hash: true);
}
```

Each key is one the server proved it holds, but a scan cannot tell whether you reached the right server. Compare the fingerprints
with ones you got another way (the server's console or its provisioning output) before you trust them, or use host certificates.

`SshHostKeyScanOptions` limits the scan to some algorithms (`HostKeyAlgorithms`), adds host certificates (`IncludeCertificates`),
or keeps to FIPS-approved algorithms (`FipsMode`). For a host behind a jump host, pass a callback that opens each connection:
`SshClient.ScanHostKeysAsync(ct => new ValueTask<Stream>(jump.OpenTcpTunnelAsync("internal-host", 22, ct)))`.

## After connecting

`client.HostKey` is the verified key (`KeyType`, `Algorithm`, `Fingerprint`, `PublicKey`, `KeySizeBits`, and `Certificate`
when the server presented a host certificate).
