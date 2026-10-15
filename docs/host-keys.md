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

### Revoked host keys

`RevokedHostKeys` (ssh_config's `RevokedHostKeys`) names a file of host keys never to accept, checked before anything else
and in every mode, even for a key `known_hosts` trusts:

```csharp
var verifier = new KnownHostsVerifier([knownHostsPath]) { RevokedHostKeys = "/etc/ssh/revoked_host_keys" };
```

The file is an OpenSSH Key Revocation List, the binary file `ssh-keygen -k` writes, or a list of public keys, one per line as
in `authorized_keys` (as with ssh, lines that do not parse are skipped). A KRL can revoke:

- plain keys, by the key itself or by its SHA-1 or SHA-256 fingerprint;
- host certificates, by serial number (single, range or bitmap) or key id, for one certificate authority or for any.

A host certificate is also refused when its certified key or its authority's key is revoked. The refusal reads as ssh's:
`Host key ssh-ed25519 SHA256:... revoked by file ...`.

As with ssh, a file that cannot be read, or a KRL that is malformed or uses a section or critical extension this library does
not know, refuses every host key ("Error checking host key ... in revoked keys file ..."): a revocation list that cannot be
checked must not let a revoked key through. A KRL's signature sections are read but not verified; the file is trusted as local
configuration. `UpdateHostKeys` never learns a revoked key.

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
or keeps to FIPS-approved algorithms (`FipsMode`); `Timeout` bounds each connection (5 seconds, as `ssh-keyscan -T`;
`Timeout.InfiniteTimeSpan` for none). For a host behind a jump host, pass a callback that opens each connection:
`SshClient.ScanHostKeysAsync(ct => new ValueTask<Stream>(jump.OpenTcpTunnelAsync("internal-host", 22, ct)))`.

## After connecting

`client.HostKey` is the verified key (`KeyType`, `Algorithm`, `Fingerprint`, `PublicKey`, `KeySizeBits`, and `Certificate`
when the server presented a host certificate).
