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

`UpdateHostKeys = true` (`UpdateHostKeys yes`) records the other host keys the server proves it holds after login, so a
key rotation does not break the next connection. Keys the server stops announcing are not removed yet (#60).

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

## After connecting

`client.HostKey` is the verified key (`KeyType`, `Algorithm`, `Fingerprint`, `PublicKey`, `KeySizeBits`, and `Certificate`
when the server presented a host certificate).
