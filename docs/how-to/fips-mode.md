# FIPS mode

`SshClientOptions.FipsMode = true` limits what a connection negotiates to FIPS-approved algorithms: NIST curves and Diffie-Hellman
groups, RSA and ECDSA host keys, AES, and HMAC-SHA2. Curve25519, Ed25519 and ChaCha20-Poly1305 are excluded.

## When to use

- Policy requires FIPS 140-approved cryptography for SSH (government, regulated industries).
- You need to show which algorithms a connection may use.

> [!IMPORTANT]
> FIPS mode restricts what is negotiated. It does not make your process FIPS-validated: that depends on the platform's
> cryptographic module (Windows CNG, or OpenSSL in FIPS mode on Linux) and how it is configured.

## Connect in FIPS mode

[!code-csharp[](../snippets/Platform.cs#fips)]

## What is allowed

| Kind | In FIPS mode |
|---|---|
| Key exchange | `mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384` (post-quantum, .NET 10 and later with platform ML-KEM), `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`, `diffie-hellman-group14-sha256` (not `diffie-hellman-group-exchange-sha256`: SP 800-56A rev. 3 approves the fixed RFC 3526 groups, not a group the server picks) |
| Host keys | `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-512`, `rsa-sha2-256` |
| Ciphers | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` |
| MACs | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512` |

The NIST-curve ML-KEM hybrids keep a post-quantum key exchange in FIPS mode where both sides support it. See
[Algorithms](../reference/algorithms.md) for the full list and order.

## Check a server before switching

[!code-csharp[](../snippets/Platform.cs#fips-scan)]

## Notes and pitfalls

- **User keys are yours to choose.** FIPS mode governs the transport (key exchange, host keys, ciphers, MACs); it does not filter the
  keys you authenticate with. Ed25519 is not FIPS-approved, so use ECDSA or RSA keys.
- **Connecting by alias.** `FipsMode` is an `SshClientOptions` setting; `SshConfigConnectOptions` has no equivalent. With
  `ssh_config`, restrict `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `MACs` to the lists above.
- **With your own algorithm lists.** `SshClientOptions.KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `Macs` narrow or reorder
  the lists further; FIPS mode then removes what it excludes from them. A list left with nothing FIPS mode allows (only
  `chacha20-poly1305@openssh.com`, say) throws `ArgumentException` before connecting. See
  [Choose algorithms and authentication methods](algorithms-and-authentication-order.md).
- **Servers with only Ed25519 host keys** cannot be reached in FIPS mode: the connection fails with `KeyExchangeFailed`. Add an
  ECDSA or RSA host key on the server.
- **Host key scans** take `SshHostKeyScanOptions.FipsMode` too.
- **Strict key exchange** (the Terrapin fix) is on in every mode.

## See also

- [Connecting: algorithms](../connecting.md#algorithms)
- [Cryptography review](../crypto-review.md)
