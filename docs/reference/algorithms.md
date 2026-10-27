# Algorithms

SshSharp implements modern SSH algorithms only. The lists below are in default preference order: the client proposes them in this
order, and the first one the server also supports is used. `client.Algorithms` shows what a connection negotiated.

## Key exchange

| Algorithm | Notes | FIPS mode |
|---|---|---|
| `mlkem768x25519-sha256` | Post-quantum hybrid (ML-KEM-768 + X25519). OpenSSH 9.9+, its default since 10.0. .NET 10 and later where the platform has ML-KEM (OpenSSL 3.5+, or a recent Windows). | No |
| `mlkem768nistp256-sha256` | Post-quantum hybrid with P-256 (RFC 10042). Same platform requirement. | Yes |
| `mlkem1024nistp384-sha384` | Post-quantum hybrid with P-384 (RFC 10042). Same platform requirement. | Yes |
| `sntrup761x25519-sha512`, `sntrup761x25519-sha512@openssh.com` | Post-quantum hybrid (Streamlined NTRU Prime + X25519). Managed, so on every platform and .NET 8. OpenSSH 8.5+. | No |
| `curve25519-sha256`, `curve25519-sha256@libssh.org` | X25519 (the platform's on .NET 11 where the OS provides it, managed otherwise). | No |
| `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521` | NIST curves. | Yes |
| `diffie-hellman-group-exchange-sha256` | Finite-field DH in a group the server picks (RFC 4419), for servers with nothing better, often older network equipment. The client asks for 2048 to 8192 bits, preferring a size that matches the cipher as OpenSSH does (3072 bits with `aes128-gcm@openssh.com`, 8192 with 256-bit ciphers or an `hmac-sha2-*` MAC), and checks the server's group before using it (see the [threat model](../threat-model.md)). With an 8192-bit group a connection takes about 0.9 s. | No: the server picks the group, and SP 800-56A rev. 3 approves only fixed safe-prime groups |
| `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`, `diffie-hellman-group14-sha256` | Finite-field DH in the fixed 4096, 8192 and 2048-bit groups of RFC 3526, last, in OpenSSH's order. | Yes |

Without platform ML-KEM (on .NET 8, or an older OS), the three `mlkem*` methods are not offered and the list starts at
`sntrup761x25519-sha512`. `client.Algorithms.IsPostQuantum` tells whether a connection's key exchange resists a future quantum
computer; the client logs at `Information` level when it does not.

Strict key exchange (`kex-strict-c-v00@openssh.com`, the fix for the Terrapin attack, CVE-2023-48795) is offered on every
connection and used whenever the server supports it. `ext-info-c` (RFC 8308) is offered, so the server can announce
`server-sig-algs`.

## Host keys

| Algorithm | FIPS mode |
|---|---|
| `ssh-ed25519` | No |
| `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` | Yes |
| `rsa-sha2-512`, `rsa-sha2-256` | Yes |

OpenSSH host certificates of the same types (`ssh-ed25519-cert-v01@openssh.com`, `ecdsa-sha2-nistp256-cert-v01@openssh.com`, ...,
`rsa-sha2-512-cert-v01@openssh.com`, `rsa-sha2-256-cert-v01@openssh.com`) are proposed first when a `@cert-authority` line in
`known_hosts` covers the host.

## Ciphers

| Algorithm | Notes | FIPS mode |
|---|---|---|
| `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` | AEAD. First when the CPU has AES instructions. | Yes |
| `chacha20-poly1305@openssh.com` | AEAD, managed. First when the CPU lacks AES instructions. | No |
| `aes256-ctr`, `aes192-ctr`, `aes128-ctr` | With a MAC below. | Yes |

## MACs

Used only with the CTR ciphers; the AEAD ciphers carry their own authentication.

| Algorithm | Notes | FIPS mode |
|---|---|---|
| `hmac-sha2-512-etm@openssh.com` | Encrypt-then-MAC. | Yes |
| `hmac-sha2-256-etm@openssh.com` | Encrypt-then-MAC. | Yes |
| `hmac-sha2-256` | Encrypt-and-MAC (RFC 4253, RFC 6668). For servers that offer no `-etm` MAC, often network equipment. | Yes |
| `hmac-sha2-512` | Encrypt-and-MAC, as above. | Yes |

The encrypt-then-MAC (`-etm@openssh.com`) variants come first, as in OpenSSH: they authenticate the encrypted packet before anything
is decrypted, and leave only the packet length in clear. The plain variants authenticate the plaintext and encrypt the length, so
the receiver decrypts the packet before it can check the MAC. With AES-CTR both are sound, and the plain ones are what many routers,
switches and appliances offer. A server that offers both always gets an `-etm` MAC. To refuse the plain ones, write
`MACs -hmac-sha2-256,hmac-sha2-512` in `ssh_config`.

## Compression

| Algorithm | Notes | FIPS mode |
|---|---|---|
| `none` | The default. | Yes |
| `zlib@openssh.com` | OpenSSH's delayed compression: zlib, started with the first packet after the server accepts the user's authentication, in both directions, and kept for the rest of the connection. Offered only when `SshClientOptions.Compression` (or `Compression yes` in `ssh_config`) turns it on, before `none`, as `ssh -C` does. What SshSharp sends is Huffman-coded only, as OpenSSH does; on .NET 8 SshSharp does not compress what it sends and offers `none` for that direction. | Yes: zlib is not a cryptographic algorithm |

Compression is off by default, as in OpenSSH: it costs CPU, helps only on slow links with compressible data, and makes packet
lengths depend on the content (see the [threat model](../threat-model.md#compression)). Each key re-exchange that negotiates it
starts new zlib streams, as OpenSSH does; one that negotiates `none` turns compression off. A packet must inflate to less than
256 KiB, or the connection fails with a protocol error. Plain `zlib`, which compresses from the first packet, is not supported (see
below). See [Compress a slow link](../how-to/tune-and-inspect-connections.md#compress-a-slow-link).

## User authentication keys

| Key type | Signature algorithms |
|---|---|
| Ed25519 | `ssh-ed25519` |
| ECDSA P-256, P-384, P-521 | `ecdsa-sha2-nistp256/384/521` |
| RSA (2048 bits or more) | `rsa-sha2-512`, `rsa-sha2-256`, as the server's `server-sig-algs` and `PubkeyAcceptedAlgorithms` allow |
| FIDO security keys, through the agent | `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` |
| OpenSSH certificates of the above | the matching `-cert-v01@openssh.com` algorithms |

## Private key file encryption

These protect key files on disk, not the connection. SshSharp reads all of them and writes only the first three rows' formats
with the ciphers shown in [Export a key](../how-to/agent-and-keys.md#export-a-key-to-pkcs8-or-putty).

| Format | Ciphers | Key derivation |
|---|---|---|
| OpenSSH | `aes128/192/256-ctr`, `aes128/192/256-cbc`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com` | `bcrypt_pbkdf` |
| PKCS#8 | what .NET reads (PBES2 with AES) | PBKDF2 |
| PuTTY `.ppk` | `aes256-cbc` | Argon2 (version 3), SHA-1 (version 2) |
| Traditional PEM (`Proc-Type: 4,ENCRYPTED`), read only | `AES-128-CBC`, `AES-192-CBC`, `AES-256-CBC` | OpenSSL's `EVP_BytesToKey` (MD5, one round) |

Not read, by design: DES and 3DES (`DES-CBC`, `DES-EDE3-CBC`, `DES-EDE3-CFB`) in traditional PEM; convert such a key with
`ssh-keygen -p -f <file>`. See [Encrypted key files](../how-to/agent-and-keys.md#encrypted-key-files) and the
[cryptography review](../crypto-review.md#encrypted-private-keys-read-from-files).

## Not supported

By design, none of these are implemented: CBC ciphers, 3DES, RC4, `hmac-sha1` and other SHA-1 MACs, `ssh-rsa` (SHA-1) signatures,
`ssh-dss`, `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, and plain `zlib`
compression, which starts before authentication and so exposes the decompressor to an unauthenticated peer (OpenSSH's client
dropped it in 9.9; `zlib@openssh.com`, above, is supported).
A server that offers nothing else fails the connection with `SshFailureReason.KeyExchangeFailed`; see
[Troubleshooting](troubleshooting.md#no-common-algorithms).

## Changing the lists

- **With `ssh_config`:** `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs` and `PubkeyAcceptedAlgorithms`, with OpenSSH's
  `+`, `-` and `^` forms, applied to these defaults as `ssh` applies them: `+` leaves a name that is already a default where it is,
  and a wildcard in any form stands for the names it matches (`Ciphers aes*-ctr`). Names SshSharp does not implement are ignored;
  a `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` or `MACs` list that leaves none it does fails the connection before anything
  is sent, naming the directive. A `PubkeyAcceptedAlgorithms` list that leaves none (`PubkeyAcceptedKeyTypes ssh-rsa`, SHA-1 only)
  offers no key, with a warning in the log; the other authentication methods still work.
  `PubkeyAcceptedAlgorithms` decides which keys are offered and, for RSA, which signature algorithm is used (the list's first that
  the server's `server-sig-algs` has); its defaults are every algorithm in the table above, certificates first.
- **In code:** `SshClientOptions.KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `Macs` and `PubkeyAcceptedAlgorithms` take an
  `SshAlgorithmList` in the same four forms (`Only`, `Append`, `Prepend`, `Remove`, or `SshAlgorithmList.Parse` for the text form),
  which mean what they mean in `ssh_config`. Unlike in `ssh_config`, a name SshSharp does not implement throws
  `ArgumentException`, and only `Remove` takes wildcards. See
  [Choose algorithms and authentication methods](../how-to/algorithms-and-authentication-order.md).
- **Host certificates:** when a certificate authority is trusted for the host, the certificate algorithms are asked for first
  with the default `HostKeyAlgorithms` or a `+` or `-` change to it; a plain or `^` list is used as written, as in `ssh`.
- **FIPS mode:** `SshClientOptions.FipsMode` restricts every transport list, yours included, to the FIPS column (`PubkeyAcceptedAlgorithms`, which governs your own keys, is not filtered); see
  [FIPS mode](../how-to/fips-mode.md).
- **RSA host key size:** `SshClientOptions.RequiredRsaSize` (`RequiredRSASize` in `ssh_config`), 2048 bits by default, 1024 at
  the least.
- **Rekeying:** `RekeyAfterBytes` (1 GiB) and `RekeyAfterTime` (1 hour).
- **Compression:** `SshClientOptions.Compression` (`Compression` in `ssh_config`) offers `zlib@openssh.com` before `none`.

## See also

- [Connecting: algorithms](../connecting.md#algorithms)
- [Cryptography review](../crypto-review.md)
