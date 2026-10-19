# Algorithms

SshSharp implements modern SSH algorithms only. The lists below are in default preference order: the client proposes them in this
order, and the first one the server also supports is used. `client.Algorithms` shows what a connection negotiated.

## Key exchange

| Algorithm | Notes | FIPS mode |
|---|---|---|
| `mlkem768x25519-sha256` | Post-quantum hybrid (ML-KEM-768 + X25519). OpenSSH 9.9+, its default since 10.0. .NET 10 where the platform has ML-KEM (OpenSSL 3.5+, or a recent Windows). | No |
| `mlkem768nistp256-sha256` | Post-quantum hybrid with P-256 (RFC 10042). Same platform requirement. | Yes |
| `mlkem1024nistp384-sha384` | Post-quantum hybrid with P-384 (RFC 10042). Same platform requirement. | Yes |
| `sntrup761x25519-sha512`, `sntrup761x25519-sha512@openssh.com` | Post-quantum hybrid (Streamlined NTRU Prime + X25519). Managed, so on every platform and .NET 8. OpenSSH 8.5+. | No |
| `curve25519-sha256`, `curve25519-sha256@libssh.org` | X25519. | No |
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

`none` only.

## User authentication keys

| Key type | Signature algorithms |
|---|---|
| Ed25519 | `ssh-ed25519` |
| ECDSA P-256, P-384, P-521 | `ecdsa-sha2-nistp256/384/521` |
| RSA (2048 bits or more) | `rsa-sha2-512`, `rsa-sha2-256`, as the server's `server-sig-algs` allows |
| FIDO security keys, through the agent | `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` |
| OpenSSH certificates of the above | the matching `-cert-v01@openssh.com` algorithms |

## Not supported

By design, none of these are implemented: CBC ciphers, 3DES, RC4, `hmac-sha1` and other SHA-1 MACs, `ssh-rsa` (SHA-1) signatures,
`ssh-dss`, `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, and `zlib` compression.
A server that offers nothing else fails the connection with `SshFailureReason.KeyExchangeFailed`; see
[Troubleshooting](troubleshooting.md#no-common-algorithms).

## Changing the lists

- **With `ssh_config`:** `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `MACs`, with OpenSSH's `+`, `-` and `^` forms,
  applied to these defaults. Names SshSharp does not implement are ignored. `PubkeyAcceptedAlgorithms` is resolved but not
  applied: each key is signed with the first of its algorithms the server lists in `server-sig-algs`.
- **In code:** `SshClientOptions.KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `Macs` take an `SshAlgorithmList` in the same
  four forms (`Only`, `Append`, `Prepend`, `Remove`, or `SshAlgorithmList.Parse` for the text form). Unlike in `ssh_config`, a name
  SshSharp does not implement throws `ArgumentException`. See
  [Choose algorithms and authentication methods](../how-to/algorithms-and-authentication-order.md).
- **FIPS mode:** `SshClientOptions.FipsMode` restricts every list, yours included, to the FIPS column; see
  [FIPS mode](../how-to/fips-mode.md).
- **RSA host key size:** `SshClientOptions.RequiredRsaSize` (`RequiredRSASize` in `ssh_config`), 2048 bits by default, 1024 at
  the least.
- **Rekeying:** `RekeyAfterBytes` (1 GiB) and `RekeyAfterTime` (1 hour).

## See also

- [Connecting: algorithms](../connecting.md#algorithms)
- [Cryptography review](../crypto-review.md)
