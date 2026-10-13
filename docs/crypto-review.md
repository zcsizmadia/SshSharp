# Managed cryptography review

SshSharp implements X25519, Ed25519, ChaCha20, Poly1305, bcrypt_pbkdf, BLAKE2b and Argon2 in managed code, because the .NET base
library does not provide them on every target. Everything else (AES, SHA-2, HMAC, RSA, ECDSA, ECDH, random numbers) comes from the
platform. This page records what was reviewed, how, and what is still open. It is an internal review, not an independent audit; an
outside review is planned before 1.0.

## Correctness

| Primitive | Checked against |
|---|---|
| X25519 | RFC 7748 vectors, OpenSSL-generated vectors, all-zero shared secret rejected |
| Ed25519 | RFC 8032 vectors, OpenSSL and ssh-keygen signatures; non-canonical S, small-order and non-canonical public keys rejected |
| ChaCha20, Poly1305, chacha20-poly1305@openssh.com | RFC 8439 vectors, OpenSSH's construction, interop with OpenSSH |
| bcrypt_pbkdf | pyca/bcrypt known answer; keys encrypted by ssh-keygen with every supported cipher |
| BLAKE2b | RFC 7693 |
| Argon2d/i/id | RFC 9106 section 5 vectors; .ppk files written by PuTTY's puttygen (CI) |

## Constant-time review of the secret-key paths (M3)

Signing with long-term user keys (public-key authentication, M3) makes Ed25519 signing the most sensitive managed code: a timing leak
there leaks the private key. X25519 shares the field arithmetic and handles ephemeral secrets.

**Method.** Line-by-line reading of `Ed25519.Sign`, the scalar multiplication, `Field25519` and `X25519`, looking for branches and
memory indices that depend on secret data; then a statistical timing test.

**Findings.**

- Scalar multiplication is a fixed 256-step ladder. Secret scalar bits only drive `ConditionalSwap`, which is mask-based: no branches,
  no secret-dependent indices.
- Field add, subtract, multiply and carry have fixed loop bounds; carries use arithmetic shifts. Inversion and square roots branch only
  on the public exponent's bits.
- Encoding (`Pack`) selects the canonical value with a mask-based swap; the parity bit is extracted arithmetically.
- Reduction modulo L uses fixed loops and shifts, no branches.
- SHA-512 is the platform's.
- Fixed: `Ed25519.Sign` left the unreduced `r + h·a` in a stack buffer; it is now cleared with the secret scalar and nonce.
- **Platform caveat:** on 32-bit x86, .NET implements 64-bit multiplication with a helper that takes a faster path when both high
  halves are zero, so timing could depend on secret limbs. The constant-time claim covers 64-bit platforms (x64, Arm64), where the
  multiplication is a single instruction.

**Timing test.** `tests/SshSharp.Benchmarks` has a dudect-style check (fixed secret against random secrets, Welch's t-test, the
slowest 10% of samples dropped): `dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --timing 15000`.
It does not run in CI, because shared runners are too noisy for a statistical timing test.

| Check (15,000 samples per class) | t | Verdict |
|---|---|---|
| Ed25519.Sign: all-zero seed vs random seeds | 0.90 | no evidence of a leak |
| X25519: scalar with one bit set vs random scalars | -0.77 | no evidence of a leak |

Measured on an Intel Core i7-12800H, Windows 11, .NET 10, x64. |t| below 4.5 means no evidence; it is not a proof.

## Accepted risks

- **DH group 14/16** uses `BigInteger.ModPow` on its ephemeral exponent, which is not constant-time. The exponent is used once and the
  timing is not observable remotely in a useful way; curve25519 and ECDH are preferred by default.
- **bcrypt_pbkdf and Argon2** index tables with data derived from the passphrase. They run once, locally, when a key file is loaded.
- **Managed strings** (the password option) cannot be wiped.

## Open

- Faster field arithmetic (5×51-bit limbs) and a vectorised ChaCha20 would need the same review again.
- An independent review before 1.0.
