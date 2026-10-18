# Managed cryptography review

SshSharp implements X25519, Ed25519, sntrup761, ChaCha20, Poly1305, bcrypt_pbkdf, BLAKE2b and Argon2 in managed code, because the .NET base
library does not provide them on every target. Everything else (AES, SHA-2, HMAC, RSA, ECDSA, ECDH, random numbers) comes from the
platform. This page records what was reviewed, how, and what is still open. It is an internal review, not an independent audit; an
outside review is planned (1.0 shipped with this internal review as its basis).

## Correctness

| Primitive | Checked against |
|---|---|
| Field arithmetic (GF(2^255 - 19)) | `BigInteger` on random and edge values (non-canonical encodings, limb boundaries), long operation chains with limb bounds checked |
| X25519 | RFC 7748 vectors including the 1,000-iteration one, OpenSSL-generated vectors, all-zero shared secret rejected |
| Ed25519 | RFC 8032 vectors, OpenSSL and ssh-keygen signatures; non-canonical S, small-order and non-canonical public keys rejected |
| ChaCha20, Poly1305, chacha20-poly1305@openssh.com | RFC 8439 vectors, OpenSSH's construction, interop with OpenSSH |
| bcrypt_pbkdf | pyca/bcrypt known answer; keys encrypted by ssh-keygen with every supported cipher |
| BLAKE2b | RFC 7693 |
| Argon2d/i/id | RFC 9106 section 5 vectors; .ppk files written by PuTTY's puttygen (CI) |
| sntrup761 | The NTRU Prime round-3 known-answer tests (key pair, ciphertext and shared secret, replayed with NIST's AES-256 CTR DRBG); `sntrup761x25519-sha512` and its `@openssh.com` name against OpenSSH (CI: the Linux runners and the OpenSSH containers that offer it; OpenSSH for Windows 9.5, the CI runners' server, does not offer it: its default key exchange list has no sntrup761); implicit rejection of tampered ciphertexts |

## Constant-time review of the secret-key paths (M3)

Signing with long-term user keys (public-key authentication, M3) makes Ed25519 signing the most sensitive managed code: a timing leak
there leaks the private key. X25519 shares the field arithmetic and handles ephemeral secrets.

**Method.** Line-by-line reading of `Ed25519.Sign`, the scalar multiplication, `Field25519` and `X25519`, looking for branches and
memory indices that depend on secret data; then a statistical timing test.

**Findings.**

- Scalar multiplication is a fixed 256-step ladder. Secret scalar bits only drive `ConditionalSwap`, which is mask-based: no branches,
  no secret-dependent indices.
- The field uses 5 limbs of 51 bits (as ref10 and curve25519-donna do). Add, subtract, multiply and square are straight-line code; the
  64×64→128-bit products come from `Math.BigMul` (`mulx`/`mul` on x64, `umulh` on Arm64). Column sums are kept as two 64-bit halves
  split at bit 51 when each product is made, so no 128-bit addition and no carry flag is involved: `UInt128` was avoided because its
  addition derives the carry from a comparison, which the JIT is not bound to compile without a branch. Subtraction adds 2p first, so
  limbs never go negative; every operation leaves limbs below 2^52, the bound its inputs need (checked by a test over long chains).
  The x64 JIT output of `Multiply` was inspected: its only branches are span length checks.
- Inversion and square roots use fixed addition chains (254 squarings and 11 multiplications for the inverse).
- Encoding (`Pack`) reduces to the canonical value arithmetically (three carry passes, then subtracting p when the value is at least
  p, computed as a carry); the parity bit is extracted arithmetically.
- Verification (`Ed25519.Verify`) uses a variable-time joint double-scalar multiplication. Its inputs (public key, message,
  signature) are all public.
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
| Ed25519.Sign: all-zero seed vs random seeds | -0.45 | no evidence of a leak |
| X25519: scalar with one bit set vs random scalars | 0.92 | no evidence of a leak |

Measured with the 51-bit field on an Intel Core i7-12800H, Windows 11, .NET 10, x64 (the 16-bit field it replaced measured 0.90 and
-0.77). |t| below 4.5 means no evidence; it is not a proof.

## Constant-time review of sntrup761

`sntrup761x25519-sha512` makes the client generate an sntrup761 key pair and decapsulate the server's ciphertext once per key
exchange. The secrets are ephemeral, but a leak in decapsulation would expose that session's post-quantum half.

**Method.** `Crypto/Sntrup761.cs` is a line-by-line port of the public-domain reference implementation (the code OpenSSH carries in
`sntrup761.c`), compared with it function by function, then the timing test below.

**Findings.**

- Reduction modulo 3 and modulo q = 4591 uses the reference's `int32_divmod_uint14`: multiply by a precomputed reciprocal, shift, and
  correct with masks. The only `/` divides by a public modulus.
- The inversions in R3 and Rq are fixed 1,521-step divstep loops. Each step's swap is mask-based, and so is the sign.
- Polynomial products accumulate the reference's per-step reductions in a 32-bit sum (at most 761 × 2,295 in magnitude) and
  reduce once per coefficient. The result is identical, and the loop bounds depend only on the degree.
- The weight-w random vector is made by sorting random keys. The reference uses djbsort; this port uses Batcher's merge-exchange
  network (Knuth, algorithm 5.2.2M). The pairs compared depend only on the length, and each compare-exchange is branch-free.
- Decapsulation re-encrypts, compares the ciphertexts with an OR-accumulated difference, and selects between the real secret and
  the implicit-rejection secret (rho) with a mask. The session hash takes `1 + mask` as its prefix, as in the reference.
- The rejection loop in key generation, which retries until g is invertible in R3, runs a data-dependent number of times, as in the
  reference. The discarded g values are independent of the key that is kept.
- Buffers that hold secrets are cleared. Intermediate polynomials are heap arrays, cleared in `finally` blocks.
- **JIT output inspected** (.NET 10, x64, `DOTNET_JitDisasm` on the Tier1 and OSR code, which is what runs after warm-up):
  - The leaf functions (`DivMod`, `ModSigned`, `F3Freeze`, `FqFreeze`, `MinMax`) and the mask helpers, which are inlined, are
    straight-line code: the masks compile to `shr`, `neg`, `and` and `sar`, with no conditional jumps.
  - The reductions by the constant moduli 3 and 4591 compile to multiply-and-shift sequences. The generic reduction's only
    `div` divides the constant 2^31 by a public modulus.
  - In the loops (`R3Recip`, `RqRecip3`, `RqMultSmall`, `R3Mult`, `Decrypt`, `CiphertextsDiffMask`, the sorting network), every
    conditional jump compares a loop counter with a public bound (761, 762, 1039), checks an array index against its length,
    or tests an object or type flag inside `Array.Clear`. None depends on a secret value.
- The platform caveat above applies to the 64-bit multiplication in the reduction: the constant-time claim covers x64 and Arm64.

| Check (2,000 samples per class) | t | Verdict |
|---|---|---|
| sntrup761 decapsulation: one secret key vs fresh secret keys | -0.49 | no evidence of a leak |
| sntrup761 decapsulation: a valid ciphertext vs random bytes (implicit rejection) | 1.27 | no evidence of a leak |

Measured on Windows 11, .NET 10, x64. Decapsulation takes about 0.9 ms.

## Private keys written to files

`SaveAsync` and `ToOpenSshPrivateKey` build the private section in a buffer sized from the key up front, which zeroes any
array it outgrows and the final one when done, so no copy of the private fields is left in the heap. The bytes of the file
are cleared after writing; the string `ToOpenSshPrivateKey` returns cannot be.

## Accepted risks

- **DH group 14/16/18 and group exchange** use `BigInteger.ModPow` on the ephemeral exponent, which is not constant-time. The
  exponent is used once and the timing is not observable remotely in a useful way; curve25519 and ECDH are preferred by default.
- **Group exchange primality** is one Miller-Rabin round with a random base on the server's prime (`DhGroupValidator`), after trial
  division of p and (p-1)/2 by the odd numbers below 4096. For a random-looking composite of 2048 bits or more, one round errs
  with probability below 2^-64 (Damgard, Landrock and Pomerance); it is not a bound against a prime crafted by the server, which
  needs no weak group to read its own session. More rounds, or proving (p-1)/2 prime, cost a full-size `BigInteger.ModPow` each:
  measured on Windows 11, .NET 10, x64, a connection to OpenSSH 9.6 on localhost takes 0.87 s with an 8192-bit group (0.22 s for
  `diffie-hellman-group18-sha512`), of which about 0.65 s is the one round.
- **bcrypt_pbkdf and Argon2** index tables with data derived from the passphrase. They run once, locally, when a key file is loaded.
- **Managed strings** (the password option) cannot be wiped.

## Open

- A vectorised ChaCha20 would need the same review again.
- An independent review.
