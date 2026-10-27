# Managed cryptography review

SshSharp implements X25519, Ed25519, sntrup761, ChaCha20, Poly1305, bcrypt_pbkdf, BLAKE2b and Argon2 in managed code, because the .NET base
library does not provide them on every target. Everything else (AES, SHA-2, HMAC, RSA, ECDSA, ECDH, random numbers) comes from the
platform. This page records what was reviewed, how, and what is still open. It is an internal review, not an independent audit, and
no outside review is planned.

## Correctness

| Primitive | Checked against |
|---|---|
| Field arithmetic (GF(2^255 - 19)) | `BigInteger` on random and edge values (non-canonical encodings, limb boundaries), long operation chains with limb bounds checked |
| X25519 | RFC 7748 vectors including the 1,000-iteration one, OpenSSL-generated vectors, all-zero shared secret rejected |
| Ed25519 | RFC 8032 vectors, OpenSSL and ssh-keygen signatures; non-canonical S, small-order and non-canonical public keys rejected |
| ChaCha20, Poly1305, chacha20-poly1305@openssh.com | RFC 8439 vectors, the framework's RFC 8439 AEAD, OpenSSH's construction, interop with OpenSSH; the vectorized ChaCha20 against the scalar code, and Poly1305's 64-bit limbs against its 26-bit code and a `BigInteger` computation of the definition (below); key files that `ssh-keygen -Z chacha20-poly1305@openssh.com` encrypted (CI, [below](#encrypted-private-keys-read-from-files)) |
| bcrypt_pbkdf | pyca/bcrypt known answer; keys encrypted by ssh-keygen with every supported cipher |
| BLAKE2b | RFC 7693 |
| Argon2d/i/id | RFC 9106 section 5 vectors; .ppk files written by PuTTY's puttygen (CI), and .ppk files SshSharp writes read by puttygen (CI) |
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

| Check (15,000 samples per class) | t, .NET 10 | t, .NET 8 | Verdict |
|---|---|---|---|
| Ed25519.Sign: all-zero seed vs random seeds | 2.23 | 1.08 | no evidence of a leak |
| X25519: scalar with one bit set vs random scalars | -0.32 | 0.44 | no evidence of a leak |

Re-run for 1.1.0 on the code after "Optimized at the first call" below (the kernels compiled fully optimized at their first call, and
`Ed25519.Sign` with the key's own public key), on an Intel Core i7-12800H, Windows 11, x64. The same run's ChaCha20, Poly1305 (both
limb sizes) and sntrup761 checks were all between -1.4 and 1.5. Before that change, with the 51-bit field, the two checks measured
-0.45 and 0.92 (and the 16-bit field before it 0.90 and -0.77). |t| below 4.5 means no evidence; it is not a proof.

## Ed25519 signing with the key's own public key

`Ed25519.Sign` derived the public key from the seed on every signature, because the challenge hashes it: a fixed-base scalar
multiplication, one of the two that make up nearly all of the signing cost (the other computes R). An overload takes the public key
instead, and `SshPrivateKey.Ed25519Key` passes the one it derived from its seed when it was made.

**Why this needs care.** RFC 8032 derives the nonce from the seed's second half and the message only. Two signatures of one message
under two different public keys would share R and differ in S by (h - h') · a, which gives the secret scalar a away; a test
(`AMismatchedPublicKey_WouldGiveTheSecretScalarAway`) shows the shared R. So the public key passed must be the seed's own.

**How it is guaranteed.** `Ed25519Key` has one public constructor, which takes only the seed and derives the public key itself; the
public key is a private field, set nowhere else. The parsers (OpenSSH, PuTTY, PKCS#8) pass only the seed; a public key in the file
(OpenSSH and PuTTY have one) is only compared with the derived one, and the file is refused when they differ (tested with a file whose public key is consistent
in all three places and is not the seed's). A disposed key, whose seed is zeros, refuses to sign or export. The signature from the overload is
checked to equal the one that derives the public key afresh, and the overload against the RFC 8032 and OpenSSL vectors.

## Optimized at the first call

The tiered JIT first compiles a method without optimization, and recompiles it optimized only after 30 calls and a spell of 100 ms
in which no new methods were compiled. A connect is a burst of new methods, so in a process that connects once, or in the first
connects of any process, the key exchange, the host key verification and the signature ran entirely in unoptimized code, where the
helpers marked `AggressiveInlining` are not inlined and locals live in memory: several times slower (measured by comparing with
`DOTNET_TieredCompilation=0` against OpenSSH: about 5.8 ms less client CPU in each early connect). The heavy, once-per-connect methods are now marked
`MethodImplOptions.AggressiveOptimization`, as the vectorized ChaCha20 kernels already were, so they are compiled optimized at their
first call:

- `Field25519`: `Add`, `Sub`, `ConditionalSwap`, `Multiply`, `Square` (the operations inside every ladder step and point addition;
  the inversion chains and encodings built on them are cheap loops around these calls);
- `X25519`'s ladder (`ScalarMult`);
- `Ed25519`: `Sign` (the overload that does the work), `Verify`, the point addition `Add`, its `ConditionalSwap`, `ScalarMult`,
  `DoubleScalarMultPublic` and `ModL`. `ScalarBase` and `GetPublicKey` only set up and call `ScalarMult`, so they are left alone.

**Effect on constant time.** None intended: the code is the same and is now compiled by the same optimizing compiler that compiled
it before once it was hot, minus profile-guided optimization. The tier-0 code it replaces had the same structure (no branches on
secrets) but was never the code reviewed above, which is the optimized output. The cost is one optimizing compile per method and no
dynamic PGO for them, which straight-line arithmetic does not need. The timing test above was re-run on this code for 1.1.0, on
.NET 10 and .NET 8, with no evidence of a leak.

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

## Constant-time review of the vectorized ChaCha20

ChaCha20 computes several blocks at once with SIMD vectors (`Crypto/ChaCha20.Vector.cs`): 8 blocks with 256-bit vectors where the
CPU has them (AVX2) and the runtime is .NET 10, 4 blocks with 128-bit vectors otherwise (SSE on x64, AdvSimd on Arm64). Whole groups
of 8 and then 4 blocks take the vector code, and the rest, fewer than 4 blocks with the last one possibly partial, takes the scalar
block function. Without vector hardware, or on a big-endian machine, the scalar code does everything. The key, the keystream and the
data are secret; the counter and the nonce (the packet sequence number) are not.

**Method.** Line-by-line reading of the vector code, inspection of the x64 JIT output (.NET 10, `DOTNET_JitDisasm`), a differential
test against the scalar code, and the timing test below.

**Findings.**

- **Lane layout:** vector N holds state word N of consecutive blocks, one block per 32-bit lane. The rounds are the scalar rounds
  applied to every lane at once (add, xor, rotate), and no operation moves data between lanes. Rotations by 12 and 7 are two shifts
  and an OR; rotations by 16 and 8 are byte shuffles with constant indices. All of them take the same time whatever the data.
- **Counter:** lane j holds counter + j. A lane whose low word wraps carries into the high word through a vector comparison turned
  into a mask, with no branch; the counter is public anyway. A test checks the keystream across the 2^32 and 2^64 boundaries in
  every lane against the scalar code and against the block function.
- **Output:** each group of four words is transposed into one 16-byte row per block with constant-index shuffles and constant-mask
  selects, then XORed with the input. Every load and store address depends only on the offset into the buffer.
- **Control flow:** which path runs, and how many groups, depends only on the CPU, the runtime and the length. In the x64 JIT
  output of `Xor8Blocks` and `Xor4Blocks`, every conditional jump is a loop counter or a span bounds check.
- **Secrets in memory:** like the scalar code's locals, the vector state lives in registers and stack slots the method does not
  clear.

| Check (15,000 samples per class) | t (.NET 10) | t (.NET 8) | Verdict |
|---|---|---|---|
| ChaCha20 over 1,000 bytes (8 and 4 blocks, scalar tail): all-zero key vs random keys | -0.42 | -0.03 | no evidence of a leak |
| The same, 4 blocks at once (128-bit vectors) | -1.33 | 0.69 | no evidence of a leak |
| ChaCha20 over 1,000 bytes: all-zero data vs random data | -0.20 | 1.21 | no evidence of a leak |

Measured on an Intel Core i7-12800H, Windows 11, x64 (on .NET 8 the first row also runs 4 blocks at once). The first run of the
data check gave t = -16.9: the harness reused one array for the fixed class, which stayed in the cache while each random input was a
fresh array. The fixed class now gets a fresh copy per sample, like the random class, and the other checks' results did not change.

## Constant-time review of Poly1305 with 64-bit limbs

In a 64-bit process, Poly1305 (`Crypto/Poly1305.cs`) holds r and the accumulator h in three limbs of 44, 44 and 42 bits (the
poly1305-donna-64 representation) and multiplies them with 64×64→128-bit products from `Math.BigMul`: 9 products per 16-byte block,
against 25 with the five 26-bit limbs it replaced. A 32-bit process keeps the 26-bit code (`Crypto/Poly1305.Limbs26.cs`, unchanged),
because there a 64×64-bit product takes four 32-bit multiplies and the 64-bit limbs measured about twice as slow
([benchmarks](benchmarks.md#poly1305-64-bit-limbs)). Which one runs depends only on the process (`Environment.Is64BitProcess`, a
constant for the JIT). The one-time key (r and s) and the accumulator are secret. In `chacha20-poly1305@openssh.com` the message is the
ciphertext, but the code treats it as secret too; only its length is public.

**Method.** Line-by-line reading against poly1305-donna-64, a bound for every limb and column sum (in the code's comments), inspection
of the x64 JIT output on .NET 10 and .NET 8 (`DOTNET_JitDisasm`), a differential test, and the timing test below.

**Findings.**

- **Clamping and limbs:** r is clamped and split into limbs with constant masks and shifts; the message limbs and the 2^128 bit of a
  whole block are added the same way.
- **Products:** `Math.BigMul` compiles to `mulx` on x64 with BMI2 and to `mul` and `umulh` on Arm64, whose time does not depend on
  their operands; without BMI2 the runtime's fallback is straight-line code of four multiplies of 32-bit halves. The multipliers
  (r0, r1, r2 and 20·r2) are stored shifted left by 20 bits, which still fits in 64, so each 128-bit product splits at bit 44 with
  one shift of its low word, and 20·h2 is multiplied by r1 instead of h2 by 20·r1, which would not fit shifted. As in the X25519 field, column sums are kept as two 64-bit halves, so no
  128-bit addition and no carry flag is involved: every product is below 2^92 and every column below 2^93, so neither half can
  overflow.
- **Carries:** one fixed pass per block, with shifts and masks: d0 into d1, d1 into d2, and the carry above 2^130 back into h0 times 5,
  then h0 into h1. Every block leaves h0 below 2^44, h1 below 2^44 + 2^8 and h2 below 2^42, the bounds the next block's products need.
- **Final reduction** (`Finish44`, inlined): the steps of poly1305-donna-64, line for line and in its order. Two full carry passes
  (h1 into h2, h2's overflow into h0 times 5, h0 into h1) leave every limb within its width. Then g = h + 5 - 2^130 (h - p) is
  computed limb by limb, and the sign bit of its top limb becomes a mask (`(g2 >> 63) - 1`) that selects g or h with AND and OR.
  Adding s is limb by limb with shift carries, and the carry out of 2^128 is dropped by the top limb's mask. Within the limb bounds
  the block loop guarantees (h0 < 2^44, h1 < 2^44 + 2^8, h2 < 2^42), the second pass never carries: the first pass carries h0 into
  h1 only after h2 overflowed, which needs a carry out of h1, which leaves h1 below 2^8 before the +1. It is kept so that the code
  matches the reference. A test runs this step on its own against `BigInteger` for every combination of edge limb values at those
  bounds (including the rare state where the first pass carries all the way round) and for 4,000 random states.
- **Control flow:** the loop runs once per 16-byte block, and its one branch, between a whole block read in place and the last
  partial block staged with its 0x01 terminator, depends only on the length. In the JIT output of `ComputeTag44` on .NET 10 and
  .NET 8, with `Finish44` inlined into it, every conditional jump is a span length or bounds check (the key, the tag, the remaining
  message), the loop's own length tests or the stack-guard check; there is no `cmov` or `setcc`, and the 9 `mulx` of a block and the
  final reduction and select are straight-line code. The method is compiled fully optimized at once (it uses `stackalloc`, so it
  does not go through tier 0), so this is the code that runs.
- **Secrets in memory:** the limbs live in registers and stack slots, and the last partial block in a 16-byte stack buffer; none is
  cleared, as before.
- **32-bit processes:** the 26-bit code multiplies 32-bit values into 64-bit products, as before this change. In the x86 JIT output
  (.NET 10 and .NET 8) each of its 25 products per block is one `mulx` instruction, with no call to the 64-bit multiplication helper
  of the platform caveat above.

| Check (15,000 samples per class) | t (.NET 10) | t (.NET 8) | Verdict |
|---|---|---|---|
| Poly1305 over 16,383 bytes (1,023 blocks and a partial one): all-zero key vs random keys | 0.49 | -0.93 | no evidence of a leak |
| The same with the 26-bit limbs | 0.93 | -0.61 | no evidence of a leak |
| Poly1305 over 4,095 bytes: all-zero data vs random data | 0.89 | 0.09 | no evidence of a leak |
| The same with the 26-bit limbs | -0.89 | 0.64 | no evidence of a leak |

Measured on an Intel Core i7-12800H, Windows 11, x64, on an otherwise idle machine. Poly1305 runs over more data than ChaCha20 in
this test because it is fast: over 1,000 bytes it took 4 to 5 timer ticks (100 ns each on Windows), too few to show a small
difference; over 16,383 bytes it takes about 64 ticks with the 64-bit limbs and 97 with the 26-bit ones.

A differential test runs both limb sizes on every machine against each other and against the definition computed with `BigInteger`:
random keys and messages of every length up to 1,100 bytes and longer ones, the largest clamped r with all-ones messages, accumulators
that end just below, at and above p and 2^130 (where the final subtraction and the carry above 2^130 decide the result), an s that
carries out of 2^128, two blocks that drive the 26-bit code's final reduction into its rarest carry (below), and the RFC 8439
vectors (section 2.5.2 and appendix A.3).

Mutation testing (the `chacha20-poly1305` scope, Stryker.NET 5) kills 126 mutants of the 64-bit code and 175 of the 26-bit code,
and every mutant of ChaCha20, its vector code and the `chacha20-poly1305@openssh.com` construction that is not equivalent. What
survives, or is annotated as equivalent:

- `>>` turned into `>>>`: on an unsigned value both are the same shift, so these mutants are equivalent. Where the shift is the only
  bitwise operator of its statement, the statement carries a `// Stryker disable once Bitwise` comment. Where the statement also
  has `&`, `|` or `<<` (6 statements in the 64-bit code, 11 in the 26-bit code), it does not, because the comment would also hide
  those operators' mutants, which the tests kill.
- The call of the 26-bit code from `ComputeTag` runs only in a 32-bit process, so a 64-bit test run cannot cover it; the tests call
  `ComputeTag26` directly instead. Removing the call is annotated; removing its `else` block stays as the scope's one uncovered
  mutant, because annotating the `if` would also hide the removal of the 64-bit branch, which the tests kill. Negating
  `Environment.Is64BitProcess` is equivalent (both branches give the same tag), and so is removing the clearing of the last block's
  stack buffer (it starts zeroed and only the last block uses it); both are annotated.
- The additions of the second carry pass of the final reduction (`h2 += cc`, `h0 += cc * 5`, `h1 += cc`) add a carry that is
  always 0 within the block loop's limb bounds (above), so changing them is equivalent; they are annotated with that bound.
- In the 26-bit code, the last carry of its final reduction (`h1 += cc`, after the fold adds 5 to h0) is not equivalent, but no
  random input reaches it. It carries only when h1 is at least 2^26, h2, h3 and h4 are at their tops, and h0 is at least
  2^26 - 5. With r = 2^26 - 1 (r1 to r4 zero), the block loop computes (h + m) * r exactly, which made the state reachable with two
  blocks found by a search. `TheFinalReductionWith26BitLimbs_CarriesOutOfH0AfterTheFold` uses them, and it is the only test that
  fails when the addition becomes a subtraction.
- ChaCha20 and the `chacha20-poly1305@openssh.com` construction: wiping the keystream, the one-time Poly1305 key and the block they
  come from off the stack is hygiene that the API cannot observe, and clearing the nonce's stack buffer again changes nothing
  (locals are initialized); these are annotated. So is the 8-block vector path: without it, the 4-block path does the same blocks
  with the same output, only slower. `>>` turned into `>>>` on the 64-bit block counter is equivalent, as above. What the API can
  observe is tested: that `Dispose` wipes both halves of the key (the disposed cipher encrypts as an all-zero key does), each
  size check, and the smallest packet (a length with an empty body).

## Private keys written to files

`SaveAsync` and `ToOpenSshPrivateKey` build the private section in a buffer sized from the key up front, which zeroes any
array it outgrows and the final one when done, so no copy of the private fields is left in the heap. The bytes of the file
are cleared after writing; the string `ToOpenSshPrivateKey` returns cannot be.

The PKCS#8 and PuTTY writers (`ToPkcs8PrivateKey`, `ToPuttyPrivateKey`, `SaveAsync` with a `SshPrivateKeyFormat`) follow the same
rules: their buffers zero what they hold, and only the returned string is left to the garbage collector. They add no primitive:

- **PKCS#8, RSA and ECDSA:** the platform exports the key (`ExportPkcs8PrivateKey`) and encrypts it
  (`ExportEncryptedPkcs8PrivateKey`: PBES2, PBKDF2-HMAC-SHA256 with 600,000 iterations, AES-256-CBC). The iteration count is OWASP's
  for PBKDF2-HMAC-SHA256; OpenSSL's default, 2048, would not slow down guessing. CBC here is the file format's cipher, the one
  PBES2 offers in the platform, not a transport cipher; legacy algorithms still stay out of the protocol.
- **PKCS#8, Ed25519:** the PrivateKeyInfo of RFC 8410 has a fixed DER layout, so it is written as a constant prefix and the seed,
  which keeps the seed out of an ASN.1 writer's buffers; RFC 8410's example key is written back byte for byte. The platform has no
  Ed25519 to encrypt one with, so encrypting one is refused (`NotSupportedException`) rather than implemented here.
- **PuTTY `.ppk` version 3:** Argon2id (this library's, as for reading) with 46 MiB, one pass and one lane, OWASP's first Argon2id
  setting; then the platform's AES-256-CBC and HMAC-SHA256, as PuTTY defines them. The padding to the AES block is random bytes
  where PuTTYgen uses bytes of a SHA-1 hash of the blob: any bytes do, as the MAC covers them, and no SHA-1 is used. Version 2
  (SHA-1) is never written. PuTTY 0.81's `puttygen` reads every exported key, plain and encrypted, and an unencrypted file
  `puttygen` made is written back byte for byte (CI).

## Encrypted private keys read from files

Reading an encrypted key file adds no primitive. Two formats that need some care are read, never written:

- **Traditional encrypted PEM** (`BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` with `Proc-Type: 4,ENCRYPTED` and
  `DEK-Info`), as `ssh-keygen -m PEM` and OpenSSL's `-traditional` output write it. The key comes from OpenSSL's legacy
  `EVP_BytesToKey`: MD5, one iteration, and the first 8 bytes of the IV as the salt (D_1 = MD5(passphrase ‖ salt),
  D_i = MD5(D_(i-1) ‖ passphrase ‖ salt), the key is their concatenation cut to length). That derivation is weak: one MD5 per
  guess makes a stolen file cheap to attack, which is why SshSharp only reads it, to let such keys be used or converted, and
  writes OpenSSH (bcrypt_pbkdf) or PKCS#8 (PBKDF2 with 600,000 iterations) instead. MD5 and AES-CBC are the platform's
  (`MD5.HashData`, `Aes.DecryptCbc`). Only AES-128/192/256-CBC are read; DES and 3DES (`DES-CBC`, `DES-EDE3-CBC`,
  `DES-EDE3-CFB`) stay out like every other legacy algorithm, and such a key is refused with a message that names the cipher and
  says to re-encrypt it with `ssh-keygen -p -f <file>`. The PKCS#7 padding is checked by the platform; the check is not
  constant-time, which does not matter here: the file is local and decrypted once, with no oracle to ask. A wrong passphrase
  usually fails the padding check; the rare one that does not (about 1 in 256) yields bytes that do not parse as exactly one key,
  and both are reported as a wrong passphrase. The derived key and the passphrase bytes are cleared after use, and so is the
  decrypted DER once imported. Checked against `EVP_BytesToKey`'s definition, against files made in the tests, and against files
  `ssh-keygen -m PEM` (OpenSSH with OpenSSL, and OpenSSH for Windows with LibreSSL) and `openssl rsa`/`openssl ec` wrote with each
  AES key size (CI, LocalTools).
- **OpenSSH keys encrypted with `chacha20-poly1305@openssh.com`** (`ssh-keygen -Z chacha20-poly1305@openssh.com`). The key file
  uses the transport cipher differently, as OpenSSH's `sshkey.c` does (`private2_decrypt` calls `cipher_crypt` with sequence
  number 0, no additional data and the cipher's 16-byte tag; `cipher.c` gives the cipher a 64-byte key, no IV and an 8-byte
  block; `cipher-chachapoly.c` does the rest). So `bcrypt_pbkdf` derives 64 bytes; the Poly1305 key is ChaCha20 block 0 under
  the first 32 bytes with an all-zero nonce; the tag, which follows the encrypted section in the file, covers the encrypted
  section alone (there is no encrypted length); the section is decrypted from block 1; and the second 32 bytes, the packet
  cipher's length key, are never used. The tag is compared with `CryptographicOperations.FixedTimeEquals` before anything is
  decrypted, so a wrong passphrase or any edit to the section or the tag is rejected without bytes to parse. It reuses the managed
  ChaCha20 and Poly1305 reviewed above; nothing in it branches on secret data.

## Accepted risks

- **DH group 14/16/18 and group exchange** use `BigInteger.ModPow` on the ephemeral exponent, which is not constant-time. The
  exponent is used once and the timing is not observable remotely in a useful way; curve25519 and ECDH are preferred by default.
- **Group exchange primality** is one Miller-Rabin round with a random base on the server's prime (`DhGroupValidator`), after trial
  division of p and (p-1)/2 by the odd numbers below 4096. For a random-looking composite of 2048 bits or more, one round errs
  with probability below 2^-64 (Damgard, Landrock and Pomerance); it is not a bound against a prime crafted by the server, which
  needs no weak group to read its own session. More rounds, or proving (p-1)/2 prime, cost a full-size `BigInteger.ModPow` each:
  measured on Windows 11, .NET 10, x64, a connection to OpenSSH 9.6 on localhost takes 0.87 s with an 8192-bit group (0.22 s for
  `diffie-hellman-group18-sha512`), of which about 0.65 s is the one round.
- **bcrypt_pbkdf and Argon2** index tables with data derived from the passphrase. They run once, locally, when a key file is loaded or
  written.
- **Managed strings** (the password option) cannot be wiped.
- **Compression buffers** cannot be wiped. With `zlib@openssh.com` negotiated, .NET's `ZLibStream` rents an 8 KiB buffer from
  `ArrayPool<byte>.Shared` per direction and returns it uncleared, holding the last compressed payloads (plaintext to anyone who
  inflates them), and zlib frees its native window unwiped. SshSharp's own buffers, the decompressor's output included, are zeroed
  (see the [threat model](threat-model.md#compression)). Compression is off by default.

## Open

- No independent audit has been done, and none is planned. The checks on this page (reference vectors, Wycheproof, the timing
  tests and mutation testing) are what the managed code rests on.
