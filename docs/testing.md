# Testing and validation

An SSH library is trusted with credentials, host keys and other people's servers, so how it is tested matters as much as what it
does. This page describes what is tested, against what, how intermittent failures are hunted down, and what is not covered yet.

## At a glance

| What | How |
|---|---|
| Unit tests | About 1,300 per target framework, with no network: scripted fake servers and agents over in-memory streams, and a fake clock |
| Known-answer vectors | RFC and reference vectors, OpenSSL's Curve25519 vectors, the sntrup761 KAT, and about 6,400 [Project Wycheproof](https://github.com/C2SP/wycheproof) edge cases |
| Real servers | OpenSSH (from 7.x to current, Linux and Windows), Dropbear, AsyncSSH, Apache MINA SSHD, Erlang/OTP `ssh`, and two SFTP-only servers, on every pull request |
| Network faults | A proxy that cuts, stalls, slows down and fragments connections to real servers, at any point |
| Fuzzing | Coverage-guided fuzzing of the parsers that read untrusted input, nightly; mutation fuzzing in every test run |
| Mutation testing | Stryker.NET over the cryptography, the packet codec and the configuration parsers |
| Stress | The whole suite in a loop on every platform, with an instrumented build that checks buffer ownership and received data |
| Platforms | Linux (x64, Arm64), Windows (x64, Arm64), macOS (Arm64), each on .NET 8 and .NET 10, plus a Native AOT smoke test |
| Algorithm audit | [ssh-audit](https://github.com/jtesta/ssh-audit) rates what the client offers, by default and in FIPS mode, on every pull request |
| Static analysis | CodeQL, the .NET analyzers at their recommended level with warnings as errors, and tracked public API |

## Unit tests

The protocol stack runs over any `Stream`, so the unit tests need no network. Scripted fake servers (`FakeSshServer`,
`FakeSessionServer`, `FakeSftpServer`) and a fake SSH agent play the other side over in-memory pipes. They can also misbehave on
purpose: send malformed or out-of-order messages, stall, refuse, reorder SFTP replies, or answer slowly. Time comes from a
`TimeProvider`, so keep-alives, channel timeouts, re-key intervals and keystroke timing are tested on a fake clock. Real sleeps
are not used. The file system, the environment and `Match exec` sit behind small delegates.

Inputs come from the real tools wherever possible:
- `known_hosts` files and KRLs made by OpenSSH
- private keys made by `ssh-keygen`, in every format and with every cipher it can encrypt a key with
- PuTTY `.ppk` files made by `puttygen`
- the key files SshSharp writes (OpenSSH, PKCS#8, `.ppk`), read back by `ssh-keygen`, OpenSSL and `puttygen`; and unencrypted keys
  OpenSSL and `puttygen` make, written back byte for byte
- `ssh_config` files using OpenSSH's own syntax and tokens

## Cryptography

SshSharp uses the .NET libraries for every primitive they provide on both target frameworks. It implements X25519, Ed25519,
ChaCha20, Poly1305, AES-CTR and sntrup761 itself. Those implementations are checked against:

- **Reference vectors:** the RFCs' test vectors, OpenSSL's Curve25519 vectors, and the sntrup761 known-answer tests.
- **[Project Wycheproof](https://github.com/C2SP/wycheproof):** about 6,400 edge cases, each of which broke a real implementation
  somewhere. They cover:
  - X25519 (low-order and non-canonical points) and Ed25519 (non-canonical encodings, malleable signatures)
  - ChaCha20 and Poly1305, through RFC 8439's construction
  - ECDH on P-256, P-384 and P-521 (invalid-curve attacks, points on the wrong curve), through the key exchange's own point check
  - ECDSA and RSA signature verification through the SSH signature path, RSA from 2048 to 8192 bits
  - RSA signing (rsa-sha2-256 and rsa-sha2-512), from a PEM key to the signature
  - AES-GCM, ML-KEM-768 and ML-KEM-1024 decapsulation, and HMAC-SHA-256/512, with the parameters SSH uses

  Every vector gives the expected answer. Wycheproof keeps adding vectors as new bugs are found, so the copies in the repository are
  checked for updates from time to time and before each release; the
  [fixtures' README](https://github.com/zcsizmadia/SshSharp/blob/main/tests/SshSharp.Tests/Fixtures/wycheproof/README.md) says how.
- **Differential tests:** the vectorized ChaCha20 (8 and 4 blocks at once) against the scalar code, for every length up to 2,000
  bytes, long buffers, and counters that cross the 2^32 and 2^64 boundaries in every lane. The tests choose the path explicitly, so
  every path runs on every CI platform, whatever vector width its CPU has. Poly1305 with 64-bit limbs against the 26-bit code (which
  32-bit processes use) and against the definition computed with `BigInteger`: random keys and messages of every length up to 1,100
  bytes and long ones, the largest clamped r, accumulators just below and above p and 2^130, an s that carries out of 2^128, the final reduction on its own at the edges of its limb bounds, and
  every RFC 8439 Poly1305 vector. Both limb sizes run on every machine.
- **Constant-time review and a timing test:** see the [cryptography review](crypto-review.md).

## Real servers

The interop tests run against real servers on every pull request. Each server catches something the others tolerate:

| Server | What it checks |
|---|---|
| **OpenSSH** on Linux (x64 and Arm64) | Keys of every type and format, host and user certificates from a test CA, `ssh-agent` and agent forwarding, PAM keyboard-interactive, Kerberos (a throwaway realm), every key exchange, cipher and MAC, forwarding of every kind, SFTP and SCP, re-keying every 32 KiB |
| **OpenSSH** on Alpine 3.6, 3.13, 3.19 and 3.22 | Releases from several eras, including ones without strict key exchange (Terrapin) |
| **OpenSSH for Windows** | ConPTY terminals, Windows paths, and the Windows server's own behaviour |
| **Dropbear** (two releases) | A second C implementation, with its own limits and quirks |
| **AsyncSSH** | An independent implementation in Python. It found that SFTP symbolic links were sent in the wrong argument order for servers that follow the SFTP draft |
| **Apache MINA SSHD** | An independent implementation in Java, the server inside Jenkins, Gerrit and Eclipse. It answers keep-alive requests, reports a killed command as an exit status, and has no pseudo-terminal. It re-keys only when the client does: with a small limit of its own, MINA 2.20.0 sometimes failed sessions while both sides re-keyed |
| **Erlang/OTP `ssh`** | An implementation known for following the RFCs strictly: the transport with every algorithm it offers, host keys, SFTP, forwarding and network faults (no shells or commands, which run Erlang there). Its SFTP server ignores a new file size and still answers OK |
| **atmoz/sftp** and a **Go `pkg/sftp`** server | Chrooted, SFTP-only servers, the kind behind many hosted file-transfer services |

A key-exchange volume test can run thousands of handshakes per host key type against a server. It is off by default and turned on
with `SSHSHARP_TEST_HANDSHAKES`.

**[ssh-audit](https://github.com/jtesta/ssh-audit)** checks what the client offers. In client mode it listens as a server, records
the key exchanges, host keys, ciphers and MACs in SshSharp's first message, and rates each one. A CI job runs it on every pull
request, once with the default options and once in FIPS mode. The job fails if:
- any rating is not one of the few explained in
  [the checker](https://github.com/zcsizmadia/SshSharp/blob/main/tests/ssh-audit/check_client_audit.py), such as ssh-audit's
  opinion of the NIST curves, which OpenSSH's client also offers;
- ssh-audit lists a CVE;
- strict key exchange (the Terrapin countermeasure) is missing;
- the default list does not start with a post-quantum hybrid;
- FIPS mode offers anything outside FIPS.

A weakened default list therefore fails at once.

## Network faults

A fault-injection proxy sits between the client and a real server. It can:
- cut the connection at once, or after a chosen number of bytes in either direction (in the middle of a packet)
- stop forwarding in both directions, as a dead route does (no FIN, no RST: only keep-alive can tell)
- stop forwarding in **one** direction only, so the peer seems to stop reading while the connection looks alive
- add latency, limit the bandwidth, or deliver the data in tiny segments

A separate test kills the server's process for one session, as an administrator or the OOM killer would.

Every fault must end promptly with an `SshException`, never with a hang or another exception type, and disposing a client must
always finish. A sweep cuts the connection at 13 points from the first byte to well past authentication, in each direction.

## Fuzzing and mutation testing

- **Coverage-guided fuzzing** (SharpFuzz and libFuzzer, nightly) of the parsers that read untrusted input. The targets are
  packets, the server's identification line, `KEXINIT`, public keys and signatures, certificates, private keys (text and binary),
  `known_hosts`, `ssh_config`, KRLs, SFTP replies and compressed packets (`zlib@openssh.com`). Each parser is also mutation-fuzzed briefly in every unit test run.
- **Mutation testing** (Stryker.NET, weekly and on demand) over the cryptography, the packet codec, compression and the configuration
  parsers. A surviving mutant is a code change no test notices. The score is reported, not enforced.

## Stress testing and intermittent failures

A stress workflow runs the unit tests on every platform, and the interop tests against every server, in a loop (100 iterations
per job for a release). It uses an instrumented build that:
- tracks every pooled buffer and reports a buffer returned twice, with both stacks
- checksums received data when it arrives, and checks it again when it is read and when it is released, so a buffer overwritten
  while queued is reported where it happens
- records a bounded trace of relays and key exchanges, which a hung test includes in its failure message, together with the step
  it was stuck in

Intermittent failures are treated as bugs until shown otherwise. They are not retried away, and tests are not serialised to hide
a race. The rule of thumb used: no failures in N runs bounds the failure rate below about 3/N with 95% confidence, so a failure
seen once in 20 runs needs about 60 clean runs before it counts as gone. A failure is closed when its cause is understood, and
ideally reproduced by a test.

Before 0.6.0 this hunt ([#188](https://github.com/zcsizmadia/SshSharp/issues/188)) found, among others:
- **A real data race:** disposing a session or tunnel while another task read it could hand the reader zeroed bytes. Found by the
  instrumented build's checksum report, reproduced by a test, and fixed.
- **A real hang:** disposing a client could wait forever when the server had stopped reading in the middle of a write. Reproduced
  by a test that hung, and fixed.
- **Server-side failures, avoided in tests:** OpenSSH for Windows drops some accepted connections under a burst of them, and its
  pipe close can deadlock. Both are reported with the server's own logs as evidence.
- **Flaws in the tests themselves:** fixed waits, counters read without their lock, fake servers that spun a thread. These are
  fixed in the tests, not tolerated.

## Test categories and skips

A test that cannot run where it is (no server, no tool, a platform without the feature) skips itself and says why. A skip passes,
so CI checks that every skip is one it expects.

### Categories

The test classes carry a TUnit `[Category]`, and each CI job selects its tests by category:

| Category | What | Where it runs |
|---|---|---|
| (none) | Unit tests: fake servers, in-memory streams, no network | The unit jobs, on every OS and target framework |
| `LocalTools` | Key files read back by `ssh-keygen`, OpenSSL and `puttygen`; no server | The unit jobs and the OpenSSH runner job. CI installs PuTTY's command-line `puttygen` on Linux and macOS; on Windows, PuTTY's `puttygen.exe` has only a window, so the `.ppk` tests skip there |
| `Integration` | Tests against a real server (`SSHSHARP_TEST_SSHD` and the other `SSHSHARP_TEST_*` variables) | The interop jobs |
| `SshAudit` | The client audit; also `Integration`, but it needs ssh-audit listening, not an SSH server | The audit job |
| `Measure` | Measurements, not checks (`SSHSHARP_MEASURE=1`) | Nowhere in CI; by hand |

The selections, as TUnit tree filters (Microsoft.Testing.Platform's `--treenode-filter`):

| Run | Filter |
|---|---|
| Unit tests | `/*/*/*/*[(Category!=Integration)&(Category!=Measure)]` |
| Interop tests | `/*/*/*/*[(Category=Integration)&(Category!=SshAudit)&(Category!=Measure)]` |
| A measurement | `/*/*/*/*[Category=Measure]`, with `SSHSHARP_MEASURE=1` |

A new test class that needs a real server gets `[Category("Integration")]`. Without it, the class runs in the unit jobs, where it
skips, and the skip check fails the job.

### Running them locally

Build once, then run the test assembly with a filter (`dotnet test --project tests/SshSharp.Tests -f net10.0 --treenode-filter ...`
takes the same filters):

```shell
dotnet build tests/SshSharp.Tests -c Release
# the unit tests
dotnet tests/SshSharp.Tests/bin/Release/net10.0/SshSharp.Tests.dll --treenode-filter "/*/*/*/*[(Category!=Integration)&(Category!=Measure)]"
# the interop tests, against a server named by SSHSHARP_TEST_SSHD, SSHSHARP_TEST_USER and so on (without one they all skip)
dotnet tests/SshSharp.Tests/bin/Release/net10.0/SshSharp.Tests.dll --treenode-filter "/*/*/*/*[(Category=Integration)&(Category!=SshAudit)&(Category!=Measure)]"
```

Without a filter everything runs, and the Integration tests skip at once when no server is configured.

### Expected skips

Each CI job lists the tests it may skip, in
[tests/ci/skips](https://github.com/zcsizmadia/SshSharp/tree/main/tests/ci/skips): one file per job, such as
`unit-ubuntu-latest-net8.0.txt` or `interop-dropbear-alpine-3.22.txt`, with one `Class.DisplayName` per line. The jobs write a TRX
report (`--report-trx`), and
[tests/ci/check-skips.ps1](https://github.com/zcsizmadia/SshSharp/blob/main/tests/ci/check-skips.ps1) compares its skips with the
list:

- a skip that is not on the list fails the job, naming the test and its reason;
- a listed test that ran, or was not in the run, gives a notice, so the list can be tightened;
- the job summary counts the skips by reason.

The lists hold only what a job cannot run: .NET 8 without ML-KEM or `gssapi-with-mic`, a Linux without ML-KEM in its OpenSSL,
Windows without FIFOs, servers without an algorithm, an extension or a key setup. A new skip is not added to a list until it is
understood. A skip can hide a regression as well as a limit of the platform.

When a job's skips change on purpose, update its list. To regenerate one from a TRX report (the `coverage-<os>` artifact holds
the unit jobs'), run the script with `-Update` and review the diff before committing it:

```shell
pwsh tests/ci/check-skips.ps1 -Job "unit (ubuntu-latest) net10.0" -Trx TestResults/unit-net10.0.trx -Update
```

The file name comes from the job's name, in lower case, with anything but letters, digits and dots replaced by `-`.

## Coverage

The unit tests alone cover about 95% of lines and 91% of branches, merged across the platforms. Code that only the interop tests
exercise (real re-keys, forwarding, SFTP against real servers) is not counted yet. The target is 95%, reported but not enforced.
`scripts/coverage.ps1` writes the HTML report locally.

Coverage shows that code ran, not that it is right under concurrency. The races and hangs above were in covered code. The stress
runs, the instrumented build and the fault tests are what found them.

## Not covered yet

- **An independent review of the managed cryptography,** still planned. Until then, it is checked against the reference
  vectors, Wycheproof and the timing test.
- **Interop coverage** in the coverage figure.
- **Commercial negative-testing suites** (thousands of malformed messages against the client). Fuzzing covers the parsers, but not
  every message sequence.

See also the [threat model](threat-model.md) and the [design notes](design.md).
