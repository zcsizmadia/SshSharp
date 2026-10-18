# Benchmarks

`tests/SshSharp.Benchmarks` uses BenchmarkDotNet. Run it with:

```
dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --filter "*" --job short
```

Drop `--job short` for a longer, more precise run. Results (including allocations per operation) go to `BenchmarkDotNet.Artifacts/`.

## Why these benchmarks exist

SshSharp is designed to be zero-copy on the packet hot path: packets are encrypted and decrypted in place in one pooled buffer, and the
only per-packet garbage is a small wrapper object. The unit tests (`AllocationTests`) fail if that stops being true; these benchmarks show
the cost.

## Packet encode and decode (one packet, in memory)

Machine: Intel Core i7-12800H, Windows 11, .NET 10.0.12, `--job short` (3 iterations, so treat the digits as indicative).

| Suite | Payload | Encode | Encode + decode | Allocated (encode / encode + decode) |
|---|---:|---:|---:|---|
| aes256-gcm | 64 B | 201 ns | 481 ns | 0 B / 32 B |
| aes256-gcm | 1 KiB | 318 ns | 751 ns | 0 B / 32 B |
| aes256-gcm | 16 KiB | 1.96 µs | 4.57 µs | 0 B / 32 B |
| chacha20-poly1305 (managed) | 16 KiB | 14.6 µs | 29.1 µs | 0 B / 32 B |
| aes256-ctr + hmac-sha2-256-etm | 16 KiB | 13.7 µs | 27.6 µs | 0 B / 32 B |

The 32 B is the `DecodedPacket` wrapper; it does not grow with the payload. AES-GCM runs on the CPU's AES instructions, which is why it is
the default first choice when the CPU has them. ChaCha20-Poly1305 is plain managed code (the framework's `ChaCha20Poly1305` is the RFC 8439
AEAD, not OpenSSH's construction), so it is the better first choice only on CPUs without AES instructions.

### What the benchmarks found

The first run showed two problems that are now fixed:

* AES-CTR allocated in proportion to the payload (5.7 KB for a 16 KiB packet): the span-based `Aes.EncryptEcb` allocates on every call on
  Windows. It now uses one persistent encryptor with fixed scratch buffers: 0 B, and 3.1x faster.
* The ChaCha20 core ran at about 150 MB/s. With the state in locals and a vectorized XOR it is 2.9x faster (37 µs for 16 KiB, about 440 MB/s).
  The block function is now vectorized as well (see below).

## ChaCha20-Poly1305 (vectorized ChaCha20)

ChaCha20 computes 8 blocks at once with 256-bit vectors (AVX2, .NET 10) or 4 with 128-bit vectors (SSE or AdvSimd, and .NET 8), and
the scalar block function only for the last few blocks of a packet or without vector hardware. The lane layout and its constant-time
review are in the [cryptography review](crypto-review.md#constant-time-review-of-the-vectorized-chacha20).

Machine: Intel Core i7-12800H, Windows 11, .NET 10.0.12 and 8.0.31, `--job medium`. Before is the scalar code (main before the
change); MB/s is bytes of payload per second.

| Benchmark | Runtime | Before | After | Speed-up |
|---|---|---:|---:|---:|
| ChaCha20, 32 KiB | .NET 10 | 49.4 µs (663 MB/s) | 16.6 µs (1,979 MB/s) | 3.0x |
| ChaCha20, 32 KiB | .NET 8 | 40.4 µs (811 MB/s) | 22.0 µs (1,493 MB/s) | 1.8x |
| Packet encode (seal), 16 KiB | .NET 10 | 35.4 µs (463 MB/s) | 17.9 µs (915 MB/s) | 2.0x |
| Packet encode (seal), 16 KiB | .NET 8 | 30.5 µs (537 MB/s) | 21.3 µs (769 MB/s) | 1.4x |
| Packet encode + decode (seal and open), 16 KiB | .NET 10 | 70.4 µs | 36.5 µs | 1.9x |
| Packet encode + decode (seal and open), 16 KiB | .NET 8 | 64.1 µs | 44.0 µs | 1.5x |
| Packet encode, 1 KiB | .NET 10 | 2.63 µs | 1.46 µs | 1.8x |
| Packet encode, 64 B | .NET 10 | 483 ns | 460 ns | 1.0x |

`CryptoBenchmarks` also runs each path on its own (`ChaCha20 32 KiB, 4 blocks` and `ChaCha20 32 KiB, scalar`): on .NET 10, 21.1 µs
with 4 blocks at once and 50.1 µs scalar.

* **Why .NET 8 stops at 4 blocks:** on .NET 8 the JIT did not inline the 8-block path's output stage (the transpose and XOR), which
  made it slower (30 µs for 32 KiB) than the 4-block path (22 µs).
* **Register pressure:** the 16 state vectors fill the 16 vector registers of x64 without AVX-512, so the JIT keeps some rotation
  temporaries on the stack. That is why 8 blocks at once is 1.3x, not 2x, faster than 4.
* **Tiering:** the vector kernels are compiled fully optimized up front (`AggressiveOptimization`). With tiered compilation, which tier
  a benchmark ended in made the ChaCha20 timing vary by a factor of two between runs.
* **Poly1305 then cost more than ChaCha20:** 20.0 µs for 32 KiB (about 1,640 MB/s), so roughly 10 µs of the 17.9 µs packet.
  Vectorizing it needs a 32×32→64-bit lane multiply, which the cross-platform `Vector128`/`Vector256` API does not have (64-bit lane
  multiplication is emulated on x64 without AVX-512), so it would need x64- and Arm64-specific intrinsics with the scalar code as the
  fallback. It now uses 64-bit limbs instead (below).

## Poly1305 (64-bit limbs)

In a 64-bit process Poly1305 holds its numbers in three limbs of 44, 44 and 42 bits and multiplies them with `Math.BigMul`
(64×64→128-bit): 9 products per 16-byte block instead of 25 with the five 26-bit limbs. Its constant-time review is in the
[cryptography review](crypto-review.md#constant-time-review-of-poly1305-with-64-bit-limbs).

Machine: Intel Core i7-12800H, Windows 11, .NET 10.0.12 and 8.0.31, `--job medium`. Before is the 26-bit code (main before the
change); MB/s is bytes of payload per second.

| Benchmark | Runtime | Before | After | Speed-up |
|---|---|---:|---:|---:|
| Poly1305, 32 KiB | .NET 10 | 19.8 µs (1,655 MB/s) | 13.0 µs (2,524 MB/s) | 1.5x |
| Poly1305, 32 KiB | .NET 8 | 20.5 µs (1,598 MB/s) | 12.7 µs (2,576 MB/s) | 1.6x |
| Packet encode (seal), 16 KiB | .NET 10 | 17.9 µs (915 MB/s) | 14.6 µs (1,124 MB/s) | 1.23x |
| Packet encode (seal), 16 KiB | .NET 8 | 21.4 µs (767 MB/s) | 18.5 µs (886 MB/s) | 1.15x |
| Packet encode + decode (seal and open), 16 KiB | .NET 10 | 36.1 µs | 29.1 µs | 1.24x |
| Packet encode + decode (seal and open), 16 KiB | .NET 8 | 44.4 µs | 37.2 µs | 1.19x |

`CryptoBenchmarks` also runs the 26-bit code on its own (`Poly1305 32 KiB, 26-bit limbs`): 19.3 µs on .NET 10 and 19.6 µs on
.NET 8, the same as before the change. Before and after ran back to back on an otherwise idle machine; the .NET 8 "before" Poly1305
measurement is bimodal in every run (20.4 to 20.5 µs on average), the others are not.

* **Why not 2x:** the multiplications are a third of what they were, but each 128-bit product is still split, summed and carried, and
  .NET's `Math.BigMul` hands the low half of `mulx` back through a stack slot. Storing the multipliers shifted left by 20 bits, so
  that the high word of a product is already the part above bit 44, saved about a tenth of the time against splitting each
  product afterwards (12.7 against 14.1 µs for 32 KiB in a simple timing loop on .NET 10).
* **32-bit processes keep the 26-bit code.** Without a 64×64-bit multiply instruction, the runtime computes each `Math.BigMul` from
  four 32-bit multiplies. Measured on the same machine with the 32-bit (x86) runtime, 32 KiB took 72 to 73 µs with the 64-bit limbs
  against 36 to 38 µs with the 26-bit limbs on .NET 10, and 84 to 85 µs against 36 to 37 µs on .NET 8 (a simple timing loop). Which code runs is decided by
  `Environment.Is64BitProcess`, a constant for the JIT.
* **With ChaCha20 vectorized and Poly1305 on 64-bit limbs**, a 16 KiB chacha20-poly1305 packet now takes about 15 µs to seal on
  .NET 10, against 2 µs with AES-GCM on AES instructions.

## Public key operations (one operation)

| Operation | Time | Allocated |
|---|---:|---|
| X25519 agree | 228 µs | 0 B |
| Ed25519 sign | 607 µs | 336 B |
| Ed25519 verify | 264 µs | 168 B |

These run once per connection (key exchange and host key check), so they are not on the transfer path, but they are a visible part of
the connect time. The first version used TweetNaCl's field arithmetic (16 limbs of 16 bits) and measured 0.92 ms, 3.1 ms and 3.3 ms.
The field now uses 5 limbs of 51 bits with 128-bit products, and verification uses a joint double-scalar multiplication (its inputs
are public), which made X25519 4x and verification 12x faster.

## Comparing with SSH.NET

`ComparisonBenchmarks` runs the same operations through SshSharp and SSH.NET 2026.0.0 against the same OpenSSH server, with the same
algorithms forced on both (`curve25519-sha256`, `aes256-gcm@openssh.com`, `ssh-ed25519`) and password authentication. The
`--peak` mode streams a large output through one library in a fresh process and reports its throughput, CPU and memory.

`scripts/bench-lanes.sh` runs everything on one Linux machine in parallel lanes. Each lane has its own OpenSSH container (the CI
image) and its own CPU cores, split between client and server, so the lanes don't compete:

```
scripts/bench-lanes.sh [cores-per-side] [peak-mebibytes]    # for example: 8 4096, which needs 112 cores
```

Machine: AMD EPYC 7543 (128 logical cores), Ubuntu 22.04, .NET 10.0.12, OpenSSH on Alpine 3.22 in Docker, 8 client and 8 server
cores per lane, BenchmarkDotNet 0.15.8 in-process.

| Benchmark | SSH.NET | SshSharp | SshSharp time | Allocated (SSH.NET / SshSharp) |
|---|---:|---:|---:|---|
| Connect and authenticate | 24.2 ms | 26.9 ms | 1.11x | 68.7 KB / 56.4 KB |
| Run a command (`echo hi`) on an open connection | 1.76 ms | 1.68 ms | 0.96x | 12.1 KB / 6.3 KB |
| 8 commands (`echo hi`) in parallel on one connection | 6.04 ms | 3.90 ms | 0.65x | 84.8 KB / 53.7 KB |
| Download 32 MiB (command output) | 80.7 ms | 76.5 ms | 0.95x | 639 KB / 160 KB |
| SCP upload 32 MiB | 374 ms | 170 ms | 0.46x | 344 KB / 173 KB |

Streaming 2 GiB of command output (`--peak`), client on 8 cores:

| | SSH.NET | SshSharp |
|---|---:|---:|
| Throughput | 432 MiB/s | 428 MiB/s |
| Client CPU per GiB | 4.88 s | 5.57 s |
| ... with thread-pool spinning off | 2.69 s | 2.40 s |
| Throughput with the client on 1 core | 265 MiB/s | 434 MiB/s |
| Peak working set (4 GiB run) | 83 MiB | 76 MiB |
| Allocated (4 GiB run) | 62 MiB | 15 MiB |

For reference, OpenSSH's own `ssh` client reaches 397 MiB/s on the same setup: the server's single encryption thread sets the pace,
so on many cores both libraries keep up with it. The CPU each library spends per GiB, and how it does on one core, are what tell
them apart.

Most of the client CPU in the 8-core run is the .NET thread pool spin-waiting for work between packets, not SSH work. It affects
both libraries, and setting `DOTNET_ThreadPool_UnfairSemaphoreSpinLimit=0` removes it without costing throughput. SshSharp's
CPU per GiB is lower than SSH.NET's once spinning is excluded. On one core, SshSharp keeps the full rate and SSH.NET slows to
265 MiB/s.

### Measuring a connect fairly

A connect is short and runs mostly code that runs once per connect, so how it is measured decides much of the result:

* **Only the connect is timed.** `Connect_SshSharp` connects through the `ssh_config` route (to force the algorithms through public
  API), and builds and parses that configuration once, outside the timed connects, as an application holds its configuration.
  Each connect still resolves the host's settings from it and reads the key file, as SSH.NET's `Connect` reads its `PrivateKeyFile`.
  Until this change the configuration text was built and parsed inside every timed connect.
* **The same authentication on both sides.** With `SSHSHARP_BENCH_KEY` (an OpenSSH key file) both libraries log in with that key;
  otherwise both use the password, the only method each is given. `SSHSHARP_BENCH_CIPHER` picks the cipher forced on both.
* **Cold and warm are reported apart.** The connect profiler (`-- --connect-profile`) first times the first connect in the process
  (cold: everything is compiled on the way, as for a command-line tool that connects once), then warms up with 100 connects of each
  route (`SSHSHARP_BENCH_WARMUP` changes it) and a pause, so that the measured rounds run optimized code, as in a long-running
  service. With one warm-up connect, methods that run once per connect stayed in the unoptimized tier for all the measured rounds.
  BenchmarkDotNet measures the `Connect` benchmarks after its own warm-up iterations, so they report the warm figure.

### SFTP

`SftpBenchmarks` compares the SFTP clients: SshSharp's `SftpClient` against SSH.NET's `Renci.SshNet.SftpClient`. It uses the same
server, algorithms and environment variables as `ComparisonBenchmarks`. Run it on its own with:

```
dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --filter "*SftpBenchmarks*"
```

| Category | SSH.NET (baseline) | SshSharp |
|---|---|---|
| `SftpUpload32MiB` | `UploadFileAsync` from a `MemoryStream` | `UploadAsync` from a `MemoryStream` |
| `SftpDownload32MiB` | `DownloadFileAsync` into `Stream.Null` | `DownloadAsync` into `Stream.Null` |
| `SftpOpenWrite32MiB` | `CopyToAsync` into `OpenAsync(..., FileMode.Create, FileAccess.Write)` | `CopyToAsync` into `OpenWriteAsync` |

Each library works in a new directory under `/tmp` on the server (`sshsharp-sftp-bench-` and a random suffix). The setup uploads
the 32 MiB file that both libraries download, and the cleanup removes the directory. The memory diagnoser reports allocated bytes
and Gen0, Gen1 and Gen2 collections per operation. With OpenSSH's 255 KiB requests, an array allocated for each request lands on
the large object heap, so Gen2 collections show it.

### What the comparison found

* **Connect** first measured 2.2x SSH.NET's time. Profiling each phase showed the key exchange took 12 ms, mostly in the
  managed X25519 and Ed25519. The faster field arithmetic (see above) brought the whole connect within 12% of SSH.NET.
  The rest is the server (process start, password check), the same for both libraries.
* **Allocations while streaming** were first 837 KB for the 32 MiB download, more than SSH.NET's. The `--peak` mode's
  allocation sampler showed why: async state machine boxes on the receive path (the methods complete asynchronously for
  nearly every packet), and two closures allocated per packet by lambdas that rarely run. With pooled builders and those
  lambdas moved into methods of their own, streaming allocates about 90 bytes per 32 KiB packet (the packet and data
  wrappers), and a 1 GiB transfer runs without a garbage collection.
* **Setup pitfalls** that made early numbers meaningless, and that the scripts now avoid:
  * The CI image renews keys every 32 KiB (`RekeyLimit 32K`, to test rekeying), which held every transfer to about 2 MiB/s. The
    benchmark containers set `REKEY_LIMIT="default none"`.
  * BusyBox `head -c` caps its output at about 130 MiB/s, so the benchmarks use `dd if=/dev/zero bs=1048576`.
  * Docker's userland proxy for published ports adds its own ceiling, so the lanes connect to each container's address directly.

### A second machine: Windows and WSL

A later round of measurements, on a laptop, covers what the Linux host above does not: a Windows client. It found five things worth
fixing (#304-#307), all now in. Each change was measured on its own, against the code before it, with SSH.NET 2026.0.0 measured in
the same run as the control.

Machine: Intel Core i7-12800H (20 logical cores), Windows 11 with WSL 2 (Ubuntu 24.04, mirrored networking), OpenSSH 9.6p1 in WSL
as the server (a separate `sshd` with `RekeyLimit default none` and the SFTP subsystem, pinned to cores 8-15), BenchmarkDotNet 0.15.8
in-process, medium job. Ed25519 key authentication, `curve25519-sha256`, `ssh-ed25519` host key. Two clients:

* **Linux:** the client runs inside WSL on .NET 10.0.7, pinned to cores 0-7, so client and server talk over Linux loopback.
* **Windows:** the client runs on Windows on .NET 10.0.12. WSL's mirrored loopback relays the traffic, which caps it at about
  85-95 MiB/s for both libraries, so the throughput there says little; the client CPU per GiB is what tells the libraries apart.

Linux client, AES-256-GCM:

| Benchmark | SSH.NET | SshSharp | Allocated (SSH.NET / SshSharp) |
|---|---:|---:|---|
| Connect and authenticate | 21.0 ms | 20.9 ms | 86.7 KB / 73.4 KB |
| Run a command (`echo hi`) | 1.77 ms | 1.84 ms | 12.0 KB / 5.7 KB |
| 8 commands in parallel | 7.83 ms | 3.87 ms | 85.0 KB / 47.5 KB |
| Download 32 MiB (command output) | 251 ms | 181 ms | 876 KB / 206 KB |
| SCP upload 32 MiB | 212 ms | 211 ms | 382 KB / 106 KB |
| SFTP upload 32 MiB | 257 ms | 244 ms | 857 KB / 223 KB |
| SFTP download 32 MiB | 235 ms | 188 ms | 2464 KB / 356 KB |
| SFTP `CopyToAsync` into an open file, 32 MiB | 681 ms | 226 ms | 2282 KB / 241 KB |

Streaming 2 GiB of command output (`--peak`), Linux client:

| | SSH.NET | SshSharp |
|---|---:|---:|
| Throughput, AES-256-GCM | 132 MiB/s | 157 MiB/s |
| Client CPU per GiB, AES-256-GCM | 8.4 s | 7.0 s |
| Throughput, ChaCha20-Poly1305 | 127 MiB/s | 156 MiB/s |
| Client CPU per GiB, ChaCha20-Poly1305 | 14.8 s | 10.8 s |

With ChaCha20-Poly1305 the comparison measures SshSharp's managed cipher against SSH.NET's (BouncyCastle); with AES-GCM both use the
platform's. `SSHSHARP_BENCH_CIPHER` picks the cipher forced on both.

Streaming 1 GiB, Windows client (AES-256-GCM):

| Client CPU per GiB | SSH.NET | SshSharp before #304 | SshSharp |
|---|---:|---:|---:|
| Default runtime settings | 2.6 s | 24.8 s | 4.4 s |
| `DOTNET_ThreadPool_UnfairSemaphoreSpinLimit=0` | 1.5 s | 7.5 s | 2.2 s |

What these measurements found:

* **Small socket reads on Windows (#304).** The transport read the socket through a pipe with its default 4 KiB buffer, so one
  32 KiB packet took nine or more reads, each an asynchronous completion handed through the thread pool, and each pool wake-up
  spun. On Linux the same code cost little; on Windows it cost about ten times SSH.NET's CPU. Reads into a 128 KiB buffer, waiting
  for a whole packet before decoding it, cut that by a factor of six. Zero-byte reads keep an idle connection from holding the
  buffer, at no measured cost. The rest of the gap on Windows is SSH.NET's dedicated thread blocking on the socket, against
  SshSharp's asynchronous reads through the thread pool.
* **The public key query (#306).** Connect took 27 ms against SSH.NET's 18. A packet timeline (a logging proxy in front of the
  server) showed why: after answering a public key query (PK_OK), OpenSSH's `sshd` waits before it reads the next request, about
  6 ms here (`ensure_minimum_time_since`, its defence against telling users apart by timing). SSH.NET signs straight away and never
  pays it. SshSharp now signs straight away with keys held in memory, and keeps the query for agent, signer and hardware keys.
* **Unoptimized code on early connects (#306).** In a new process, the key exchange and the signature ran several times slower
  than the crypto micro-benchmarks suggest: once-per-connect code runs unoptimized (tier 0) until it has been called often. The
  managed X25519, Ed25519 and field arithmetic are now compiled fully optimized on first use (`AggressiveOptimization`), which
  matters to a tool that connects once.
* **Large arrays per SFTP request (#307).** With OpenSSH's 255 KiB requests, each write allocated three large-object-heap arrays and
  each read reply one: 132 MB allocated and a thousand full collections per 32 MiB upload. Requests are now built in pooled buffers
  of their exact size, and data replies are read into pooled buffers: 240 KB per upload, no full collections.
* **Allocations on the send path (#305):** pooled SCP buffers and send state machines, one copy less per data packet, and padding
  randomness drawn 256 bytes at a time took an SCP upload from 273 KB to 106 KB and a command from 7.3 KB to 5.7 KB.
* **Setup pitfalls:**
  * WSL's test server renews keys every 32 KiB (`RekeyLimit 32K`, for the tests), so the benchmarks use a separate `sshd`.
  * With the client on Windows, WSL's loopback relay caps every transfer, so library-bound throughput needs the client inside WSL.