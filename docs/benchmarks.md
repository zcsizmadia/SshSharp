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
| chacha20-poly1305 (managed) | 16 KiB | 37.3 µs | 74.0 µs | 0 B / 32 B |
| aes256-ctr + hmac-sha2-256-etm | 16 KiB | 13.7 µs | 27.6 µs | 0 B / 32 B |

The 32 B is the `DecodedPacket` wrapper; it does not grow with the payload. AES-GCM runs on the CPU's AES instructions, which is why it is
the default first choice when the CPU has them. ChaCha20-Poly1305 is plain managed code (the framework's `ChaCha20Poly1305` is the RFC 8439
AEAD, not OpenSSH's construction), so it is the better first choice only on CPUs without AES instructions.

### What the benchmarks found

The first run showed two problems that are now fixed:

* AES-CTR allocated in proportion to the payload (5.7 KB for a 16 KiB packet): the span-based `Aes.EncryptEcb` allocates on every call on
  Windows. It now uses one persistent encryptor with fixed scratch buffers: 0 B, and 3.1x faster.
* The ChaCha20 core ran at about 150 MB/s. With the state in locals and a vectorized XOR it is 2.9x faster (37 µs for 16 KiB, about 440 MB/s).
  Vectorizing the block function itself is a possible later step.

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