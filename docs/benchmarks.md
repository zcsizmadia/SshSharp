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
| X25519 agree | 0.92 ms | 0 B |
| Ed25519 sign | 3.1 ms | 337 B |
| Ed25519 verify | 3.3 ms | 169 B |

These run once per connection (key exchange and host key check), so they are not on the transfer path.

## Comparing with SSH.NET

That comparison (throughput, latency, allocations, threads, peak memory, against the same OpenSSH container) is part of milestone M5, so it
can run on the final implementation.