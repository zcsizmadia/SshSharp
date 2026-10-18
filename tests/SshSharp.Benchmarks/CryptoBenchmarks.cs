using BenchmarkDotNet.Attributes;
using SshSharp.Crypto;

namespace SshSharp.Benchmarks;

/// <summary>The managed primitives (the framework has no X25519, Ed25519 or OpenSSH-style ChaCha20-Poly1305).</summary>
[MemoryDiagnoser]
public class CryptoBenchmarks
{
    private readonly byte[] _privateKey = new byte[32];
    private readonly byte[] _peer = new byte[32];
    private readonly byte[] _shared = new byte[32];
    private readonly byte[] _seed = new byte[32];
    private readonly byte[] _publicKey = new byte[32];
    private readonly byte[] _message = new byte[256];
    private readonly byte[] _signature = new byte[64];
    private readonly byte[] _bulk = new byte[32 * 1024];
    private readonly byte[] _bulkOut = new byte[32 * 1024];
    private readonly byte[] _polyKey = new byte[32];
    private readonly byte[] _tag = new byte[16];

    [GlobalSetup]
    public void Setup()
    {
        new Random(1).NextBytes(_privateKey);
        new Random(2).NextBytes(_seed);
        new Random(3).NextBytes(_bulk);
        new Random(4).NextBytes(_polyKey);
        var peerPrivate = new byte[32];
        new Random(5).NextBytes(peerPrivate);
        X25519.GetPublicKey(peerPrivate, _peer);
        Ed25519.GetPublicKey(_seed, _publicKey);
        Ed25519.Sign(_seed, _message, _signature);
    }

    [Benchmark]
    public bool X25519Agree() => X25519.TryAgree(_privateKey, _peer, _shared);

    [Benchmark]
    public void Ed25519Sign() => Ed25519.Sign(_seed, _message, _signature);

    [Benchmark]
    public bool Ed25519Verify() => Ed25519.Verify(_publicKey, _message, _signature);

    [Benchmark(Description = "ChaCha20 32 KiB")]
    public void ChaCha20() => SshSharp.Crypto.ChaCha20.Xor(_privateKey, _peer.AsSpan(0, 8), 1, _bulk, _bulkOut);

    // The same with the number of blocks at once forced: 4 (Vector128) and 1 (the scalar block function, the fallback).
    [Benchmark(Description = "ChaCha20 32 KiB, 4 blocks")]
    public void ChaCha20Vector128() => SshSharp.Crypto.ChaCha20.Xor(_privateKey, _peer.AsSpan(0, 8), 1, _bulk, _bulkOut, 4);

    [Benchmark(Description = "ChaCha20 32 KiB, scalar")]
    public void ChaCha20Scalar() => SshSharp.Crypto.ChaCha20.Xor(_privateKey, _peer.AsSpan(0, 8), 1, _bulk, _bulkOut, 1);

    [Benchmark(Description = "Poly1305 32 KiB")]
    public void Poly1305Tag() => SshSharp.Crypto.Poly1305.ComputeTag(_polyKey, _bulk, _tag);
}