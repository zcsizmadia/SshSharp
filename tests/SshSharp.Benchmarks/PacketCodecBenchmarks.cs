using System.Buffers;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using SshSharp.Protocol;

namespace SshSharp.Benchmarks;

/// <summary>
/// Packet encode and decode per cipher suite and payload size: the hot path of every transfer. The memory column should read 0 B for
/// encoding and a small constant (the pooled packet wrapper) for decoding, whatever the payload size.
/// </summary>
[MemoryDiagnoser]
public class PacketCodecBenchmarks
{
    private PacketProtector _sender = null!;
    private PacketProtector _receiver = null!;
    private byte[] _payload = null!;
    private ArrayBufferWriter<byte> _buffer = null!;
    private uint _sequence;

    [Params("chacha20-poly1305", "aes256-gcm", "aes256-ctr+hmac-sha2-256-etm")]
    public string Suite { get; set; } = string.Empty;

    [Params(64, 1024, 16384)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _sender = Create(Suite);
        _receiver = Create(Suite);
        _payload = RandomNumberGenerator.GetBytes(PayloadSize);
        _payload[0] = 94;
        _buffer = new ArrayBufferWriter<byte>(PayloadSize + 1024);
        _sequence = 0;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sender.Dispose();
        _receiver.Dispose();
    }

    [Benchmark]
    public int Encode()
    {
        _buffer.Clear();
        PacketCodec.Encode(_buffer, _payload, _sender, _sequence++);
        return _buffer.WrittenCount;
    }

    [Benchmark]
    public int EncodeThenDecode()
    {
        _buffer.Clear();
        var sequence = _sequence++;
        PacketCodec.Encode(_buffer, _payload, _sender, sequence);
        PacketCodec.TryDecode(new ReadOnlySequence<byte>(_buffer.WrittenMemory), _receiver, sequence, out var packet, out _);
        using (packet)
        {
            return packet!.Payload.Length;
        }
    }

    private static PacketProtector Create(string suite)
    {
        var key = new byte[64];
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(i * 7);
        }

        return suite switch
        {
            "chacha20-poly1305" => new ChaCha20Poly1305Protector(key),
            "aes256-gcm" => new AesGcmProtector(key.AsSpan(0, 32), key.AsSpan(32, 12)),
            _ => new AesCtrEtmProtector(key.AsSpan(0, 32), key.AsSpan(32, 16), key.AsSpan(0, 32), HashAlgorithmName.SHA256),
        };
    }
}