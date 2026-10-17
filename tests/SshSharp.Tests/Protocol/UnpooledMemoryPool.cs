using System.Buffers;
using System.IO.Pipelines;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// A memory pool that never reuses memory, for the test harness's in-memory pipes. A <see cref="Pipe"/> returns its segments to its pool
/// once both ends are complete, and the harness can complete them while someone is still writing (a server script sending as the test
/// disposes the server, or the client flushing as the test disposes its stream). With the shared pool, those late writes land in an
/// array another test has rented since: a stress run saw random bytes in the middle of a decrypted packet that way. With fresh arrays they
/// land nowhere that matters, and the library under test keeps its own pooled buffers, whose misuse the instrumented build reports.
/// </summary>
internal sealed class UnpooledMemoryPool : MemoryPool<byte>
{
    public static readonly UnpooledMemoryPool Instance = new();

    private const int DefaultSize = 4096;

    public override int MaxBufferSize => int.MaxValue;

    /// <summary>A pipe whose segments come from <see cref="Instance"/>.</summary>
    public static Pipe CreatePipe() => new(new PipeOptions(pool: Instance));

    public override IMemoryOwner<byte> Rent(int minBufferSize = -1) => new Owner(new byte[minBufferSize <= 0 ? DefaultSize : minBufferSize]);

    protected override void Dispose(bool disposing)
    {
    }

    private sealed class Owner(byte[] array) : IMemoryOwner<byte>
    {
        public Memory<byte> Memory => array;

        public void Dispose()
        {
        }
    }
}
