using System.Buffers.Binary;
using System.Text;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/custom-channels.md.</summary>
internal static class CustomChannels
{
    /// <summary>An SSH string: a big-endian uint32 length, then the UTF-8 bytes.</summary>
    private static byte[] SshString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var result = new byte[4 + bytes.Length];
        BinaryPrimitives.WriteInt32BigEndian(result, bytes.Length);
        bytes.CopyTo(result, 4);
        return result;
    }

    public static async Task ChannelAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <open-channel>
        // A channel type the server defines, with its type-specific data (here one SSH string) encoded as the type defines it.
        await using var channel = await client.OpenChannelAsync("metrics@example.com", SshString("v2"), cancellationToken);

        // Send the request, end the writing side, then read the answer until the server ends its side.
        await channel.Stream.WriteAsync(Encoding.UTF8.GetBytes("GET cpu\n"), cancellationToken);
        await channel.ShutdownSendAsync(cancellationToken);
        using var reader = new StreamReader(channel.Stream, Encoding.UTF8);
        Console.WriteLine(await reader.ReadToEndAsync(cancellationToken));
        // </open-channel>
    }

    public static async Task GlobalRequestAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <global-request>
        // A global request the server defines. A server that does not know it answers with a failure, returned rather than thrown.
        var result = await client.SendGlobalRequestAsync("quota@example.com", SshString("home"), cancellationToken);
        if (result.Success && result.Data.Length >= 8)
        {
            // The answer's fields, as the request defines them: here one uint64.
            Console.WriteLine($"{BinaryPrimitives.ReadUInt64BigEndian(result.Data.Span):N0} bytes free");
        }
        // </global-request>
    }
}
