using System.Net;
using System.Net.Sockets;

namespace SshSharp.Tests.Integration;

/// <summary>
/// A TCP proxy between the client and a real server that can misbehave on command: add latency, limit the bandwidth, deliver the data
/// in small slices, stop forwarding in one direction or both (a dead network that sends no FIN or RST), cut the connection after a given
/// number of bytes in one direction, or cut it at once. One client connection at a time.
/// </summary>
internal sealed class FaultyProxy : IAsyncDisposable
{
    private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    private readonly (string Host, int Port) _target;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Socket> _sockets = [];
    private volatile bool _stalledToServer;
    private volatile bool _stalledToClient;
    private long _closeAfterToServer = long.MaxValue;
    private long _closeAfterToClient = long.MaxValue;

    public FaultyProxy((string Host, int Port) target)
    {
        _target = target;
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen();
        _ = Task.Run(AcceptAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndPoint!).Port;

    /// <summary>Delay added to every chunk forwarded, both ways.</summary>
    public TimeSpan Latency { get; set; }

    /// <summary>Stop forwarding in both directions without closing anything, as a dead route or a crashed peer does.</summary>
    public void Stall() => _stalledToServer = _stalledToClient = true;

    /// <summary>Stop forwarding what the client sends (the server stops reading, as it seems to the client), or start again.</summary>
    public bool StallToServer
    {
        get => _stalledToServer;
        set => _stalledToServer = value;
    }

    /// <summary>Stop forwarding what the server sends (the client's receive side goes silent), or start again.</summary>
    public bool StallToClient
    {
        get => _stalledToClient;
        set => _stalledToClient = value;
    }

    /// <summary>Cut the connection (RST) once this many bytes have gone in that direction, the last chunk only in part.</summary>
    public void CloseAfter(bool toServer, long bytes)
    {
        if (toServer)
        {
            Interlocked.Exchange(ref _closeAfterToServer, bytes);
        }
        else
        {
            Interlocked.Exchange(ref _closeAfterToClient, bytes);
        }
    }

    /// <summary>Forward in pieces of 1 to this many bytes, each sent on its own (0: as received).</summary>
    public int MaxSlice { get; set; }

    /// <summary>At most this many bytes per second each way (0: no limit).</summary>
    public int BytesPerSecond { get; set; }

    /// <summary>Close every connection abruptly (RST), as a reset router or a killed server does.</summary>
    public void Cut()
    {
        lock (_sockets)
        {
            foreach (var socket in _sockets)
            {
                socket.LingerState = new LingerOption(true, 0); // close with RST
                socket.Dispose();
            }
        }
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }

            var server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            client.NoDelay = true; // so that each slice goes out as it is sent
            await server.ConnectAsync(_target.Host, _target.Port, _stop.Token);
            lock (_sockets)
            {
                _sockets.Add(client);
                _sockets.Add(server);
            }

            _ = PumpAsync(client, server, toServer: true);
            _ = PumpAsync(server, client, toServer: false);
        }
    }

    private async Task PumpAsync(Socket from, Socket to, bool toServer)
    {
        var buffer = new byte[16 * 1024];
        long forwarded = 0;
        try
        {
            while (await from.ReceiveAsync(buffer, SocketFlags.None, _stop.Token) is var read and > 0)
            {
                while (toServer ? _stalledToServer : _stalledToClient)
                {
                    await Task.Delay(50, _stop.Token); // hold this direction: nothing arrives, nothing is closed
                }

                if (Latency > TimeSpan.Zero)
                {
                    await Task.Delay(Latency, _stop.Token);
                }

                // Up to the cut point only: the rest of this chunk never arrives, and the connection is reset.
                var limit = toServer ? Interlocked.Read(ref _closeAfterToServer) : Interlocked.Read(ref _closeAfterToClient);
                var allowed = (int)Math.Min(read, Math.Max(0, limit - forwarded));
                await SendAsync(to, buffer.AsMemory(0, allowed));
                forwarded += allowed;
                if (allowed < read || forwarded >= limit)
                {
                    Cut();
                    return;
                }
            }

            to.Shutdown(SocketShutdown.Send);
        }
        catch (Exception)
        {
            // Cut, or stopped.
        }
    }

    /// <summary>Sends <paramref name="data"/> in slices and at the bandwidth set, if any.</summary>
    private async Task SendAsync(Socket to, ReadOnlyMemory<byte> data)
    {
        while (!data.IsEmpty)
        {
            var slice = MaxSlice > 0 ? Math.Min(data.Length, Random.Shared.Next(1, MaxSlice + 1)) : data.Length;
            if (BytesPerSecond > 0)
            {
                slice = Math.Min(slice, Math.Max(1, BytesPerSecond / 20)); // a twentieth of a second's worth at a time
                await Task.Delay(TimeSpan.FromSeconds((double)slice / BytesPerSecond), _stop.Token);
            }

            var sent = await to.SendAsync(data[..slice], SocketFlags.None, _stop.Token);
            data = data[sent..];
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Dispose();
        lock (_sockets)
        {
            foreach (var socket in _sockets)
            {
                socket.Dispose();
            }
        }

        _stop.Dispose();
    }
}
