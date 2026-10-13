using System.Net;
using System.Net.Sockets;

namespace SshSharp.Tests.Integration;

/// <summary>
/// A TCP proxy between the client and a real server that can misbehave on command: add latency, stop forwarding (a dead network that
/// sends no FIN or RST), or cut the connection. One client connection at a time.
/// </summary>
internal sealed class FaultyProxy : IAsyncDisposable
{
    private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    private readonly (string Host, int Port) _target;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Socket> _sockets = [];
    private volatile bool _stalled;

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
    public void Stall() => _stalled = true;

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

            var server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await server.ConnectAsync(_target.Host, _target.Port, _stop.Token);
            lock (_sockets)
            {
                _sockets.Add(client);
                _sockets.Add(server);
            }

            _ = PumpAsync(client, server);
            _ = PumpAsync(server, client);
        }
    }

    private async Task PumpAsync(Socket from, Socket to)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (await from.ReceiveAsync(buffer, SocketFlags.None, _stop.Token) is var read and > 0)
            {
                while (_stalled)
                {
                    await Task.Delay(50, _stop.Token); // hold everything: nothing arrives, nothing is closed
                }

                if (Latency > TimeSpan.Zero)
                {
                    await Task.Delay(Latency, _stop.Token);
                }

                await to.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, _stop.Token);
            }

            to.Shutdown(SocketShutdown.Send);
        }
        catch (Exception)
        {
            // Cut, or stopped.
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
