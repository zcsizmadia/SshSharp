using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// The shared connection per endpoint: kept while it is up, opened again when it drops, with a growing wait after failures so a down
/// server is not hammered. Owns its clients; disposing it (with the container) disposes them. Reports each connection's start and end
/// to the watchers of its endpoint (<see cref="WatchAsync"/>).
/// </summary>
internal sealed class SshConnectionProvider(SshClientFactory factory, TimeProvider? time = null) : ISshConnectionProvider, IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private volatile bool _disposed;

    public async Task<SshClient> GetClientAsync(string name, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var endpoint = factory.Endpoint(name);
        var entry = _entries.GetOrAdd(name, static _ => new Entry());
        if (entry.Client is { IsConnected: true } current)
        {
            return current;
        }

        await entry.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (entry.Client is { IsConnected: true } shared)
            {
                return shared; // another caller reconnected while this one waited
            }

            if (entry.Client is { } dead)
            {
                // Reported here as well as by the closed token's callback, whichever comes first: that callback may still be on its
                // way, and the drop must reach watchers before the reconnection does.
                ReportDisconnected(name, entry, dead);
                entry.Client = null;
                await dead.DisposeAsync().ConfigureAwait(false);
            }

            if (entry.LastError is { } last && _time.GetUtcNow() < entry.RetryAt)
            {
                // Still waiting before the next attempt. A new exception for each caller, with the failure inside: rethrowing the one
                // instance to every caller would grow its stack trace with each of them, from several threads at once.
                throw new SshException(last is SshException ssh ? ssh.Reason : SshFailureReason.ConnectFailed,
                    $"The SSH endpoint '{name}' failed to connect; the next attempt is at {entry.RetryAt:u}. {last.Message}", last);
            }

            try
            {
                var client = await factory.ConnectAsync(name, cancellationToken).ConfigureAwait(false);
                entry.Client = client;
                entry.LastError = null;
                entry.Delay = TimeSpan.Zero;
                ReportConnected(name, entry, client);
                return client;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // The caller giving up is not the server's failure; anything else is, and the next attempt waits longer.
                entry.Delay = entry.Delay == TimeSpan.Zero
                    ? endpoint.ReconnectDelay
                    : TimeSpan.FromTicks(Math.Min(entry.Delay.Ticks * 2, endpoint.MaxReconnectDelay.Ticks));
                entry.RetryAt = _time.GetUtcNow() + entry.Delay;
                entry.LastError = ex;
                throw;
            }
        }
        finally
        {
            entry.Gate.Release();
        }
    }

    public async IAsyncEnumerable<SshConnectionEvent> WatchAsync(string name, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        factory.Registry.ThrowIfUnknown(name);
        var entry = _entries.GetOrAdd(name, static _ => new Entry());

        // Unbounded, so a slow watcher misses nothing and never slows the connection down: an endpoint has at most a few events per
        // connection, and the reconnect delay bounds how often connections come and go.
        var events = Channel.CreateUnbounded<SshConnectionEvent>(new UnboundedChannelOptions { SingleReader = true });
        lock (entry.Watchers)
        {
            entry.Watchers.Add(events);
            if (_disposed)
            {
                events.Writer.TryComplete();
            }
            else if (entry.Current is { } current)
            {
                // The current state first, so a watcher that starts late still knows where things stand. A connection that has ended
                // but is not reported yet is left to the report, which is on its way and reaches this watcher too.
                if (current.Reported)
                {
                    events.Writer.TryWrite(new SshConnectionEvent(name, SshConnectionEventKind.Disconnected, current.Client, entry.LastDropError,
                        _time.GetUtcNow()));
                }
                else if (current.Client.IsConnected)
                {
                    events.Writer.TryWrite(new SshConnectionEvent(name, SshConnectionEventKind.Connected, current.Client, null, _time.GetUtcNow()));
                }
            }
        }

        try
        {
            while (await events.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (events.Reader.TryRead(out var change))
                {
                    yield return change;
                }
            }
        }
        finally
        {
            lock (entry.Watchers)
            {
                entry.Watchers.Remove(events);
            }
        }
    }

    /// <summary>A new shared connection: tells the watchers, and watches the connection for its end.</summary>
    private void ReportConnected(string name, Entry entry, SshClient client)
    {
        var tracked = new Tracked(client);
        lock (entry.Watchers)
        {
            var kind = entry.EverConnected ? SshConnectionEventKind.Reconnected : SshConnectionEventKind.Connected;
            var error = entry.EverConnected ? entry.LastDropError : null;
            entry.EverConnected = true;
            entry.Current = tracked;
            Publish(entry, new SshConnectionEvent(name, kind, client, error, _time.GetUtcNow()));
        }

        // The callback runs on the thread that ends the connection (its receive loop, often): it only queues the event. Registered
        // after the lock is released, as a connection that has already ended runs it at once, here.
        client.ConnectionClosed.UnsafeRegister(static state =>
        {
            var (provider, name, entry, client) = ((SshConnectionProvider, string, Entry, SshClient))state!;
            provider.ReportDisconnected(name, entry, client);
        }, (this, name, entry, client));
    }

    /// <summary>The shared connection <paramref name="client"/> ended: tells the watchers, once, unless the provider is closing it.</summary>
    private void ReportDisconnected(string name, Entry entry, SshClient client)
    {
        lock (entry.Watchers)
        {
            if (_disposed || entry.Current is not { Reported: false } current || !ReferenceEquals(current.Client, client))
            {
                return;
            }

            current.Reported = true;
            entry.LastDropError = client.ConnectionError;
            Publish(entry, new SshConnectionEvent(name, SshConnectionEventKind.Disconnected, client, entry.LastDropError, _time.GetUtcNow()));
        }
    }

    private static void Publish(Entry entry, SshConnectionEvent change)
    {
        foreach (var watcher in entry.Watchers)
        {
            watcher.Writer.TryWrite(change);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        foreach (var entry in _entries.Values)
        {
            await entry.Gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (entry.Client is { } client)
                {
                    entry.Client = null;
                    await client.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                entry.Gate.Release();
            }

            lock (entry.Watchers)
            {
                foreach (var watcher in entry.Watchers)
                {
                    watcher.Writer.TryComplete();
                }
            }
        }
    }

    private sealed class Entry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public volatile SshClient? Client;

        public Exception? LastError { get; set; }

        public DateTimeOffset RetryAt { get; set; }

        public TimeSpan Delay { get; set; }

        // The fields below are guarded by Watchers' lock.

        /// <summary>The watchers' queues.</summary>
        public List<Channel<SshConnectionEvent>> Watchers { get; } = [];

        /// <summary>The latest shared connection, and whether its end has been reported.</summary>
        public Tracked? Current { get; set; }

        /// <summary>Whether a connection was ever opened, so the next one is a reconnection.</summary>
        public bool EverConnected { get; set; }

        /// <summary>Why the last connection ended, for the reconnection's event.</summary>
        public Exception? LastDropError { get; set; }
    }

    private sealed class Tracked(SshClient client)
    {
        public SshClient Client { get; } = client;

        public bool Reported { get; set; }
    }
}
