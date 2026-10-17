using System.Collections.Concurrent;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// The shared connection per endpoint: kept while it is up, opened again when it drops, with a growing wait after failures so a down
/// server is not hammered. Owns its clients; disposing it (with the container) disposes them.
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
        }
    }

    private sealed class Entry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public volatile SshClient? Client;

        public Exception? LastError { get; set; }

        public DateTimeOffset RetryAt { get; set; }

        public TimeSpan Delay { get; set; }
    }
}
