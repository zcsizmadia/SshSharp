using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;

namespace SshSharp;

/// <summary>
/// The names SshSharp publishes diagnostics under. Subscribe to <see cref="SourceName"/> for traces (<see cref="ActivitySource"/>) and
/// metrics (<see cref="Meter"/>), for example with OpenTelemetry: <c>.AddSource(SshTelemetry.SourceName)</c> and <c>.AddMeter(SshTelemetry.SourceName)</c>.
/// Nothing is recorded unless something listens, and no secrets (passwords, keys, command text) are ever recorded.
/// </summary>
/// <remarks>
/// Activities: <c>SshSharp.Connect</c> (a client span; tags <c>network.protocol.name</c>, <c>network.protocol.version</c>,
/// <c>network.transport</c>, <c>server.port</c>, <c>ssh.kex</c>, <c>ssh.kex.post_quantum</c>, <c>ssh.cipher</c>, <c>ssh.host_key.type</c>, and
/// <c>error.type</c> on failure), <c>SshSharp.Authenticate</c> inside it (<c>ssh.auth.method</c>, <c>ssh.auth.attempts</c>,
/// <c>error.type</c>), <c>SshSharp.Command</c> (<c>ssh.command.exit_status</c>, <c>error.type</c>), and the SFTP transfers
/// <c>SshSharp.Sftp.Upload</c> and <c>SshSharp.Sftp.Download</c> (<c>ssh.sftp.bytes</c>, <c>error.type</c>) and
/// <c>SshSharp.Sftp.UploadDirectory</c> and <c>SshSharp.Sftp.DownloadDirectory</c> (also <c>ssh.sftp.files</c> and
/// <c>ssh.sftp.directories</c>). Instruments: <c>sshsharp.connections</c>, <c>sshsharp.connect.duration</c> (s; successful and failed
/// connects, the failed ones tagged <c>error.type</c>), <c>sshsharp.bytes.sent</c>, <c>sshsharp.bytes.received</c>,
/// <c>sshsharp.key_exchanges</c>, <c>sshsharp.channels</c>, <c>sshsharp.commands</c> (tagged <c>result</c> and, for errors,
/// <c>error.type</c>), <c>sshsharp.sftp.bytes</c> (By, tagged <c>ssh.sftp.direction</c>), <c>sshsharp.forwarding.connections</c> (tagged
/// <c>ssh.forwarding.type</c> and <c>result</c>), <c>sshsharp.forwarding.active</c> (tagged <c>ssh.forwarding.type</c>) and
/// <c>sshsharp.keep_alive.round_trip_time</c> (s); SshSharp.Extensions.DependencyInjection adds
/// <c>sshsharp.connection_provider.reconnects</c> under the same meter name. No host names, user names or paths are recorded.
/// </remarks>
public static class SshTelemetry
{
    /// <summary>The name of both the <see cref="ActivitySource"/> and the <see cref="Meter"/>.</summary>
    public const string SourceName = "SshSharp";

    private static readonly string Version = typeof(SshTelemetry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    internal static readonly ActivitySource Activities = new(SourceName, Version);

    private static readonly Meter Instruments = new(SourceName, Version);

    internal static readonly UpDownCounter<int> Connections = Instruments.CreateUpDownCounter<int>(
        "sshsharp.connections", "{connection}", "Currently open SSH connections.");

    internal static readonly Histogram<double> ConnectDuration = Instruments.CreateHistogram<double>(
        "sshsharp.connect.duration", "s", "Time to connect, key-exchange and authenticate.");

    internal static readonly Counter<long> BytesSent = Instruments.CreateCounter<long>(
        "sshsharp.bytes.sent", "By", "SSH message payload bytes sent (before compression, encryption and padding).");

    internal static readonly Counter<long> BytesReceived = Instruments.CreateCounter<long>(
        "sshsharp.bytes.received", "By", "SSH message payload bytes received (after decryption and decompression).");

    internal static readonly Counter<int> KeyExchanges = Instruments.CreateCounter<int>(
        "sshsharp.key_exchanges", "{exchange}", "Completed key exchanges, including the first one on each connection.");

    internal static readonly UpDownCounter<int> Channels = Instruments.CreateUpDownCounter<int>(
        "sshsharp.channels", "{channel}", "Currently open channels.");

    internal static readonly Counter<long> Commands = Instruments.CreateCounter<long>(
        "sshsharp.commands", "{command}", "Remote commands run, tagged by outcome (success, failure, error).");

    internal static readonly Counter<long> SftpBytes = Instruments.CreateCounter<long>(
        "sshsharp.sftp.bytes", "By", "File data moved by SFTP transfers, tagged by direction (upload, download).");

    internal static readonly Counter<long> ForwardedConnections = Instruments.CreateCounter<long>(
        "sshsharp.forwarding.connections", "{connection}", "Forwarded connections, tagged by forwarding type and result (opened, failed).");

    internal static readonly UpDownCounter<int> ActiveForwardedConnections = Instruments.CreateUpDownCounter<int>(
        "sshsharp.forwarding.active", "{connection}", "Currently open forwarded connections, tagged by forwarding type.");

    internal static readonly Histogram<double> KeepAliveRoundTrip = Instruments.CreateHistogram<double>(
        "sshsharp.keep_alive.round_trip_time", "s", "Time from a keep-alive probe to the server's answer.");

    // Made once: the SFTP byte counter is added to for every read and write of a transfer.
    internal static readonly KeyValuePair<string, object?> Upload = new("ssh.sftp.direction", "upload");
    internal static readonly KeyValuePair<string, object?> Download = new("ssh.sftp.direction", "download");

    /// <summary>
    /// Starts the span of an SFTP transfer (<c>SshSharp.Sftp.Upload</c>, <c>Download</c>, <c>UploadDirectory</c> or
    /// <c>DownloadDirectory</c>). Paths are never recorded: they can hold user names, and are the application's to add.
    /// </summary>
    internal static Activity? StartTransfer(string name) => Activities.StartActivity(name);

    /// <summary>
    /// Starts the connect span as a client span with OpenTelemetry's general attributes (<c>network.protocol.name</c>, and when this
    /// library makes the TCP connection itself, <c>network.transport</c> and <c>server.port</c>). <c>server.address</c> is left out: host
    /// names are never recorded by this library (see the threat model); add it in an <see cref="ActivityListener"/> or a parent span.
    /// </summary>
    internal static Activity? StartConnect(int? tcpPort)
    {
        var activity = Activities.StartActivity("SshSharp.Connect", ActivityKind.Client);
        if (activity is not null)
        {
            activity.SetTag("network.protocol.name", "ssh");
            activity.SetTag("network.protocol.version", "2.0");
            if (tcpPort is { } port)
            {
                activity.SetTag("network.transport", "tcp");
                activity.SetTag("server.port", port);
            }
        }

        return activity;
    }

    /// <summary>
    /// Marks a span as failed with OpenTelemetry's <c>error.type</c>: an <see cref="SshException"/>'s <see cref="SshException.Reason"/>
    /// (<c>AuthenticationFailed</c>, <c>Timeout</c>, ...), otherwise the exception's type name. Returns the value, for metrics.
    /// </summary>
    internal static string Failed(Activity? activity, Exception exception)
    {
        var errorType = exception is SshException ssh ? ssh.Reason.ToString() : exception.GetType().FullName ?? "Exception";
        activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name); // as before error.type existed
        activity?.SetTag("error.type", errorType);
        return errorType;
    }
}

/// <summary>
/// One connect attempt's span and duration, from before the network connection (TCP, proxy, ProxyCommand or ProxyJump) to the end of
/// authentication; the outcome is recorded once, whichever step ends it.
/// </summary>
internal sealed class ConnectMeasurement(int? tcpPort) : IDisposable
{
    private readonly long _started = Stopwatch.GetTimestamp();
    private bool _recorded;

    public Activity? Activity { get; } = SshTelemetry.StartConnect(tcpPort);

    public void Succeeded(bool postQuantum) => Record(new KeyValuePair<string, object?>("ssh.kex.post_quantum", postQuantum));

    public void Failed(Exception exception)
    {
        if (!_recorded)
        {
            Record(new KeyValuePair<string, object?>("error.type", SshTelemetry.Failed(Activity, exception)));
        }
    }

    private void Record(KeyValuePair<string, object?> tag)
    {
        if (!_recorded)
        {
            _recorded = true;
            SshTelemetry.ConnectDuration.Record(Stopwatch.GetElapsedTime(_started).TotalSeconds, tag);
        }
    }

    public void Dispose() => Activity?.Dispose();
}

/// <summary>
/// One forwarded connection for the forwarding instruments: counted as opened (and open until disposed) once it reaches its
/// destination, or as failed when it is disposed without having got there, unless its forwarding is stopping. Only the forwarding's
/// type is recorded, never an address, port or socket path.
/// </summary>
internal sealed class ForwardedConnectionMeasurement(KeyValuePair<string, object?> type, CancellationToken stopping) : IDisposable
{
    internal static readonly KeyValuePair<string, object?> Local = new("ssh.forwarding.type", "local");
    internal static readonly KeyValuePair<string, object?> Dynamic = new("ssh.forwarding.type", "dynamic");
    internal static readonly KeyValuePair<string, object?> Remote = new("ssh.forwarding.type", "remote");
    internal static readonly KeyValuePair<string, object?> RemoteDynamic = new("ssh.forwarding.type", "remote_dynamic");

    private static readonly KeyValuePair<string, object?> OpenedResult = new("result", "opened");
    private static readonly KeyValuePair<string, object?> FailedResult = new("result", "failed");

    private bool _opened;
    private bool _done;

    /// <summary>The connection reached its destination (or its handler): it counts as open until this is disposed.</summary>
    public void Opened()
    {
        if (!_done && !_opened)
        {
            _opened = true;
            SshTelemetry.ForwardedConnections.Add(1, type, OpenedResult);
            SshTelemetry.ActiveForwardedConnections.Add(1, type);
        }
    }

    /// <summary>A connection refused before it was taken on (a limit was reached).</summary>
    public static void Refused(KeyValuePair<string, object?> type) => SshTelemetry.ForwardedConnections.Add(1, type, FailedResult);

    public void Dispose()
    {
        if (_done)
        {
            return;
        }

        _done = true;
        if (_opened)
        {
            SshTelemetry.ActiveForwardedConnections.Add(-1, type);
        }
        else if (!stopping.IsCancellationRequested)
        {
            Refused(type);
        }
    }
}