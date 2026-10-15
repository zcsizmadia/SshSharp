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
/// <c>error.type</c> on failure) and <c>SshSharp.Command</c> (<c>ssh.command.exit_status</c>, <c>error.type</c>). Instruments:
/// <c>sshsharp.connections</c>, <c>sshsharp.connect.duration</c> (s; successful and failed connects, the failed ones tagged
/// <c>error.type</c>), <c>sshsharp.bytes.sent</c>, <c>sshsharp.bytes.received</c>, <c>sshsharp.key_exchanges</c>, <c>sshsharp.channels</c>,
/// <c>sshsharp.commands</c> (tagged <c>result</c> and, for errors, <c>error.type</c>).
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
        "sshsharp.bytes.sent", "By", "SSH message payload bytes sent (before encryption and padding).");

    internal static readonly Counter<long> BytesReceived = Instruments.CreateCounter<long>(
        "sshsharp.bytes.received", "By", "SSH message payload bytes received.");

    internal static readonly Counter<int> KeyExchanges = Instruments.CreateCounter<int>(
        "sshsharp.key_exchanges", "{exchange}", "Completed key exchanges, including the first one on each connection.");

    internal static readonly UpDownCounter<int> Channels = Instruments.CreateUpDownCounter<int>(
        "sshsharp.channels", "{channel}", "Currently open channels.");

    internal static readonly Counter<long> Commands = Instruments.CreateCounter<long>(
        "sshsharp.commands", "{command}", "Remote commands run, tagged by outcome (success, failure, error).");

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