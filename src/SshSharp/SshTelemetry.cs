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
/// Activities: <c>SshSharp.Connect</c> (tags <c>ssh.kex</c>, <c>ssh.cipher</c>, <c>ssh.host_key.type</c>) and <c>SshSharp.Command</c> (tag
/// <c>ssh.command.exit_status</c>). Instruments: <c>sshsharp.connections</c>, <c>sshsharp.connect.duration</c> (s), <c>sshsharp.bytes.sent</c>,
/// <c>sshsharp.bytes.received</c>, <c>sshsharp.key_exchanges</c>, <c>sshsharp.channels</c>, <c>sshsharp.commands</c>.
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
}