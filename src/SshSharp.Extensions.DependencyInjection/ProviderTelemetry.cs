using System.Diagnostics.Metrics;
using System.Reflection;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>
/// This package's instruments. Their meter has the name of SshSharp's (<see cref="SshTelemetry.SourceName"/>), so whatever collects
/// SshSharp's metrics collects these too. Endpoint names are not recorded: they are the application's, and are often host names.
/// </summary>
internal static class ProviderTelemetry
{
    private static readonly string Version = typeof(ProviderTelemetry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    private static readonly Meter Instruments = new(SshTelemetry.SourceName, Version);

    private static readonly Counter<long> Reconnects = Instruments.CreateCounter<long>(
        "sshsharp.connection_provider.reconnects", "{reconnect}",
        "Attempts to replace a shared connection that ended, tagged by result (success, error).");

    private static readonly KeyValuePair<string, object?> Success = new("result", "success");
    private static readonly KeyValuePair<string, object?> Error = new("result", "error");

    public static void Reconnected() => Reconnects.Add(1, Success);

    /// <summary>A failed reconnection, with OpenTelemetry's <c>error.type</c> as SshSharp's own instruments give it.</summary>
    public static void ReconnectFailed(Exception exception)
    {
        if (Reconnects.Enabled)
        {
            var errorType = exception is SshException ssh ? ssh.Reason.ToString() : exception.GetType().FullName ?? "Exception";
            Reconnects.Add(1, Error, new KeyValuePair<string, object?>("error.type", errorType));
        }
    }
}
