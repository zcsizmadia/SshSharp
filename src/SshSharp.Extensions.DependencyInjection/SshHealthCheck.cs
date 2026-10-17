using System.Globalization;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace SshSharp.Extensions.DependencyInjection;

/// <summary>Pings the shared connection of one endpoint (connecting it first if it is not up).</summary>
internal sealed class SshHealthCheck(string name, ISshConnectionProvider connections) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var client = await connections.GetClientAsync(name, cancellationToken).ConfigureAwait(false);
            var roundTrip = await client.PingAsync(cancellationToken).ConfigureAwait(false);
            return HealthCheckResult.Healthy(
                string.Create(CultureInfo.InvariantCulture, $"Connected to {client.ServerIdentification}; ping {roundTrip.TotalMilliseconds:F0} ms."),
                new Dictionary<string, object> { ["roundTripMilliseconds"] = roundTrip.TotalMilliseconds });
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return new HealthCheckResult(context.Registration.FailureStatus, $"SSH endpoint '{name}': {ex.Message}", ex);
        }
    }
}
