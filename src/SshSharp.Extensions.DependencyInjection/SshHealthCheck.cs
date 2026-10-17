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
            // Nothing from the server in the text: health endpoints are often reachable without authentication.
            return HealthCheckResult.Healthy(
                string.Create(CultureInfo.InvariantCulture, $"Connected; ping {roundTrip.TotalMilliseconds:F0} ms."),
                new Dictionary<string, object> { ["roundTripMilliseconds"] = roundTrip.TotalMilliseconds });
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // The error's type only (a server's disconnect text could be in its message); the exception itself is attached for logging.
            return new HealthCheckResult(context.Registration.FailureStatus, $"SSH endpoint '{name}' is unavailable ({ex.GetType().Name}).", ex);
        }
    }
}
