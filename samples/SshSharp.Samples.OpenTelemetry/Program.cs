using System.Diagnostics;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using SshSharp;

// Exports SshSharp's traces and metrics with OpenTelemetry, over OTLP:
//
//   dotnet run --project samples/SshSharp.Samples.OpenTelemetry -- <destination> [command]
//
// <destination> is an ~/.ssh/config alias, user@host or ssh://user@host:port, connected through ssh_config (keys, the agent,
// known_hosts). A password, if the server asks for one, comes from SSHSHARP_PASSWORD. The exporter follows the standard OTEL_*
// environment variables: OTEL_EXPORTER_OTLP_ENDPOINT (default http://localhost:4317, for example a local collector, Jaeger or the
// .NET Aspire dashboard) and OTEL_EXPORTER_OTLP_PROTOCOL.
if (args.Length is < 1 or > 2)
{
    Console.Error.WriteLine("usage: <destination> [command]");
    return 2;
}

var destination = args[0];
var command = args.Length == 2 ? args[1] : "uname -a";

// The application's own spans, as the parent of SshSharp's.
using var source = new ActivitySource("SshSharp.Samples.OpenTelemetry");
var resource = ResourceBuilder.CreateDefault().AddService("sshsharp-otel-sample");

// SshSharp's ActivitySource and Meter are both named SshTelemetry.SourceName ("SshSharp"). Nothing is recorded unless a listener
// such as these providers subscribes to them.
using var tracing = Sdk.CreateTracerProviderBuilder()
    .SetResourceBuilder(resource)
    .AddSource(source.Name)
    .AddSource(SshTelemetry.SourceName)
    .AddOtlpExporter()
    .Build();
using var metrics = Sdk.CreateMeterProviderBuilder()
    .SetResourceBuilder(resource)
    .AddMeter(SshTelemetry.SourceName)
    .AddOtlpExporter()
    .Build();

using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(1));
using (var job = source.StartActivity("check-server"))
{
    // SshSharp never records host names (see docs/diagnostics.md). Add the destination to your own span if your policy allows it;
    // this sample records only that a destination was given.
    job?.SetTag("app.destination.given", true);
    try
    {
        // SshSharp.Connect covers the TCP connection, key exchange and authentication; SshSharp.Command covers the command.
        await using var client = await SshClient.ConnectAsync(destination, new SshConfigConnectOptions
        {
            Password = Environment.GetEnvironmentVariable("SSHSHARP_PASSWORD"),
        }, stop.Token);

        var result = await client.RunCommandAsync(command, stop.Token);
        Console.Write(result.StandardOutputText);
        job?.SetTag("app.exit_status", result.ExitStatus);
    }
    catch (SshException ex)
    {
        job?.SetStatus(ActivityStatusCode.Error, ex.Reason.ToString());
        Console.Error.WriteLine($"{ex.Reason}: {ex.Message}");
        return 1;
    }
}

// Disposing the providers (at the end of Main) flushes what is still buffered, metrics included.
Console.WriteLine($"Exported traces and metrics to {Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT") ?? "http://localhost:4317"}.");
return 0;
