using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/logging-and-diagnostics.md and docs/reference/errors.md.</summary>
internal static class Diagnostics
{
    public static async Task LoggingAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <logging>
        using var loggerFactory = LoggerFactory.Create(builder => builder
            .AddSimpleConsole(o => o.TimestampFormat = "HH:mm:ss ")
            .SetMinimumLevel(LogLevel.Debug));

        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            Password = Environment.GetEnvironmentVariable("DEPLOY_PASSWORD"),
            HostKeyVerifier = verifier,
            Logger = loggerFactory.CreateLogger("SshSharp"),   // never logs passwords, keys, command text or user names
        }, cancellationToken);
        // </logging>
    }

    public static async Task InspectAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <inspect>
        Console.WriteLine($"server:    {client.ServerIdentification}");                      // SSH-2.0-OpenSSH_9.9 ...
        Console.WriteLine($"host key:  {client.HostKey.KeyType} {client.HostKey.Fingerprint}");
        Console.WriteLine($"kex:       {client.Algorithms.KeyExchange} (post-quantum: {client.Algorithms.IsPostQuantum})");
        Console.WriteLine($"cipher:    {client.Algorithms.EncryptionClientToServer}");
        Console.WriteLine($"strict kex: {client.Algorithms.StrictKeyExchange}");
        Console.WriteLine($"round trip: {(await client.PingAsync(cancellationToken)).TotalMilliseconds:F1} ms");
        Console.WriteLine($"client:    {SshSharpInfo.SoftwareVersion}");                       // SshSharp_1.0.0
        // </inspect>
    }

    public static async Task ErrorsAsync(CancellationToken cancellationToken)
    {
        // <errors>
        try
        {
            await using var client = await SshClient.ConnectAsync("prod-db", cancellationToken: cancellationToken);
            (await client.RunCommandAsync("systemctl reload nginx", cancellationToken)).EnsureSuccess();
        }
        catch (SshCommandException ex)
        {
            // Before SshException: it is one. The message names the exit status or signal; stderr's end is separate.
            Console.Error.WriteLine($"{ex.Message}\n{ex.StandardErrorText.Trim()}");
        }
        catch (SshHostKeyException ex)
        {
            Console.Error.WriteLine($"Host key not trusted ({ex.HostKey?.Fingerprint}): {ex.Message}");
        }
        catch (SshAuthenticationException ex)
        {
            Console.Error.WriteLine($"Login failed; the server accepts: {string.Join(", ", ex.AllowedMethods)}");
        }
        catch (SshException ex) when (ex.Reason is SshFailureReason.ConnectFailed or SshFailureReason.Timeout)
        {
            Console.Error.WriteLine($"Unreachable: {ex.Message}");
        }
        catch (SshException ex)
        {
            Console.Error.WriteLine($"SSH failed ({ex.Reason}): {ex.Message}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.Error.WriteLine("Cancelled.");
        }
        // </errors>
    }

    public static IDisposable ListenToTraces()
    {
        // <activity-listener>
        // Without OpenTelemetry: the connect and command spans, straight from the ActivitySource.
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SshTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => Console.WriteLine(
                $"{activity.OperationName} {activity.Duration.TotalMilliseconds:F0} ms {activity.Status} " +
                string.Join(' ', activity.Tags.Select(t => $"{t.Key}={t.Value}"))),
        };
        ActivitySource.AddActivityListener(listener);
        // </activity-listener>
        return listener;
    }

    public static IDisposable ListenToMetrics()
    {
        // <meter-listener>
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == SshTelemetry.SourceName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Console.WriteLine($"{instrument.Name} {value:+#;-#;0}"));
        listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Console.WriteLine($"{instrument.Name} {value:F3}"));
        listener.Start();
        // </meter-listener>
        return listener;
    }
}
