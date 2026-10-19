# Logging and diagnostics

SshSharp reports what it does through the standard .NET channels: `ILogger` for logs, an `ActivitySource` for traces and a `Meter`
for metrics, all named `SshSharp`. None of them ever contain passwords, private keys, command text, user names or host names.

## When to use

- A connection fails and the exception message is not enough: log at `Debug`.
- You run SshSharp in a service: export traces and metrics with OpenTelemetry.
- You need to know what a server negotiated (for an audit, or to find hosts without post-quantum key exchange).

## Log

[!code-csharp[](../snippets/Diagnostics.cs#logging)]

At `Information`: connected (algorithms and host key fingerprint), authenticated (which method), identity files and agent keys that
were skipped and why, host keys recorded by `UpdateHostKeys`, and connections without post-quantum key exchange. At `Debug`: key
exchanges and rekeys, channels and sessions, each authentication attempt.

With dependency injection, clients log through the container's `ILoggerFactory` automatically, under the category `SshSharp`.

## Inspect a connection

[!code-csharp[](../snippets/Diagnostics.cs#inspect)]

The client also has the connection's endpoints, when it was made, its session id and how many bytes it has carried:

[!code-csharp[](../snippets/ConnectionTuning.cs#inspect-connection)]

These are for your own reports: SshSharp never logs or records the endpoints itself. See
[Tune and inspect a connection](tune-and-inspect-connections.md#inspect-a-connection).

## Trace and measure with OpenTelemetry

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddSource(SshTelemetry.SourceName))
    .WithMetrics(metrics => metrics.AddMeter(SshTelemetry.SourceName));
```

The `SshSharp.Connect` span covers connecting, key exchange and authentication (each `ProxyJump` hop is a span of its own inside
it), and `SshSharp.Command` covers each `RunCommandAsync`. The metrics count connections, channels, commands, bytes and key
exchanges, and time connecting. [Errors and diagnostics](../diagnostics.md#tracing-and-metrics) lists every tag and instrument.

## Listen without OpenTelemetry

The BCL's listeners see the same data, for a quick look in a console tool or a test:

[!code-csharp[](../snippets/Diagnostics.cs#activity-listener)]

[!code-csharp[](../snippets/Diagnostics.cs#meter-listener)]

## Notes and pitfalls

- **Host names are not recorded**, by design (see the [threat model](../threat-model.md)): add `server.address` to a parent span of
  your own when you want it.
- **Nothing is recorded unless something listens**, so the instrumentation costs nothing when unused.
- **Exception messages** can contain what the server said (an SFTP error, a refused command). Treat them as server-controlled
  text before showing them to end users.
- **Comparing with `ssh -vvv`.** The `Debug` log shows the same stages (key exchange, host key, authentication methods), so it is
  the place to look when `ssh` connects and SshSharp does not.

## See also

- [Errors and diagnostics](../diagnostics.md) (in-depth: every tag and instrument)
- [Troubleshooting](../reference/troubleshooting.md)
- <xref:SshSharp.SshTelemetry> in the API reference
