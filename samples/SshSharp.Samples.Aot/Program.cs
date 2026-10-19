using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using SshSharp;

// A command-line tool published with Native AOT: one self-contained executable with no .NET runtime to install, that starts in
// milliseconds. It runs a command on several servers at once and prints one JSON line per server:
//
//   dotnet publish samples/SshSharp.Samples.Aot -c Release -o out
//   out/sshrun "uptime" web1 web2 user@db.example.com
//
// Each destination is an ~/.ssh/config alias, user@host or ssh://user@host:port, connected through ssh_config (keys, the agent,
// known_hosts, ProxyJump). Nothing prompts: no prompt callbacks are given, so (with ssh's default StrictHostKeyChecking) an unknown host key fails that destination, and an
// encrypted key file is skipped (the agent can hold it instead).
//
// What AOT needs from an application: no reflection-based serialization (the JSON here is source-generated, see SampleJson below),
// and trim and AOT warnings treated as errors so that the publish fails rather than the program at run time. SshSharp itself is
// AOT-compatible and needs nothing else.
if (args.Length < 2)
{
    Console.Error.WriteLine("usage: sshrun <command> <destination>...");
    return 2;
}

var command = args[0];
using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(5));
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};

var results = await Task.WhenAll(args.Skip(1).Select(destination => RunAsync(destination, command, stop.Token)));
foreach (var result in results)
{
    Console.WriteLine(JsonSerializer.Serialize(result, SampleJson.Default.RunResult));
}

return results.All(r => r.ExitStatus == 0) ? 0 : 1;

static async Task<RunResult> RunAsync(string destination, string command, CancellationToken cancellationToken)
{
    var started = Stopwatch.GetTimestamp();
    try
    {
        await using var client = await SshClient.ConnectAsync(destination, new SshConfigConnectOptions
        {
            // A tool that runs unattended: a bound on each connection, whatever ssh_config says.
            ConnectTimeout = TimeSpan.FromSeconds(20),
        }, cancellationToken);
        var result = await client.RunCommandAsync(command, cancellationToken);
        return new RunResult(destination, result.ExitStatus, result.StandardOutputText, result.StandardErrorText, null,
            Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    }
    catch (SshException ex)
    {
        return new RunResult(destination, null, null, null, $"{ex.Reason}: {ex.Message}", Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    }
}

internal sealed record RunResult(string Destination, int? ExitStatus, string? Output, string? Error, string? Failure, double Milliseconds);

/// <summary>Serialization code generated at build time, so no reflection is needed at run time (and none is trimmed away).</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RunResult))]
internal sealed partial class SampleJson : JsonSerializerContext;
