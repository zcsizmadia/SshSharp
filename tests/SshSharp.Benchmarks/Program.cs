using BenchmarkDotNet.Running;

// Run with: dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --filter "*"
// Add --job short for a quick pass. Results (including allocations per operation) are written to BenchmarkDotNet.Artifacts.
// Constant-time check of the managed secret-key code: ... -- --timing [samples] (see TimingLeakCheck).
if (args.Length > 0 && args[0] == "--timing")
{
    TimingLeakCheck.Run(args.Length > 1 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 20_000);
    return;
}

// Peak memory streaming a large output through one library: ... -- --peak sshsharp|sshnet [MiB] (see PeakMemory).
if (args.Length > 1 && args[0] == "--peak")
{
    await SshSharp.Benchmarks.PeakMemory.RunAsync(args[1], args.Length > 2 ? int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : 1024);
    return;
}

if (args.Length > 0 && args[0] == "--connect-profile")
{
    await SshSharp.Benchmarks.ConnectProfile.RunAsync();
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

/// <summary>Entry point holder for the benchmark runner.</summary>
internal static partial class Program;
