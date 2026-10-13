using BenchmarkDotNet.Running;

// Run with: dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --filter "*"
// Add --job short for a quick pass. Results (including allocations per operation) are written to BenchmarkDotNet.Artifacts.
// Constant-time check of the managed secret-key code: ... -- --timing [samples] (see TimingLeakCheck).
if (args.Length > 0 && args[0] == "--timing")
{
    TimingLeakCheck.Run(args.Length > 1 ? int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture) : 20_000);
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

/// <summary>Entry point holder for the benchmark runner.</summary>
internal static partial class Program;
