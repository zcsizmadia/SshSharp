using BenchmarkDotNet.Running;

// Run with: dotnet run -c Release --project tests/SshSharp.Benchmarks -f net10.0 -- --filter "*"
// Add --job short for a quick pass. Results (including allocations per operation) are written to BenchmarkDotNet.Artifacts.
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

/// <summary>Entry point holder for the benchmark runner.</summary>
internal static partial class Program;