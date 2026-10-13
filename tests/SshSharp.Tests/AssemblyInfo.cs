using TUnit.Core;

// A hung test must fail by name instead of stalling CI; the slowest legitimate tests (4096-bit safe prime checks) take well under a minute.
[assembly: Timeout(180_000)]
