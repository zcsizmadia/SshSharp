# Native AOT

All four SshSharp packages are trimming- and Native AOT-compatible (`IsAotCompatible`): no reflection, no runtime code
generation, and no trim or AOT warnings. An application that uses them can be published as a single self-contained native
executable, with fast startup and no .NET runtime to install.

## When to use

- Command-line tools that should start instantly and ship as one file.
- Small containers and constrained hosts.

## Publish

```xml
<PropertyGroup>
  <OutputType>Exe</OutputType>
  <TargetFramework>net10.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <InvariantGlobalization>true</InvariantGlobalization> <!-- optional: smaller, if you need no culture data -->
</PropertyGroup>
```

```
dotnet publish -c Release -r linux-x64
```

The code needs nothing AOT-specific:

[!code-csharp[](../snippets/Platform.cs#aot)]

## How it is verified

CI publishes a smoke-test program (`tests/SshSharp.AotSmoke`) with Native AOT, with trim and AOT warnings as errors, and runs it
against a real OpenSSH server: configuration parsing, connecting, and the main features, all from the AOT-compiled binary.

## Notes and pitfalls

- **Your own code** must be AOT-compatible too: `System.Text.Json` with source generation, no `Assembly.Load`, and so on. The
  publish warnings tell you where.
- **Native AOT needs the platform toolchain** (on Windows, the C++ build tools; on Linux, clang). Cross-OS publishing is not
  supported by .NET; build on the target OS (or in a container of it).
- **Size.** The trimmer removes code you do not use; SCP, for example, is not carried by an application that never calls it.

## See also

- [Microsoft's Native AOT documentation](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)
- [Design notes](../design.md)
