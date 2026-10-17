# Tutorial: a server check tool

This tutorial builds a small console program that connects to a server, asks about an unknown host key the way `ssh` does, runs a
few checks, uploads a report and handles every failure cleanly. Each step adds one idea; the code is taken from a project that is
compiled with the library, so it matches the current API.

You need the .NET SDK (8 or 10) and an SSH server you can log in to with a key in your agent or a password.

## 1. Create the project

```
dotnet new console -n ServerCheck
cd ServerCheck
dotnet add package SshSharp
```

## 2. Connect

Replace `Program.cs`. The keys come from the SSH agent when one is running, and a password from the `SSH_PASSWORD` environment
variable when it is set; the client tries the keys first, as `ssh` does.

```csharp
using SshSharp;
using SshSharp.Config;
```

[!code-csharp[](snippets/Tutorial.cs#step1)]

Run it with `dotnet run -- example.com user`. With `StrictHostKeyChecking.Yes`, a server that is not in `~/.ssh/known_hosts` is
refused with an `SshHostKeyException`: the program will not talk to a server it cannot identify.

## 3. Ask about unknown hosts

`ssh` asks whether to trust a host it has not seen. `KnownHostsVerifier` does the same with the `Ask` policy and an `AskHostKey`
callback; a key you accept is added to `known_hosts`, so the next run does not ask. Use this verifier in place of
`KnownHostsVerifier.ForCurrentUser(...)` from step 2:

[!code-csharp[](snippets/Tutorial.cs#step2)]

> [!WARNING]
> Compare the fingerprint with one you got another way (the server's console, its provisioning output) before you answer `yes`.
> A changed key is never asked about: it is rejected, as `ssh` rejects it.

## 4. Run the checks

`RunCommandAsync` collects a command's output and exit status. Check the exit status: a command that fails on the server is not an
exception, it is a result.

[!code-csharp[](snippets/Tutorial.cs#step3)]

## 5. Upload a report

SFTP runs over the same connection. `Overwrite = false` makes an existing file an error instead of replacing it.

```csharp
using SshSharp.Sftp;
```

[!code-csharp[](snippets/Tutorial.cs#step4)]

The `reports` directory must exist on the server; `sftp.CreateDirectoryAsync("reports")` makes it.

## 6. Time limits and failures

Every network operation takes a `CancellationToken`. One token with a time limit bounds the whole run, and Ctrl-C cancels it.
Each kind of failure gets its own message:

[!code-csharp[](snippets/Tutorial.cs#step5)]

## Next steps

- Connect by `ssh_config` alias instead of host and user: [Use ssh_config and known_hosts](how-to/ssh-config-and-known-hosts.md).
- Check many servers at once: [the fleet health check scenario](scenarios/fleet-health-check.md).
- Stream output that does not fit in memory: [Stream large output](how-to/stream-output.md).
