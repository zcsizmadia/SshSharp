# Samples

Runnable projects, built with the solution in CI, so they keep compiling as the API changes.

| Sample | Shows |
|---|---|
| [SshSharp.Samples](SshSharp.Samples) | An `ssh`-like command-line tool, connecting through `~/.ssh/config` (aliases, ProxyJump, keys and the agent): commands, a streamed `tail`, a shell, port forwarding, a SOCKS proxy, SCP, SFTP transfers (times and permissions kept, progress, parallel ranges, resuming), a remote tree through `IFileSystem` (`SshSharp.IO.Abstractions`), and logging in with a Windows CNG key through a login-only `SshKeySigner` |
| [SshSharp.Samples.AspNetCore](SshSharp.Samples.AspNetCore) | ASP.NET Core with `SshSharp.Extensions.DependencyInjection`: endpoints on the shared connection, a file streamed through SFTP, static files from the server (`SshSharp.FileProviders`), and a health check |
| [SshSharp.Samples.Worker](SshSharp.Samples.Worker) | A worker service that follows a remote log file across dropped connections |
| [SshSharp.Samples.OpenTelemetry](SshSharp.Samples.OpenTelemetry) | SshSharp's traces (`SshSharp.Connect`, `SshSharp.Command`) and metrics exported with OpenTelemetry over OTLP, under a span of the application's own |
| [SshSharp.Samples.Terminal](SshSharp.Samples.Terminal) | A terminal client: each key sent as it is pressed (arrows, function keys, Ctrl and Alt combinations), and the remote terminal resized with the window |
| [SshSharp.Samples.JumpHost](SshSharp.Samples.JumpHost) | A jump host configured in code (`SshClientOptions.JumpHosts`), with a login to both hosts by a five-minute OpenSSH user certificate issued in the program (`SshCertificateBuilder`) |
| [SshSharp.Samples.Aot](SshSharp.Samples.Aot) | `sshrun`, a tool published with Native AOT: a command on several servers at once, one JSON line per server (source-generated JSON) |

The console tool's commands:

```
dotnet run --project samples/SshSharp.Samples -- run myserver "uname -a"
dotnet run --project samples/SshSharp.Samples -- get myserver /var/backups/db.dump db.dump
dotnet run --project samples/SshSharp.Samples -- put myserver ./site /srv/www
dotnet run --project samples/SshSharp.Samples -- tree myserver /srv/www
```

`myserver` is an `~/.ssh/config` alias, `user@host`, or `ssh://user@host:port`; the full list of commands is at the top of its
`Program.cs`. A password, if the server asks for one, comes from `SSHSHARP_PASSWORD`.

The other samples:

```
# Traces and metrics to an OTLP endpoint (OTEL_EXPORTER_OTLP_ENDPOINT, default http://localhost:4317)
dotnet run --project samples/SshSharp.Samples.OpenTelemetry -- myserver "uptime"

# A terminal session, in a terminal that understands VT sequences
dotnet run --project samples/SshSharp.Samples.Terminal -- myserver

# The first run creates the CA key and prints the line for the servers' TrustedUserCAKeys; later runs connect
dotnet run --project samples/SshSharp.Samples.JumpHost -- ./user_ca deploy@bastion.example.com deploy@db.example.com "hostname"

# A native executable (needs the platform's native toolchain, see docs/how-to/native-aot.md)
dotnet publish samples/SshSharp.Samples.Aot -c Release -o out
out/sshrun "uptime" web1 web2
```

None of them contains a host, user or credential: they come from the arguments, `~/.ssh/config`, the agent or the environment.