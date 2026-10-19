# A background worker

A partner drops files into an `outbox` directory on their SFTP server. A worker service fetches new files every five minutes, saves
them locally, and moves each one to `done` on the server once it has it. It runs for months: connections drop, the partner's server
restarts, and the worker carries on.

## The approach

- **A hosted service** (`BackgroundService`) with a `PeriodicTimer`, on the generic host.
- **The shared connection from dependency injection** (`ISshConnectionProvider`): opened on first use and again after a drop, with a
  growing delay after failures, so a server that is down is not hammered.
- **An SFTP session per run**, closed at the end of the run; the SSH connection stays open between runs.
- **At-least-once processing.** A file is moved to `done` only after it is saved, so a failure in between means it is fetched again
  at the next run, never lost. Make the downstream processing idempotent.

## The code

[!code-csharp[](../snippets/Scenarios/IngestWorker.cs#program)]

[!code-csharp[](../snippets/Scenarios/IngestWorker.cs#worker)]

`appsettings.json`:

```json
{
  "Ssh": {
    "Partner": {
      "Host": "sftp.example.com",
      "UserName": "user",
      "PrivateKeyFiles": [ "/run/secrets/partner_ed25519" ],
      "KnownHostsFiles": [ "/etc/ingest/known_hosts" ],
      "KeepAliveInterval": "00:00:30"
    }
  },
  "Ingest": { "LocalDirectory": "/var/lib/ingest/inbox" }
}
```

## For production

- **Secrets.** Mount the key (and any passphrase) from your platform's secret store, as above; do not bake it into the image.
- **Host key.** Ship the partner's host key in a `known_hosts` file. `AcceptNewHostKeys` would trust whatever answers first.
- **Health.** Add `builder.Services.AddHealthChecks().AddSsh("partner")` and expose it to your orchestrator.
- **Partial files.** The example skips names ending in `.partial`; agree on a convention with the partner (upload under a temporary
  name, then rename), or wait for a file's size to stop changing.
- **Large files.** Add `Resume = true` to continue interrupted downloads, or `Segments` for faster downloads and uploads over long distances.

## See also

- [ASP.NET Core and dependency injection](../how-to/aspnetcore-and-di.md)
- [Keep-alive and reconnecting](../how-to/keepalive-and-reconnect.md)
- The runnable [worker service sample](https://github.com/zcsizmadia/SshSharp/tree/main/samples/SshSharp.Samples.Worker), which
  follows a remote log file across dropped connections
