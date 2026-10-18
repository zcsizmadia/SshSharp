# Scenarios

Complete programs for jobs that come up again and again. Each scenario explains the approach, shows the code (compiled with the
library in CI), and lists what to change for production. Copy them as a starting point.

| Scenario | What it shows |
|---|---|
| [A deployment script](deployment-script.md) | Upload a release with resume, unpack it, switch a symlink atomically, restart, health-check through the connection, roll back. |
| [A fleet health check](fleet-health-check.md) | Check many hosts in parallel, each with its own connection and time limit, and report every host. |
| [A file sync job](file-sync.md) | Mirror a local directory to a server: only changed files, atomic replacement, safe to rerun after a failure. |
| [A database through a jump host](database-tunnel.md) | Reach a database inside a private network through a bastion, from any ADO.NET provider. |
| [A webhook receiver behind NAT](webhook-receiver.md) | Serve webhooks that reach a public server's port from your own code, over an outbound SSH connection, with no local port. |
| [A background worker](background-worker.md) | A hosted service that fetches files on a schedule over a shared, reconnecting connection. |
| [Short-lived certificates for CI jobs](ci-certificates.md) | Be the SSH certificate authority: issue each CI job a certificate for one user, for twenty minutes, from a CA key in a KMS or agent. |

The [samples](https://github.com/zcsizmadia/SshSharp/tree/main/samples) are runnable projects: an `ssh`-like command-line tool, an
ASP.NET Core API, and a worker service.
