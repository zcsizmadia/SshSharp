# A fleet health check

Check a few hundred servers in a minute: connect to many at once, run one compound command on each, and report every host, whether
it answered, failed or timed out. One slow or unreachable host must not hold up the report.

## The approach

- **Bounded parallelism.** `Parallel.ForEachAsync` with `MaxDegreeOfParallelism` keeps a fixed number of connections open at a time,
  so the checking machine, the network and any bastion are not flooded.
- **A time limit per host**, linked to the overall token, so a host that accepts TCP and then stalls costs at most that limit.
- **One connection per host, one command per connection.** Several checks are chained in one command line, so each host costs one
  round of connect, authenticate, run.
- **Every failure is a result.** Exceptions become report lines with the `SshFailureReason`, which already says whether the host was
  unreachable, refused the login, or presented an unknown host key.

## The code

[!code-csharp[](../snippets/Scenarios/FleetHealth.cs#fleet)]

[!code-csharp[](../snippets/Scenarios/FleetHealth.cs#fleet-main)]

Sample output:

```
FAIL app-17                           20.0s  timed out
FAIL db-3                              0.4s  HostKeyRejected: The host key SHA256:... is not in known_hosts, and StrictHostKeyChecking is yes.
ok   app-1                             0.9s  load 0.12, disk 41%, running
ok   app-2                             1.1s  load 0.30, disk 57%, running
```

## For production

- **Unattended runs.** Without `AskHostKey`, an unknown host fails instead of prompting; keep `StrictHostKeyChecking yes` and manage
  `known_hosts` (or `@cert-authority` lines) with your provisioning.
- **Bastions.** With `ProxyJump`, every host makes its own connection to the bastion. With many hosts, raise the bastion's
  `MaxStartups` and `MaxSessions` as needed, or connect to the bastion once and open each target over
  `OpenTcpTunnelAsync` (see [Jump hosts: by hand](../how-to/jump-hosts.md#by-hand)).
- **Exit status.** `systemctl is-system-running` exits non-zero on a degraded system, and its state is still worth reporting, so the
  code reads the output rather than calling `EnsureSuccess()`. For a check that passes or fails by its exit status
  (`systemctl is-active myapp`), chain `.EnsureSuccess()`: a failure throws `SshCommandException`, which the `catch (SshException)`
  above already turns into a report line (`CommandFailed: The command failed with exit status 3.`).
- **Output parsing.** The parsing here is deliberately simple. For anything richer, have the server print JSON
  (`jq`, or a small script you deploy) and deserialize it.
- **Metrics.** Instead of printing, record a gauge per host, or let SshSharp's own metrics (`sshsharp.connect.duration` and
  `sshsharp.commands`, see [Logging and diagnostics](../how-to/logging-and-diagnostics.md)) feed your dashboards.

## See also

- [Run a command](../how-to/run-a-command.md)
- [Cancellation and timeouts](../how-to/cancellation-and-timeouts.md)
- [Errors and failure reasons](../reference/errors.md)
