# A deployment script

Deploy a release to a set of servers, one at a time: upload the archive, unpack it next to the previous releases, switch a
`current` symlink atomically, restart the service, check its health, and roll back if the check fails. Everything goes over one SSH
connection per server: the upload (SFTP), the commands, and even the HTTP health check.

## The approach

- **Connect by `ssh_config` alias**, so bastions, the deploy key and `known_hosts` are configuration, not code.
- **Upload with `Resume`**, so a retry after a dropped connection sends only the rest.
- **Releases side by side** (`/srv/myapp/releases/<version>`), with `current` a symbolic link. Switching is creating a new link and
  renaming it over the old one: `rename(2)` is atomic, so `current` always points at a complete release.
- **Health check through the connection**: `CreateHttpConnectCallback` lets `HttpClient` reach `http://localhost:8080` on the
  server, without opening the service's port to the network.
- **Stop at the first failure**, leaving the rest of the fleet on the old version.

## The code

[!code-csharp[](../snippets/Scenarios/Deployment.cs#deploy)]

[!code-csharp[](../snippets/Scenarios/Deployment.cs#deploy-main)]

A matching `~/.ssh/config`:

```
Host bastion
  HostName bastion.example.com
  User jump

Host web-*
  HostName %h.internal
  User deploy
  ProxyJump bastion
  IdentityFile ~/.ssh/deploy_ed25519
  StrictHostKeyChecking yes
```

Run it as `deploy 2.4.1 myapp-2.4.1.tar.gz web-1 web-2 web-3`.

## For production

- **First deployment.** The script reads the previous `current` link to roll back to; on a fresh server, create it first (or treat a
  missing link as "nothing to roll back to").
- **sudo.** `sudo systemctl restart` must not prompt: give the deploy user a `NOPASSWD` rule for exactly that command. If it must
  prompt, see [Interactive shells and SshExpect](../how-to/interactive-shell.md).
- **Old releases.** Remove releases beyond the last few (`ls -1t releases | tail -n +6 | xargs rm -rf`, quoted for your paths).
- **Parallel rollout.** To deploy to several servers at once, run `DeployAsync` for a batch with `Task.WhenAll`; see the
  [fleet health check](fleet-health-check.md) for bounded parallelism.
- **Logging.** Pass a logger through `SshConfigConnectOptions.Logger` to record which algorithms and host keys each server used.

## See also

- [Transfer files with SFTP](../how-to/transfer-files-sftp.md)
- [Port forwarding and tunnels](../how-to/port-forwarding.md#httpclient-through-the-server)
- [Jump hosts](../how-to/jump-hosts.md)
