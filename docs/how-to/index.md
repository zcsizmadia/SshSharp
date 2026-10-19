# How-to guides

Short, task-oriented pages. Each one starts with when to use it, shows focused examples, and ends with the pitfalls and links to
the in-depth guides. The examples assume a connected `SshClient` named `client` and a `CancellationToken` named
`cancellationToken`; [Getting started](../getting-started.md) shows how to get the client.

Every example on these pages is compiled with the library in CI, so it matches the current API.

## Commands and shells

| Guide | Use it to |
|---|---|
| [Run a command](run-a-command.md) | Run a command, with standard input, environment variables or a terminal; read its stdout, stderr and exit status, or throw on failure. |
| [Stream large output](stream-output.md) | Process output as it arrives, feed input, and handle output that does not fit in memory. |
| [Interactive shells and SshExpect](interactive-shell.md) | Drive a shell or a device CLI with a terminal; wait for prompts and answer them. |

## Files

| Guide | Use it to |
|---|---|
| [Transfer files with SFTP](transfer-files-sftp.md) | Upload, download, resume, copy directories, and work with remote files in place. |
| [Transfer files with SCP](transfer-files-scp.md) | Copy files where the server has no SFTP. |
| [IFileSystem and IFileProvider](file-system-adapters.md) | Use remote files through System.IO.Abstractions or `Microsoft.Extensions.FileProviders`. |

## Networking

| Guide | Use it to |
|---|---|
| [Port forwarding and tunnels](port-forwarding.md) | Reach services behind the server (`ssh -L`, `-R`, `-D`), or give the server a way back. |
| [Jump hosts (ProxyJump)](jump-hosts.md) | Reach hosts through one or more bastions. |
| [Tune and inspect a connection](tune-and-inspect-connections.md) | Set socket options, identify your application to the server, raise the channel window for long links, read a connection's endpoints and traffic, and re-key on demand. |

## Configuration and trust

| Guide | Use it to |
|---|---|
| [Use ssh_config and known_hosts](ssh-config-and-known-hosts.md) | Connect by alias, ship your own configuration, read `known_hosts`. |
| [Verify host keys](verify-host-keys.md) | Choose a host key policy: `known_hosts`, pinning, certificates, or your own source of truth. |
| [Choose algorithms and authentication methods](algorithms-and-authentication-order.md) | Restrict or reorder ciphers, key exchanges, MACs and host key algorithms; choose the authentication methods; require larger RSA host keys. |

## Authentication

| Guide | Use it to |
|---|---|
| [Keys and the SSH agent](agent-and-keys.md) | Log in with key files, the agent, generated keys, or keys in a TPM, HSM or KMS; export keys to PKCS#8 or PuTTY. |
| [Passwords: prompts, expiry and failures](passwords.md) | Prompt for a password only when keys did not work, change an expired password, and see why a login failed. |
| [Certificates](certificates.md) | Log in with OpenSSH user certificates, check certificates, and issue them as a certificate authority. |
| [Kerberos](kerberos.md) | Log in with a Kerberos ticket (Active Directory). |

## Reliability

| Guide | Use it to |
|---|---|
| [Keep-alive and reconnecting](keepalive-and-reconnect.md) | Notice dead connections and open new ones. |
| [Cancellation and timeouts](cancellation-and-timeouts.md) | Bound how long connecting and commands may take. |
| [Logging and diagnostics](logging-and-diagnostics.md) | See what a connection does: logs, traces, metrics, negotiated algorithms. |

## Applications

| Guide | Use it to |
|---|---|
| [ASP.NET Core and dependency injection](aspnetcore-and-di.md) | Register SSH endpoints, share a connection, add a health check. |
| [Unit-test code that uses SshSharp](unit-testing.md) | Test your logic without a server. |
| [Native AOT](native-aot.md) | Publish a trimmed, ahead-of-time compiled application. |
| [FIPS mode](fips-mode.md) | Use only FIPS-approved algorithms. |
| [Migrate from SSH.NET](../migrating-from-sshnet.md) | Map SSH.NET code to SshSharp. |
