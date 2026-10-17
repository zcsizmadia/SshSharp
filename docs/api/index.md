# API reference

- **SshSharp**: `SshClient` and its options, sessions, forwarding, proxies, keys, certificates, signatures, the SSH agent,
  host key verification and exceptions.
- **SshSharp.Config**: `ssh_config` and `known_hosts` parsing and resolution.
- **SshSharp.Scp**: SCP uploads and downloads (extension methods on `SshClient`).
- **SshSharp.Sftp**: the SFTP client (`client.OpenSftpAsync()`).
- **SshSharp.FileProviders** (package `SshSharp.FileProviders`): `SftpFileProvider`, a remote directory as an `IFileProvider`.
- **SshSharp.IO.Abstractions** (package `SshSharp.IO.Abstractions`): `SftpFileSystem`, SFTP as an `IFileSystem`.

Start with `SshClient`, `SshClientOptions` and `SshConfigConnectOptions`.
