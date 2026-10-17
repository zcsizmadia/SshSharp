# API reference

Generated from the XML documentation comments, which IntelliSense shows too. Start with <xref:SshSharp.SshClient>,
<xref:SshSharp.SshClientOptions> and <xref:SshSharp.SshConfigConnectOptions>.

| Namespace | Package | Contents |
|---|---|---|
| <xref:SshSharp> | `SshSharp` | `SshClient` and its options, sessions, forwarding, proxies, keys, certificates, signatures, the SSH agent, host key verification and exceptions. |
| <xref:SshSharp.Config> | `SshSharp` | `ssh_config` and `known_hosts` parsing and resolution. |
| <xref:SshSharp.Sftp> | `SshSharp` | The SFTP client (`client.OpenSftpAsync()`). |
| <xref:SshSharp.Scp> | `SshSharp` | SCP uploads and downloads (extension methods on `SshClient`). |
| <xref:SshSharp.Extensions.DependencyInjection> | `SshSharp.Extensions.DependencyInjection` | `SshEndpointOptions`, `ISshClientFactory` and `ISshConnectionProvider`. `AddSshClient` and the `AddSsh` health check are in <xref:Microsoft.Extensions.DependencyInjection>. |
| <xref:SshSharp.IO.Abstractions> | `SshSharp.IO.Abstractions` | `SftpFileSystem`, SFTP as a System.IO.Abstractions `IFileSystem`. |
| <xref:SshSharp.FileProviders> | `SshSharp.FileProviders` | `SftpFileProvider`, a remote directory as an `IFileProvider`. |

## Most used types

| Task | Types |
|---|---|
| Connect | <xref:SshSharp.SshClient>, <xref:SshSharp.SshClientOptions>, <xref:SshSharp.SshConfigConnectOptions>, <xref:SshSharp.SshProxy> |
| Verify the server | <xref:SshSharp.KnownHostsVerifier>, <xref:SshSharp.SshHostKeyVerifier>, <xref:SshSharp.SshHostKey> |
| Authenticate | <xref:SshSharp.SshPrivateKey>, <xref:SshSharp.SshAgent>, <xref:SshSharp.SshCertificate>, <xref:SshSharp.SshKeySigner>, <xref:SshSharp.SshGssapiOptions> |
| Run programs | <xref:SshSharp.SshCommandResult>, <xref:SshSharp.SshSession>, <xref:SshSharp.SshSessionOptions>, <xref:SshSharp.SshExpect> |
| Transfer files | <xref:SshSharp.Sftp.SftpClient>, <xref:SshSharp.Sftp.SftpTransferOptions>, <xref:SshSharp.Scp.SshScpExtensions> |
| Forward ports | <xref:SshSharp.SshLocalPortForwarder>, <xref:SshSharp.SshRemotePortForwarder>, <xref:SshSharp.SshDynamicPortForwarder> |
| Handle errors | <xref:SshSharp.SshException>, <xref:SshSharp.SshFailureReason> |
| Configuration files | <xref:SshSharp.Config.SshConfig>, <xref:SshSharp.Config.SshHostConfig>, <xref:SshSharp.Config.KnownHostsFile> |

For explanations and examples, see the [documentation](../getting-started.md).
