# IFileSystem and IFileProvider

Two adapter packages let code written against .NET's file abstractions use files on an SSH server, unchanged, over SFTP. Nothing
is mounted: only your application sees the files.

| Package | Type | Interface |
|---|---|---|
| `SshSharp.IO.Abstractions` | `SftpFileSystem` | [System.IO.Abstractions](https://github.com/TestableIO/System.IO.Abstractions)' `IFileSystem`: `File`, `Directory`, `Path`, `FileInfo`, streams. Read and write. |
| `SshSharp.FileProviders` | `SftpFileProvider` | `Microsoft.Extensions.FileProviders.IFileProvider`: ASP.NET Core static files, Razor views, configuration. Read-only. |

## When to use

- **`IFileSystem`**: you already have (or want) code that takes an `IFileSystem`, so it can run against the local disk, an
  in-memory file system in tests, or a server.
- **`IFileProvider`**: a framework component reads files through `IFileProvider` and you want it to read them from a server.
- For transfers and full control, use [`SftpClient`](transfer-files-sftp.md) directly: the adapters add convenience, not speed.

## Code against IFileSystem

```
dotnet add package SshSharp.IO.Abstractions
```

[!code-csharp[](../snippets/FileSystems.cs#report-writer)]

[!code-csharp[](../snippets/FileSystems.cs#file-system)]

Streams from the adapter are ordinary streams, so local and remote combine:

[!code-csharp[](../snippets/FileSystems.cs#copy-between)]

## Serve files with IFileProvider

```
dotnet add package SshSharp.FileProviders
```

[!code-csharp[](../snippets/FileSystems.cs#file-provider)]

It also feeds configuration:

[!code-csharp[](../snippets/FileSystems.cs#configuration)]

## Notes and pitfalls

- **Paths are POSIX.** `SftpFileSystem.Path` uses `/` on every client OS, and `\` is an ordinary character. Relative paths start
  at the login directory.
- **Synchronous calls block.** `IFileProvider` is synchronous by contract, and so are many `IFileSystem` methods: each waits for an
  SFTP round trip and holds a thread meanwhile. Prefer the `...Async` methods of `IFileSystem` under load, and keep the provider's
  cache on (`SftpFileProviderOptions.CacheDuration`, 5 seconds by default).
- **Timeouts.** `SftpFileSystemOptions.OperationTimeout` (60 s) and `SftpFileProviderOptions.OperationTimeout` (30 s) bound each
  request; for whole-file reads and writes the file system's timeout bounds time without progress, so large files are not cut off.
- **Errors.** `SftpFileSystem` throws the `System.IO` exceptions code expects (`FileNotFoundException`,
  `UnauthorizedAccessException`, `IOException`). `SftpFileProvider` reports a missing or unreadable file as `Exists == false`.
- **No change notifications.** SFTP has none: `FileSystemWatcher` is not supported, and the provider's `Watch` never fires, so
  `reloadOnChange` has no effect.
- **Ownership.** Neither adapter owns the `SftpClient`. Dispose it (and the `SshClient`) after the adapter is no longer used.
- **Not supported** by `SftpFileSystem`: `DriveInfo`, `FileVersionInfo`, `RandomAccess`, encryption, `Replace`; SFTP has no creation
  times. The [SFTP guide](../sftp.md#using-ifilesystem-systemioabstractions) has the full table.

## See also

- [File transfer (SFTP)](../sftp.md#serving-files-with-ifileprovider) (in-depth guide)
- [ASP.NET Core and dependency injection](aspnetcore-and-di.md)
- <xref:SshSharp.IO.Abstractions.SftpFileSystem> and <xref:SshSharp.FileProviders.SftpFileProvider> in the API reference
