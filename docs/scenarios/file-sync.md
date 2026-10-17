# A file sync job

Keep a directory on a server in step with a local one, as `rsync -t` would for the common case: upload new and changed files,
optionally delete files that no longer exist locally, and make every replacement atomic. The job is safe to run again after any
failure: files already in place are skipped.

## The approach

- **Compare by size and modification time.** One recursive listing of the remote tree gives both, with no request per file.
- **Preserve times on upload**, so a file uploaded once compares as unchanged next time.
- **Upload beside, then rename over** the target (`posix-rename@openssh.com`), so readers never see a half-written file.
- **Retry with a new connection** on a dropped connection; the rerun skips what is done.

## The code

[!code-csharp[](../snippets/Scenarios/FileSync.cs#sync)]

[!code-csharp[](../snippets/Scenarios/FileSync.cs#sync-main)]

## For production

- **Large files on flaky links.** Upload large files with `Resume = true` to a fixed temporary name (not a new one per attempt),
  so a retry continues where it stopped.
- **Content changes with the same size and time** are not detected. When that matters, compare checksums: run `sha256sum` on the
  server for candidate files, in one command.
- **Clock and time zones** do not matter: times travel as UTC seconds. Whole seconds only, which the comparison accounts for.
- **Deletion** is off by default in the example's `MainAsync`. Turn it on only when the remote directory belongs to this job.
- **Downloads.** The mirror image (server to local) is the same with `DownloadFileAsync`; for a plain copy of a tree, use
  `DownloadDirectoryAsync`, which already skips symbolic links and unsafe names.

## See also

- [Transfer files with SFTP](../how-to/transfer-files-sftp.md)
- [Keep-alive and reconnecting](../how-to/keepalive-and-reconnect.md)
