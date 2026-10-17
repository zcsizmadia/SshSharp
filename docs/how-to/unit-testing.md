# Unit-test code that uses SshSharp

`SshClient`, `SshSession`, `SftpClient` and the other types are sealed, and SshSharp has no interfaces for them on purpose: an
interface can be added later without breaking anyone, but changing one after it ships breaks everyone who implements it. Test your
logic through a small interface of your own instead, and keep the SshSharp code behind it thin.

## When to use

- Your code decides things based on what a server says (parses output, chooses what to run next, handles failures).
- You want fast tests that need no server, no network and no credentials.

## Put a seam in front of SSH

Define the operations your code needs, in your terms, and implement them once with SshSharp:

[!code-csharp[](../snippets/Testing.cs#seam)]

## Write the logic against the seam

[!code-csharp[](../snippets/Testing.cs#logic)]

## Fake it in tests

[!code-csharp[](../snippets/Testing.cs#fake)]

[!code-csharp[](../snippets/Testing.cs#test)]

## Test configuration logic directly

The configuration types parse from strings and resolve with explicit inputs, so tests need no files:

[!code-csharp[](../snippets/Testing.cs#config-test)]

[!code-csharp[](../snippets/Testing.cs#known-hosts-test)]

`SshHostKeyVerifier` and `SshKeySigner` are abstract classes: your own verifiers and signers are testable like any other class.

## Integration tests

For tests against a real server, run OpenSSH in a container (the repository's `tests/docker` and `scripts/test-server.ps1` show one
way), and connect with a pinned host key or a `known_hosts` file the test writes. `SshClient.ConnectAsync` also takes any `Stream`,
so a test can connect to a server it runs in the same process; a package with such an in-memory test server is planned
([#240](https://github.com/zcsizmadia/SshSharp/issues/240)).

## Notes and pitfalls

- **Keep the wrapper thin.** It should translate, not decide; then it needs no unit tests of its own, only integration tests.
- **Model results, not exceptions only.** A command that exits non-zero is a result; let the fake return one, so the failure path is
  tested.
- **`IFileSystem`.** Code that works with remote files can take an `IFileSystem`: `SftpFileSystem` in production, an in-memory
  file system (System.IO.Abstractions' `MockFileSystem`) in tests. See [IFileSystem and IFileProvider](file-system-adapters.md).
- **Dependency injection.** `ISshClientFactory` and `ISshConnectionProvider` return `SshClient`, so faking them does not avoid the
  server; fake your seam instead.

## See also

- [Testing and validation](../testing.md): how SshSharp itself is tested
