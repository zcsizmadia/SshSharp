# Contributing to SshSharp

## Documentation is part of every feature

The documentation site (DocFX, built from `docs/`) is part of the product. A pull request that adds or changes user-visible behavior
is not complete until the site documents it. Reviewers hold back a merge until the docs are in the same pull request, not a
follow-up.

For a new feature, option, API or ssh_config directive:

- **A how-to page or section** in `docs/how-to/`: a short intro, "When to use", focused examples, notes and pitfalls, and "See
  also". A larger feature gets its own page, listed in `docs/how-to/index.md` and `docs/guide/toc.yml`. A smaller one gets a
  section on the page where users will look for it.
- **The in-depth guide** (`docs/connecting.md`, `docs/sftp.md`, `docs/authentication.md` and so on) when the feature changes how
  something described there works.
- **The reference pages** in `docs/reference/` when they are affected:
  - `ssh-config.md` for directives;
  - `algorithms.md` for algorithms;
  - `errors.md` for new `SshFailureReason` values or exceptions;
  - `troubleshooting.md` and `faq.md` for new failure modes.
- **Concept pages** in `docs/concepts/` when the feature changes the architecture, threading or the security model. Update
  `docs/threat-model.md` for anything that changes what is trusted, what runs locally, or what is sent to the server.
- **A scenario** in `docs/scenarios/` when the feature enables a new real-world use.
- **A diagram** (Mermaid) where a flow, sequence or set of hops is easier to see than to read. Don't add diagrams for their own sake.
- **XML doc comments** on every public member. They generate the API reference.
- **The README** feature list and comparison table, for headline features.

### Examples are compiled

Code on the site lives in `docs/snippets/`, a project in the solution that CI builds. Pages include it by region:

```markdown
[!code-csharp[](../snippets/Commands.cs#run-basic)]
```

Add new examples there, in a `#region` named after what it shows, so they cannot drift from the API. Keep them short and focused on
the task.

In examples:

- use `example.com` names and documentation addresses (`192.0.2.x`, `2001:db8::/32`), and user names such as `user` or `deploy`;
- never use a real host, address or person;
- never write a plaintext password: read it from configuration, a secret store or an environment variable.

### Checking the site locally

Run what the Docs workflow runs. It fails on any warning, including broken links and anchors:

```shell
dotnet tool restore
dotnet build src/SshSharp.FileProviders -c Release
dotnet build src/SshSharp.IO.Abstractions -c Release
dotnet build src/SshSharp.Extensions.DependencyInjection -c Release
dotnet docfx docs/docfx.json
```

The site is written to `docs/_site`, which is not committed. On a pull request, the Docs check uploads the built site as the
`docs-site` artifact, so reviewers can browse it.

## Public API

Public API changes are tracked by the PublicAPI analyzers: add new members to the project's `PublicAPI.Unshipped.txt`. Package
validation checks each package against the last release, so 1.x changes must be additive.

## Tests

New behavior needs tests in `tests/SshSharp.Tests`. Interop tests against real servers run in CI.

Test classes that need a real server carry `[Category("Integration")]`; the unit jobs leave them out and the interop jobs run only
them. Each CI job lists the tests it may skip (`tests/ci/skips/`), and an unexpected skip fails the job. See
[Test categories and skips](docs/testing.md#test-categories-and-skips) for the filters, how to run unit and interop tests locally,
and how to update a skip list.
