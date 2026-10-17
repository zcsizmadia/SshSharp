# SshSharp

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the library.

- **Every new feature, option, API or ssh_config directive ships with its documentation in the same pull request:**
  - how-to pages;
  - the affected guides, reference, concept and scenario pages;
  - Mermaid diagrams where they help;
  - XML doc comments.

  Examples go in `docs/snippets/` (compiled in CI) and are included by region. A feature without docs is not done. Don't open a
  follow-up for its docs.
- Run the Docs workflow's steps locally (CONTRIBUTING.md, "Checking the site locally"); the build must have zero warnings.
- Examples use `example.com`, documentation IP ranges and generic user names, and never a plaintext password.
