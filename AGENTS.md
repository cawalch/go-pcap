# Agent guidelines

Follow [Contributing](CONTRIBUTING.md) for verification, documentation, and
issue and pull request descriptions.

- Require a concrete caller for new protocol features. Reuse existing code,
  then prefer the Go standard library. Keep runtime dependencies at zero.
- Bound parser and reader work explicitly. Validate sizes, counts, and input
  ranges before using them.
- Keep capture I/O, dissection, fingerprints, and offline decryption in this
  module. Keep scanner schemas, YARA adapters, and rules in consuming projects.
- Update Go doc comments, examples, and relevant guides when exported
  behavior changes.
