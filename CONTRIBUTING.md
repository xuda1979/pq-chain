# Contributing to PQ Chain

Thanks for considering contributing to PQ Chain. This is a post-quantum
blockchain protocol, so correctness and consensus compatibility matter more
than anything else.

## Ground rules

- **Verification stays open, always.** Any change that makes validation
  depend on closed-source code, a network service, or a dynamically loaded
  binary is rejected on sight. See [docs/OPEN-SOURCE-POLICY.md](docs/OPEN-SOURCE-POLICY.md).
- **Consensus changes need a protocol upgrade review.** Changes to
  `protocol/`, `crypto/MLDSASuite.Verify`, hashing, or serialization
  affect every node. They require cross-implementation test vectors.
- **Security issues are reported privately** via GitHub private
  vulnerability reporting (see [SECURITY.md](SECURITY.md)), never as public
  issues.

## Development workflow

1. Fork the repository.
2. Create a branch with a descriptive name (`fix/`, `feat/`, `refactor/`).
3. Make your change with tests. New code must come with tests; changed
   behavior must update existing tests.
4. Run the local checks before pushing:

   ```sh
   go vet ./...
   go test ./... -count=1
   go test ./... -race -count=1   # run in CI too
   ```

5. Open a pull request against `main`.

## Scope

The open-source repository intentionally contains:

- The full consensus kernel: serialization, hashing, Merkle roots, the
  state machine, and all ML-DSA verification.
- The reference (portable) signer — the network works with zero closed
  source.
- The plugin ABI and signed-plugin loader.

It does **not** contain the accelerated signing engines or managed signing
service; those are commercial products in a separate proprietary
repository. Contributions that belong to the commercial layer will be
redirected rather than merged.

## Code of conduct

Be respectful. Disagreements about design are welcome; personal attacks are
not. Maintainers may ban repeat offenders.
