# Changelog

All notable changes to PQ Chain are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CONTRIBUTING.md`, `FUNDING.yml`, and this changelog to establish the
  contribution and governance surface for the open-source community.

### Changed
- Module path moved from the `your-org` placeholder to the real
  repository (`github.com/xuda1979/pq-chain`), making the module
  `go get`-able.
- Security contact switched from a placeholder email to GitHub private
  vulnerability reporting.

## [0.1.0] - 2026-11-19

### Added
- Reference protocol kernel: canonical serialization, hashing, Merkle
  transaction roots (`protocol/`).
- ML-DSA (FIPS 204) suites for parameter sets 44/65/87 with open
  verification and reference signing (`crypto/`).
- Signed-plugin loader with hash verification, Ed25519 release
  signature gate, and TOCTOU-safe staging of verified binaries
  (`crypto/plugin_load.go`).
- Plugin ABI: node⇄plugin wire protocol (`plugin/`).
- Account state machine with staking, key rotation, transaction and
  block application (`state/`).
- CI with `go vet`, full test suite, and `-race` detector runs.
- `docs/OPEN-SOURCE-POLICY.md`: normative open-core split statement
  (English and 中文).

[Unreleased]: https://github.com/xuda1979/pq-chain/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xuda1979/pq-chain/releases/tag/v0.1.0
