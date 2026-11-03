# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| main | ✅ |
| tagged releases | ✅ (latest two) |

## Reporting a vulnerability

Email **security@your-org.example** (replace with the real address before
launch). Please do not open public issues for vulnerabilities.

- We aim to acknowledge within 48 hours.
- Cryptographic flaws affecting consensus (hashing, serialization,
  signature verification) are treated as critical.
- Coordinated disclosure with credit to the reporter.

## Consensus-critical code

The following must never depend on closed-source or dynamically loaded
code, since every node must be able to validate the chain from this
repository alone:

- `protocol/` — serialization, hashing, Merkle roots
- `crypto/MLDSASuite.Verify` — ML-DSA verification
- `plugin/` handshake verification and plugin signature checks

Changes to these areas require cross-implementation test vectors and a
protocol upgrade review.
