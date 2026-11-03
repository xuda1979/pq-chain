# PQ Chain — Public (Open Source)

Post-quantum blockchain protocol reference implementation. Everything a
node needs to **validate the chain** is in this repository, in the open.

> ML-DSA (FIPS 204) signatures · canonical serialization · plugin ABI for
> optional accelerated signing

## What lives here (and what deliberately does not)

| Component | Here? | Why |
|---|---|---|
| Block / transaction / header formats | ✅ | Consensus requires identical serialization everywhere |
| Canonical hashing, Merkle tx root | ✅ | Every node must compute the same hashes |
| ML-DSA-44/65/87 **verification** | ✅ | Red line: verification must never be closed-source |
| ML-DSA **reference signing** | ✅ | The network must work with zero proprietary code |
| Plugin ABI (wire protocol, loader, signature checks) | ✅ | So vendor plugins are interoperable and auditable |
| Accelerated signing / GPU prover / HSM backends | ❌ | Commercial modules live in the private repo |

## Design rule

**Verify is open, Sign may be accelerated.**

Every transaction and block carries a standard ML-DSA signature. Any node
built from this repository alone can fully validate every signature and
every block. Optional plugins replace only the *generation* side
(keygen/sign) with faster implementations — they are never in the
consensus path.

## Layout

```
protocol/   canonical types: block, transaction, hashing, serialization
crypto/     signer/verifier interfaces, ML-DSA suites, plugin loader
plugin/     node⇄plugin wire protocol (client and server side)
state/      account state machine, staking, tx/block application, fees
```

## Quick start

Requires Go 1.27+ (stdlib crypto/mldsa).

```sh
make            # vet + test + build
go test ./...   # includes a full plugin subprocess round-trip test
```

## Using an accelerated signer plugin (optional)

```go
reg := crypto.NewRegistry()
reg.Register(crypto.NewMLDSA65()) // always register the reference suite

// Opt-in to a vendor plugin (hash + Ed25519 release-signature verified):
signer, closeFn, err := crypto.LoadAcceleratedSigner(
    "/path/to/plugin-dir", protocol.SchemeMLDSA65)
if err == nil {
    defer closeFn()
    // use signer for high-throughput signing; verification unchanged
}
```

A plugin is a directory containing:

- `accelerated-pqc-plugin` — the binary
- `manifest.json` — name, version, schemes, SHA-256 of the binary
- `binary.sig` — Ed25519 signature of the binary hash by the vendor key

Unsigned or hash-mismatched plugins are refused.

## Open-source policy

The normative statement of the open-core split — what is open, what may
be proprietary, and the compliance rules the proprietary side follows —
is [docs/OPEN-SOURCE-POLICY.md](docs/OPEN-SOURCE-POLICY.md) (bilingual,
the whitepaper "open-source policy" chapter).

## Security policy

- Verification logic must remain open-source — it is consensus-critical.
  Changes to `crypto/MLDSASuite.Verify`, `protocol.*` hashing or
  serialization are hard-fork hazards and need a BIP-style review.
- Report vulnerabilities privately to security@your-org.example
  (see SECURITY.md).
- Third-party cryptographic audit of this repository is a release
  requirement for mainnet.

## License

Apache-2.0 (see LICENSE). This license is chosen deliberately: it permits
dynamic linking with proprietary plugins (the commercial distribution
model) while keeping the protocol fully open. Do NOT relicense to GPL.

## Trademark / branding

The project name and logo are trademarks of the project owner; the
Apache-2.0 grant covers code, not branding.
