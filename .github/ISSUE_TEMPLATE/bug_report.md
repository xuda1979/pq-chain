---
name: Bug report
about: Report a defect in the protocol, crypto, or state machine
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear and concise description of what the bug is.

**To reproduce**
Minimal code or steps to trigger the bug.

**Expected vs actual behavior**
What you expected, and what actually happened.

**Severity**
- [ ] Consensus / security critical (serialization, hashing, signature
      verification)
- [ ] Consensus-adjacent (state machine, fees)
- [ ] Non-consensus (tooling, docs, ergonomics)

If severity is "consensus/security critical", **do not file a public
issue** — use GitHub private vulnerability reporting instead (see
SECURITY.md).

**Environment**
- Go version:
- OS / architecture:
- PQ Chain version (tag or commit):
