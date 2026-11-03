# Open-Source Policy / 开源策略

## English

PQ Chain follows an **open-core** model. This document is the normative
statement of what is open, what is proprietary, and why. It is the
"open-source policy" chapter of the project whitepaper.

### Principles

1. **Verification is consensus, and consensus must be open.**
   Every signature and every block must be verifiable by any party using
   only the code in this repository. Nothing in the validation path may
   depend on proprietary software, proprietary data, or a network service.

2. **Only *generation* may be closed.**
   Key generation and signing may be accelerated by proprietary engines
   (SIMD/GPU kernels, HSM backends, batch provers). A signature produced
   by any such engine is a bit string; it is valid if and only if the
   open verifier in `crypto/` accepts it.

3. **The wire is frozen here.**
   Serialization formats (`protocol/`), the plugin ABI and JSON-RPC
   method names (`plugin/`), and the signature scheme registry
   (`crypto/`) are defined in this repository under Apache-2.0.
   Proprietary implementations must conform; they cannot fork the
   protocol.

4. **No copyleft in the consensus path.**
   This repository is Apache-2.0 (not GPL) precisely so that closed-source
   plugins may link against the open interfaces without triggering
   source-disclosure obligations. Apache-2.0 is GPL-compatible for
   downstream users who prefer copyleft distributions.

### What is open (this repository)

| Area | Path | Notes |
|---|---|---|
| Serialization & hashing | `protocol/` | Canonical, deterministic, strict |
| Block & transaction types | `protocol/` | Consensus-critical |
| ML-DSA verify (all parameter sets) | `crypto/mldsa.go` | **Red line: never moved, never closed** |
| Signer/verifier interfaces & registry | `crypto/signer.go` | The seam |
| Plugin ABI: client, server, handshake | `plugin/` | Wire contract |
| Signed-plugin loader | `crypto/plugin_load.go` | Ed25519 hash+signature gate |
| State machine & fee/staking rules | `state/` | Consensus rules |
| Reference (portable) signing | `crypto/mldsa.go` | Complete, if slower |

### What may be proprietary (separate, private repository)

- Parallel/batch/GPU/HSM signing engines
- Managed (remote) signing services
- Release tooling for signed plugin packaging
- Performance know-how: kernel schedules, batching strategies

### Compliance rules for the proprietary side

1. Every proprietary artifact must verify with the open verifiers.
   CI must run all engine output through `crypto` from this repository.
2. Verification logic must never be copied into the private tree.
3. The plugin ABI version and JSON-RPC method names come from here.
4. Proprietary code links against published interfaces only
   (`crypto.Signer`, `plugin.Handler`); no internal forks of consensus
   logic.

### Fork and reverse-engineering posture

- Forking this repository yields a *slower but fully valid* chain
  client: the reference signer is complete. That is intentional.
- Performance advantages are trade secrets, not patents; we do not rely
  on legal threats against reverse engineering. We rely on the cost of
  reproducing the engineering.
- Chain-security claims (what counts as a valid block) are always
  reproducible from this repository alone.

### Attribution

This project uses the Go standard library's ML-DSA implementation
(FIPS 204), Apache-2.0. See `NOTICE`.

---

## 中文

PQ Chain 采用 **open-core（开放内核）** 模式。本文档是白皮书中"开源策略"
章节的规范表述：界定哪些部分开放、哪些部分专有，以及原因。

### 原则

1. **验证属于共识，共识必须开放。**
   任何一方仅使用本仓库的代码，即可验证每一笔签名与每一个区块。
   验证路径不得依赖专有软件、专有数据或网络服务。

2. **只有"生成"可以闭源。**
   密钥生成与签名可以由专有引擎加速（SIMD/GPU 内核、HSM 后端、批量
   证明器）。任何此类引擎产生的签名只是一个比特串：当且仅当 `crypto/`
   中的开源验证器接受它时，它才有效。

3. **线上协议（wire）在本仓库冻结。**
   序列化格式（`protocol/`）、插件 ABI 与 JSON-RPC 方法名
   （`plugin/`）、签名方案注册表（`crypto/`）均在 Apache-2.0 下定义于
   本仓库。专有实现必须遵循，不得分叉协议。

4. **共识路径不含 copyleft。**
   本仓库采用 Apache-2.0（而非 GPL），正是为了让闭源插件可以链接开源
   接口而不触发源码披露义务。对偏好 copyleft 发行版的下游用户，
   Apache-2.0 亦与 GPL 兼容。

### 开放部分（本仓库）

| 领域 | 路径 | 说明 |
|---|---|---|
| 序列化与哈希 | `protocol/` | 规范、确定、严格 |
| 区块与交易类型 | `protocol/` | 共识关键 |
| ML-DSA 验证（全部参数集） | `crypto/mldsa.go` | **红线：永不迁移、永不闭源** |
| 签名器/验证器接口与注册表 | `crypto/signer.go` | 接缝所在 |
| 插件 ABI：客户端、服务端、握手 | `plugin/` | 线上契约 |
| 签名插件加载器 | `crypto/plugin_load.go` | Ed25519 哈希+签名门禁 |
| 状态机与费用/质押规则 | `state/` | 共识规则 |
| 参考（可移植）签名实现 | `crypto/mldsa.go` | 完整，但较慢 |

### 可专有部分（独立私有仓库）

- 并行/批量/GPU/HSM 签名引擎
- 托管（远程）签名服务
- 签名插件打包的发布工具
- 性能知识：内核调度、批处理策略

### 专有一侧的合规规则

1. 每个专有产物都必须通过开源验证器。CI 必须将引擎输出送入本仓库的
   `crypto` 验证。
2. 验证逻辑永远不得复制到私有代码库。
3. 插件 ABI 版本与 JSON-RPC 方法名以本仓库为准。
4. 专有代码只链接公开接口（`crypto.Signer`、`plugin.Handler`）；
   不得在内部分叉共识逻辑。

### 分叉与逆向工程立场

- 分叉本仓库得到的是一个"较慢但完全有效"的链客户端：参考签名实现是
  完整的。这是有意为之。
- 性能优势是商业秘密而非专利；我们不依赖针对逆向工程的法律威胁，
  而是依赖重现这些工程投入的成本。
- 链安全声明（什么算有效区块）永远可以仅凭本仓库复现。

### 致谢

本项目使用 Go 标准库的 ML-DSA 实现（FIPS 204），Apache-2.0。
见 `NOTICE`。
