# R1-1：Ed25519 / X25519 provider 设计

- 状态：设计稿，未实现
- 基线：`main` @ `caab165`（`docs: refresh progress report through M2`）
- 变更范围：仅新增本文件；本 PR 不改任何代码、不改现有 provider、不合并
- 关联文档：`docs/m2-crypto-backend.md` §2.2 / §6、`docs/progress-report.md` §7、`ARCHITECTURE.md` §12

## 0. 结论

1. **推荐方案 B：新建独立 crate `rtx-crypto-dalek`**，只承载 Ed25519 / X25519 provider；实现 `rtx-crypto` 现有的 `SignatureProvider` 与 `KeyExchangeProvider`，**不另起 trait**。`rtx-crypto-rustcrypto` 保持完全不变，两个套件继续返回 `CryptoError::Unsupported`。
2. **前提校正**：`curve25519-dalek` 没有名为 `constant_time` 的 Cargo feature（4.1.3 与 5.0.0 的公开 feature 表均无此项）。常数时间是 dalek 默认算术路径的属性，变时间入口以 `vartime` 显式命名。因此可执行的审计动作不是“打开一个 feature”，而是固定版本、收紧 feature、禁止 `vartime` 调用、固定编译选项，并用工具验证。
3. 依赖选择：直接使用 `curve25519-dalek` + `ed25519-dalek`；**不默认引入 `x25519-dalek`**（`x25519-dalek 3.0.0` 无条件依赖 `rand_core`，且其 `StaticSecret`（`static_secrets` feature）暴露 `AsRef<[u8]>`，对“密钥不透明”不利）。X25519 用 `MontgomeryPoint::mul_clamped` / `mul_base_clamped` 即可。
4. **审计底线**：任何一项审计未通过或未在目标硬件上验证，对应算法继续返回 `Unsupported`；不做“先启用、后审计”，不以功能测试通过替代恒时审计。
5. 实现顺序：X25519 `generate_key` / `agree` → Ed25519 `verify` → Ed25519 `sign` → 恒时审计签字 → DTLS 引擎集成。

## 1. 仓库现状核对

本节只陈述仓库事实，作为后续设计与验收的锚点。

| 项目 | 现状 | 依据 |
|---|---|---|
| 能力 trait | `rtx-crypto` 定义六个能力 trait：`RandomProvider`、`HashProvider`、`HmacProvider`、`AeadProvider`、`SignatureProvider`、`KeyExchangeProvider`，外加聚合 marker `CryptoProvider` | `crates/rtx-crypto/src/lib.rs` |
| 零依赖 | `rtx-crypto` 的 `[dependencies]` 为空；`std` 是空 feature，默认 `no_std`；`proptest` / `rtx-buffer` / `rtx-core` 只在 dev-dependencies | `crates/rtx-crypto/Cargo.toml` |
| 签名契约 | `SignatureProvider` 有 `type PrivateKey`；`sign` 收 `&Self::PrivateKey`，`verify` 收裸公钥字节；错误语义为 `Unsupported` / `OutputTooSmall` / `InvalidSignature` | `crates/rtx-crypto/src/lib.rs` |
| 密钥交换契约 | `KeyExchangeProvider` 有 `type PrivateKey`；`generate_key` 返回 `(PrivateKey, usize)`，`agree` 收 `&Self::PrivateKey` 并写 `secret_out`；错误语义含 `InvalidKey` / `OutputTooSmall` | `crates/rtx-crypto/src/lib.rs` |
| 算法枚举 | `SignatureAlgorithm::Ed25519` 与 `KeyExchangeAlgorithm::X25519` 已存在；无需新增或修改枚举 | `crates/rtx-crypto/src/lib.rs` |
| 现有后端 | `rtx-crypto-rustcrypto` 实现 Random / Hash / HMAC / AEAD；Signature 与 KeyExchange 的每个入口都显式返回 `Unsupported` | `crates/rtx-crypto-rustcrypto/src/lib.rs` |
| 聚合 trait | `RustCryptoProvider` **没有**实现 `CryptoProvider`；只有编译期能力断言 `_AssertCapabilities` 列出四个已实现 trait | 同上；`docs/m2-crypto-backend.md` §2.2 |
| 占位句柄 | 现有 `SigningKey` / `ExchangeKey` 是占位类型，派生 `Debug`、`Clone`、`Copy`、`PartialEq`、`Eq`，`Debug` 会打印 `[u8; 32]` 私钥字节；`for_tests` 受 `cfg(any(test, feature = "std"))` 限制 | 同上。**生产实现不得照抄这些派生** |
| 设计依据 | M2 明确记录：Ed25519/X25519 需要域运算，常数时间性未审计，静默错误的握手比明确拒绝更糟 | `docs/m2-crypto-backend.md` §2.2 |
| 下一步 | §7 第 2 项列出 Ed25519 / X25519 provider | `docs/progress-report.md` §7 |
| 架构约束 | ARCH §12 六条：provider-neutral、边界无分配要求、原地 AEAD、调用方输出缓冲、私钥不透明句柄可留在 HSM/安全元件、不假设动态派发或引用计数 | `ARCHITECTURE.md` §12 |
| 工程约束 | workspace `rust-version = 1.85`、edition 2024、`unsafe_code = "forbid"`、release `lto = "thin"` / `codegen-units = 1` / `panic = "abort"` | 根 `Cargo.toml` |
| CI 现状 | Gate 1 已在 `thumbv7em-none-eabihf` 上 `cargo check --no-default-features`；Gate 3b 单独跑 `rtx-crypto-rustcrypto` 的公开向量与裸机构建 | `.github/workflows/ci.yml` |
| 对象安全 | `CryptoProvider` 不能作为 trait object：两个 supertrait 各有一个同名 `PrivateKey` 关联类型，`dyn CryptoProvider` 无法同时指定（E0191 / E0222）。单个 `SignatureProvider<PrivateKey = K>` 技术上可对象化，但与 ARCH §12 的静态分发方向不符 | `crates/rtx-crypto/src/lib.rs` 注释；本地编译验证 |

由此得到三条设计约束：

- 不需要新增算法枚举，也不需要修改 `rtx-crypto` 的 trait 签名；
- 需要的是一个**新的 provider 实现**，以及它自己的密钥句柄类型；
- 未完成审计前，`Unsupported` 必须保持为唯一行为。

## 2. 两案对比与推荐

### 2.1 候选方案

- **方案 A：并入现有 `rtx-crypto-rustcrypto`。** 以可选 feature 引入 `curve25519-dalek` / `ed25519-dalek`，在 `RustCryptoProvider` 上补齐 `SignatureProvider` 与 `KeyExchangeProvider`，并可能顺势实现 `CryptoProvider`。
- **方案 B：新增独立 crate `rtx-crypto-dalek`。** 只依赖 `rtx-crypto` 与 dalek，定义自己的 provider 类型与不透明句柄；`rtx-crypto-rustcrypto` 一行不改。
- **方案 C：在仓库内自行实现域运算。** 直接否决：等于把 dalek 已经审计多年的字段/标量算术重写一遍，审计成本远高于收益，且与“裸机可编译、常数时间可验证”的目标背道而驰。

> 说明：本设计的“独立 crate”指**新的 provider crate 仍复用 dalek**。如果把它理解为“完全不复用 dalek 的第三方实现”，那需要从零建立同等规模的审计证据，并重新适配 API / `no_std`；在同等证据强度下没有收益，因此不作为候选。

### 2.2 前提校正：不存在 `constant_time` feature

2026-10-26 从 crates.io API 取得的公开 feature 表：

| crate | 版本 | 公开 feature（节选） | 是否有 `constant_time` |
|---|---|---|---|
| `curve25519-dalek` | 4.1.3 | `alloc`、`default`、`group`、`group-bits`、`legacy_compatibility`、`precomputed-tables` | 否 |
| `curve25519-dalek` | 5.0.0 | `alloc`、`default`、`digest`、`group`、`legacy_compatibility`、`lizard`、`precomputed-tables`、`rand_core` | 否 |
| `ed25519-dalek` | 3.0.0 | `alloc`、`batch`、`default`（`fast` + `zeroize`）、`digest`、`hazmat`、`legacy_compatibility`、`pem`、`pkcs8`、`rand_core`、`serde`、`zeroize` | 否 |
| `x25519-dalek` | 3.0.0 | `default`（`precomputed-tables` + `zeroize`）、`getrandom`、`reusable_secrets`、`static_secrets`、`zeroize` | 否 |

`zeroize` 在部分版本里是可选依赖的隐式 feature，未单独列在上表中，但出现在 `default` 里；这正说明“能不能关掉”才是实际旋钮。

因此，方案 A 所说的“走 `curve25519-dalek` 的 `constant_time` feature”在 Cargo 里没有对应操作。可执行的动作是：

1. 锁定 dalek 主版本与补丁版本，审计记录绑定到具体版本；
2. `default-features = false`，只显式启用 `zeroize`；不启用 `alloc`、`getrandom`、`rand_core`、`hazmat`、`legacy_compatibility`、`batch`、`pkcs8`、`pem`、`serde`；
3. 只调用默认的恒时算术 API，禁止任何 `vartime_*` 入口；
4. 固定 target、opt-level、LTO、codegen-units 与编译器版本；
5. 用 dudect、ctgrind、反汇编与公开向量验证，而不是相信 feature 名称。

`precomputed-tables`（`ed25519-dalek` 的 `fast`）按 dalek 的设计不应改变“所有候选点都被常量时间选择”的语义，但会改变访问模式与代码体积，必须单独审计；在 MCU 上默认关闭，按实测再决定。

### 2.3 四个维度对比

| 维度 | 方案 A：并入 `rtx-crypto-rustcrypto` | 方案 B：独立 `rtx-crypto-dalek` |
|---|---|---|
| **常数时间性 / 审计面** | 使用同一份 dalek，但审计对象变成“已发布 crate + 新 feature”：7 条公开向量不受影响，11 条契约测试中的 `declined_suites_report_unsupported` 要按 feature 分叉；`RustCryptoProvider` 的能力随 feature 组合变化，审计证据与四个已实现套件混在一起。 | 审计对象只有新 crate 的薄封装 + 固定版本 dalek；`rtx-crypto-rustcrypto` 及其测试零改动；新 crate 可以有独立 CI job、独立审计报告与独立回滚单元。审计失败时整 crate 不启用，不会波及已验收的 Hash/HMAC/AEAD/Random。 |
| **`no_std` / `thumbv7em`** | dalek 本身可 `no_std`；但 `rtx-crypto-rustcrypto` 已经 `extern crate alloc`（HMAC 路径使用 `Vec`），其 `--no-default-features` 构建不能证明签名/KEX 路径零分配，需要额外断言。 | 新 crate 可以只开 `default-features = false` + `zeroize`，不启用 `alloc` / `std` / `getrandom` / `rand_core`。2026-10-26 已用 `rustc 1.92.0` 对 `thumbv7em-none-eabihf` 做 `cargo check`，`curve25519-dalek 5.0.0` + `ed25519-dalek 3.0.0` 在该 feature 面下编译通过；这是编译验证，不是硬件运行时验证。签名/KEX 路径可以单独设“零分配”门。 |
| **依赖树** | 给已发布 crate 增加 `curve25519-dalek 5.0` 与 `ed25519-dalek 3.0`；后者拉入 `sha2 0.11` / `digest 0.11`，与本仓库现有的 `sha2 0.10` / `digest 0.10` 并存（最小探针已复现 `sha2 v0.11.1` / `digest v0.11.3`）。所有使用 rustcrypto provider 的固件都会多背一份 dalek，除非再切 feature；`rtx-crypto` 的零依赖不受影响，但 feature 组合与编译时间变差。 | dalek 只出现在需要 Ed25519/X25519 的固件里；`rtx-crypto-rustcrypto` 继续停留在 `sha2 0.10` 等既有版本；`rtx-crypto` 仍然零运行时依赖。代价是：同时使用两套能力的 DTLS 固件最终仍会同时含 `sha2 0.10` 与 `0.11`，这是既有后端升级到 0.11 之前的已知重复，不是新 crate 新增的结构问题。 |
| **API 形态** | 可以在同一个 `RustCryptoProvider` 上补齐两个 trait，进而实现 `CryptoProvider`，集成最省事；但必须把现有 `SigningKey` / `ExchangeKey` 占位类型改造成生产句柄（去掉 `Copy`、明文 `Debug`、`PartialEq`），并处理 feature 开关下的 impl 分叉与能力矩阵变化。 | `DalekProvider` 实现同样两个 trait，句柄类型可独立设计；`CryptoProvider` 需要 DTLS 集成层把 `RustCryptoProvider` 与 `DalekProvider` 组合成一个具体 provider（ARCH §12 明确允许“protocols own a concrete provider handle”）。组合是少量样板代码，但职责边界清晰，单测与审计边界也清晰。 |

补充说明：

- `rtx-crypto` 的零依赖在两个方案下都不受污染；差别在于**谁**承担 dalek 依赖，以及**谁**的行为随 feature 改变。
- 方案 A 的“省事”只在最终确实采用“单一 RustCryptoProvider 同时提供六项能力”时成立；这会把一个已验收后端的签名行为从 `Unsupported` 变成“成功/失败”，属于能力语义变更，应该单独评审，而不是在一个 feature 开关里完成。
- 方案 B 的“组合样板”只在 DTLS 引擎第一次接入时付一次成本；之后硬件 provider、Linux provider 都可以按同样模式组合，属于一次性架构成本。
- X25519 不使用 `x25519-dalek` 的类型态封装：它的 `EphemeralSecret` / `StaticSecret` 确实能表达生命周期，但代价是无条件 `rand_core` 依赖与 `StaticSecret` 的 `AsRef<[u8]>` 导出面。若未来认为类型态收益大于依赖成本，需要把 `rand_core` 与 `static_secrets` 纳入同一份审计清单，而不是当作免费便利。

### 2.4 API 形态：为什么不另起 trait

“另起 trait”在这里指定义一个新的 `Ed25519Provider` / `X25519Provider` 之类的接口，而不是实现现有 trait。不可取的原因：

1. **引擎契约会被复制。** DTLS 引擎的泛型上界是六个能力 trait（`CryptoProvider` 的 supertrait 集）。新增一套并行 trait 会让引擎同时受两套抽象约束，或者被迫写适配器；这违背 ARCH §12 的“provider-neutral”而不是“provider-plural”。
2. **现有 trait 已经覆盖所需语义。** `SignatureProvider` 有算法枚举、私钥关联类型、调用方签名缓冲；`KeyExchangeProvider` 有生成、协商、私钥关联类型、调用方 secret 缓冲。Ed25519 / X25519 没有额外的方法需求。
3. **另起 trait 解决不了真正的缺口。** 真正的缺口是签名密钥的装载/生成入口、HSM 内部 KDF、能力查询；这些用现有 trait 的配套 inherent API 或未来扩展解决，另起一套 trait 只会把缺口复制两份。
4. **对象安全不会被改善。** `CryptoProvider` 不能 `dyn` 的根因是两个 supertrait 的同名关联类型；新 trait 同样会被关联类型污染，除非改成类型擦除接口，而那会违反 ARCH §12 的“不假设动态派发”。

结论：**实现现有 `SignatureProvider` / `KeyExchangeProvider`**；provider crate 可以用 inherent 方法暴露构造函数与能力表，但不新增能力 trait。

### 2.5 推荐

采用方案 B：

- 新建 `rtx-crypto-dalek`，只放 Ed25519/X25519 的 provider 实现与句柄；crate 名沿用 `rtx-crypto-<backend>` 的既有命名约定，而不是按算法拆名；
- 不修改 `rtx-crypto-rustcrypto`，其两个套件继续 `Unsupported`；
- 未来 DTLS 引擎组合 `RustCryptoProvider`（Hash/HMAC/AEAD/Random）与 `DalekProvider`（Sign/KEX），得到实现 `CryptoProvider` 的具体类型；
- 如果未来确认要合并为单一 provider，作为一次**显式的能力变更 PR** 处理：同时更新 m2 能力矩阵、`declined_suites_report_unsupported`、`_AssertCapabilities` 与覆盖率基线，而不是在本次工作中顺手做掉。

## 3. 常数时间审计清单

### 3.1 审计边界与数据分级

**在审计范围内：**

- `rtx-crypto-dalek` 的封装代码：密钥句柄、长度检查、错误映射、缓冲区写入顺序、随机数接入、零化；
- 锁定版本的 `curve25519-dalek` / `ed25519-dalek` 的 feature 组合与调用图；
- 目标三元组、编译器版本、opt-level、LTO、codegen-units、target-feature；
- 生成的机器码与运行时测量结果。

**不在审计范围内（但必须记录依赖）：**

- dalek 内部字段/标量算术的数学正确性与恒时性证明；本设计把它视为上游信任边界，审计只验证“我们只调用其恒时入口、feature 没有打开危险路径、编译产物没有引入新分支”；
- DTLS record 层的 AEAD nonce / 序号管理（由现有 `AeadProvider` 的调用方负责）；
- OS CSPRNG 或硬件熵源的随机性质量（只审计失败是否 fail-closed）。

**数据分级：**

| 数据 | 分类 | 允许的执行时间依赖 |
|---|---|---|
| Ed25519 seed、展开后的标量、`hash_prefix` | 秘密 | 只允许与秘密无关的固定时间 |
| Ed25519 公钥、签名、被签消息 / transcript | 公开 | 可依赖（长度公开） |
| X25519 私钥标量 | 秘密 | 只允许固定时间 |
| X25519 对端公钥、本端公钥、共享秘密的**长度** | 公开 | 可依赖 |
| X25519 共享秘密的**内容** | 秘密（但需导出给 KDF） | 只允许固定时间，尤其是全零检查 |
| 算法枚举、缓冲区长度、错误类型 | 公开 | 可依赖 |

审计的所有判断都基于这张表：**只有秘密数据禁止影响分支、内存访问地址、循环次数与错误返回时机；公开数据的可变时间行为是允许的。**

由此可直接得出一个常被误解的结论：**`verify` 不是恒时秘密路径。** 它处理的公钥、签名、消息都是公开数据，执行时间可以随输入变化；恒时要求集中在 `sign` 与 `agree`。`verify` 仍需满足的是“不触碰长期私钥、不 panic、失败不修改缓冲、错误码统一”，而不是“周期数恒定”。

### 3.2 逐项清单

#### A. 密钥处理

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| K-01 | 私钥句柄不得可复制或可导出 | 不实现 `Copy` / `Clone`；不提供 `AsRef<[u8]>`、`Deref`、`to_bytes`、`serde`；`Debug` 输出经过脱敏，不含密钥字节 | API 评审；`Debug` 输出断言；编译失败用例 |
| K-02 | 秘密在生命周期结束时被零化 | `zeroize` feature 在两个 dalek crate 上显式启用；seed、标量、展开密钥、共享秘密在 `Drop` 时零化；临时缓冲同样零化；零化写入不被优化掉 | 源码评审；反汇编确认写入存在；上游 `ZeroizeOnDrop` 实现记录 |
| K-03 | Ed25519 seed 与公钥保持派生关系 | 只从 32 字节 seed 派生 `SigningKey` 与其公钥；不接受“seed 与公钥分别传入”的接口，避免密钥替换/签名 oracle | API 评审；seed→公钥一致性测试 |
| K-04 | 秘密不进入日志、panic、错误消息 | 不对秘密调用 `Debug` / `Display`；不使用带秘密的 `unwrap` / `expect`；错误只返回 `CryptoError` | 源码评审；fuzz 覆盖 panic 路径 |
| K-05 | 密钥装载路径显式且可审计 | 只通过 provider 的显式构造函数装载 32 字节 seed，或由 HSM provider 返回句柄；seed 来源必须是 `RandomProvider` / 安全元件 RNG，不得使用固定种子、时间戳或 `for_tests` 常量；不使用全局/静态密钥；不启用 `static_secrets` | API 评审；集成层配置评审；故障 RNG 测试；生产构建不含 `for_tests` |
| K-06 | 句柄生命周期与握手绑定 | X25519 临时密钥每个 key share / 每次密钥交换一份，不缓存、不复用；`Drop` 释放/零化；Ed25519 长期密钥可跨握手，但 `sign` 无状态且不复制句柄 | 生命周期测试；两次握手句柄不复用测试 |

#### B. Nonce / 随机数 / 密钥生成

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| N-01 | X25519 密钥生成必须使用显式熵源 | 软件 provider 的 `generate_key` 通过 `RandomProvider::fill_random` 取恰好 32 字节；HSM provider 使用安全元件内部熵源；两者在熵源失败时都必须原样向上传播 `Unsupported` / `BackendFailure`，不得写出公钥、不得返回句柄，不得回退到固定值、时间戳或弱随机 | 注入失败 RNG 的故障测试；哨兵缓冲测试；HSM 失败注入测试 |
| N-02 | 每次密钥交换使用全新临时密钥 | 每个 key share 的 `generate_key` 产生新的私钥/公钥（在 RNG 正常时）；不存在跨握手或跨 key share 的密钥缓存或池化 | 生成测试；句柄生命周期评审 |
| N-03 | Ed25519 签名是确定性的，不依赖 RNG | 不启用 `rand_core`；同一 seed + 同一消息两次签名逐字节相等；如果未来引入 hedged signing，必须显式接收 RNG 并重新审计 | feature 依赖树；重复签名测试 |
| N-04 | AEAD nonce 不由本 provider 生成 | DTLS record 序号/nonce 由引擎管理；本 provider 不提供“生成 nonce”接口，也不缓存 nonce | 接口评审；与 `AeadProvider` 的边界说明 |
| N-05 | 失败路径不泄漏未初始化字节 | 输出缓冲在写入前完成长度检查；成功时只写 32/64 字节；失败时缓冲逐字节不变 | 哨兵缓冲契约测试 |

**术语澄清：** 本设计里的“nonce”分三种：Ed25519 签名随机数（确定性派生）、X25519 临时密钥随机性（显式熵源）、AEAD record nonce（引擎负责）。三者不能混在一个审计项里；本 provider 只涉及前两种。

#### C. 标量乘与点运算

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| S-01 | 秘密路径只调用恒时 API | 允许：`EdwardsPoint::mul_base`、`Scalar * EdwardsPoint`、`MontgomeryPoint::mul_clamped`、`MontgomeryPoint::mul_base_clamped`；禁止在秘密操作数上使用任何 `vartime_*`、`mul_bits_be`、变时间双标量乘。`verify` 的公开数据路径可以使用 dalek 的变时间双标量乘（`vartime_double_scalar_mul_basepoint`），但不得把它引入 `sign`/`agree` | 调用图评审；`cargo asm` / 反汇编；源码检索 |
| S-02 | clamp 由 dalek 完成，不手写位操作 | 原始 32 字节直接交给 `mul_clamped` / `mul_base_clamped`；不自行实现 clamp、模约减或位掩码；RFC 8032 §5.1.5 与 RFC 7748 §5 的位模式由向量验证 | RFC 向量；源码评审 |
| S-03 | 迭代次数固定，无秘密相关提前退出 | Ed25519 基点点乘、X25519 Montgomery ladder 的循环次数不随标量前导零/汉明重量变化；不做“标量小就少算”的优化 | 反汇编；dudect；上游实现记录 |
| S-04 | 表查找是恒时选择，不是秘密索引 | 基点点乘若启用预计算表，必须读取全部候选并用条件选择；默认不启用 `precomputed-tables` / `fast`；在 Cortex-M7 的 D-cache 下单独评估访问模式 | 源码评审；反汇编；目标板 cache/cycle 测量 |
| S-05 | X25519 输入侧遵循 RFC 7748，不做多余拒绝 | 恰好 32 字节即可；最高位按 RFC 7748 §5 屏蔽；必须接受非规范编码并按模 `p` 处理；不得在输入侧建立低阶点黑名单（低阶点通过输出全零检查处理） | RFC 7748 §5/§6.1；Wycheproof 非规范/低阶向量 |
| S-06 | 共享秘密全零检查必须恒时 | 对完整 32 字节做常量时间或运算/`ct_eq`，不得用 `==` 或提前返回；全零时返回 `InvalidKey` 并中止握手，且不产生可用 secret。检查必须在写入 `secret_out` 之前完成：先在会被零化的临时缓冲中计算，检查通过后再复制给调用方；失败时调用方缓冲保持不变 | 全零/低阶点测试；哨兵缓冲测试；dudect；RFC 8422 §5.11 / RFC 8446 §7.4.2 |
| S-07 | 无秘密相关内存索引 | 封装层不以私钥/标量字节作为数组下标、切片边界或分支条件；dalek 内部表访问另行评审 | ctgrind；反汇编；源码评审 |
| S-08 | 点解码失败路径恒定 | Ed25519 公钥/R 解码使用常数时间 `CtOption` 语义；失败统一映射，不在解码过程中提前泄露“哪一位失败”；`verify_strict` 拒绝小阶公钥 R/A 与非规范 R | 源码评审；Wycheproof 边界向量 |

#### D. 签名随机数

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| R-01 | Ed25519 的 `r` 是确定性派生 | `r = SHA-512(hash_prefix ‖ M)`；`hash_prefix` 来自 seed 的展开；SHA-512 的执行时间只与输入长度有关，不与内容有关；不得替换为 RNG 生成的 `r` | 源码评审；同消息两次签名相等；dudect |
| R-02 | 64 字节哈希到标量的约减是恒时的 | 使用 dalek 的 `Scalar::from_hash` / 宽约减路径；不自写模 `L` 约减；不引入秘密相关分支 | 源码评审；dudect |
| R-03 | 不引入未审计的 hedged / randomized 签名 | 默认确定性签名；若未来为抗故障攻击引入 hedged signing，必须显式接收 RNG、定义失败语义并重新执行本清单 | API/feature 评审；变更记录 |
| R-04 | 消息/transcript 的处理不依赖秘密 | 消息按完整字节流一次性喂入；transcript 长度是公开信息；不按秘密条件分段或跳过 | 接口评审；握手场景测试 |
| R-05 | `sign` 先校验缓冲再触碰秘密 | 输出小于 64 字节时直接 `OutputTooSmall`，不展开密钥、不做标量乘；失败时输出缓冲不变 | 哨兵缓冲测试；源码评审 |

#### E. 失败路径是否恒时

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| F-01 | 错误返回时机不依赖秘密 | 对秘密内容不同的输入（不同标量、全零/非零共享秘密），从进入到返回的路径长度与分支序列一致；公开数据（长度、算法、公钥格式）导致的早退允许 | dudect；反汇编；源码评审 |
| F-02 | 允许公开早退，禁止秘密早退 | 对 `sign` / `agree`：长度不符、算法不支持可以在进入密码运算前返回；合法的 32 字节 KEX 输入必须完成固定工作量；不得按秘密字节提前返回。`verify` 的公开数据路径允许变时间，但不得触碰长期私钥，也不得把变时间逻辑复用到 `sign` | 数据分级对照；反汇编 |
| F-03 | 验签失败只有一个错误码 | 公钥长度/解码失败 → `InvalidKey`；签名长度/验证失败/小阶公钥等 → `InvalidSignature`；不区分“R 错”“S 错”“弱公钥”到不同错误码 | 负向向量测试；错误映射表 |
| F-04 | 失败不修改调用方缓冲 | 所有长度检查在任何写入之前；失败后输出缓冲逐字节与调用前一致 | 契约测试（沿用现有后端模式） |
| F-05 | 不可信输入不触发 panic | 任意长度/内容的公钥、签名、消息都不导致 panic；release `panic = "abort"` 下 panic 等于进程终止，属于 DoS | fuzz；`unwrap`/索引评审 |
| F-06 | 失败路径同样零化临时秘密 | 全零共享秘密、验签失败、缓冲不足等路径上，已产生的临时标量/展开密钥/共享秘密都要零化；不能因为“要报错”就跳过清理 | 源码评审；反汇编 |
| F-07 | HSM 错误不泄露细节 | 硬件 provider 的细粒度错误统一映射为 `BackendFailure`；不把槽位号、密钥 ID、认证失败原因写进日志或返回给对端 | HSM provider 接口评审 |
| F-08 | DTLS alert 映射不引入秘密侧信道 | 全零/无效公钥 → `InvalidKey` → 握手中止；验签失败 → `InvalidSignature` → `decrypt_error` 类告警；不因秘密内容选择不同告警；失败后不复用该临时密钥 | 引擎集成测试；告警映射表 |

#### F. 构建、依赖与测试证据

| ID | 审计点 | 通过标准 | 证据 |
|---|---|---|---|
| C-01 | 版本固定且 MSRV 匹配 | 实现时锁定 `curve25519-dalek 5.0.x` / `ed25519-dalek 3.0.x`（MSRV 均为 1.85，与 workspace 一致）；审计报告记录精确版本与 checksum；升级主版本必须重跑本清单 | 清单/锁文件；`cargo tree` |
| C-02 | feature 面收紧 | 关闭 `alloc`、`getrandom`、`rand_core`、`hazmat`、`legacy_compatibility`、`batch`、`pkcs8`、`pem`、`serde`、`fast` / `precomputed-tables`（后者按目标实测再定）；显式启用 `zeroize` | `cargo tree -e features`；CI 断言 |
| C-03 | 本 crate 禁止 unsafe | `unsafe_code = "forbid"` 继续生效；依赖中的 unsafe 单独清点（dalek 在 x86_64 SIMD 后端有 unsafe，`thumbv7em` 不编译该后端）；不为“优化”在本 crate 引入 unsafe | `cargo geiger`；目标三元组检查 |
| C-04 | 编译选项固定 | 审计绑定到具体 rustc、opt-level、LTO、codegen-units、target-feature；MCU 不使用 `target-cpu=native`；任何选项变化都视为审计失效，重跑 dudect/反汇编 | 审计记录；CI 构建参数 |
| C-05 | 裸机编译门禁 | `cargo check --no-default-features --target thumbv7em-none-eabihf` 通过；不启用 `alloc`；不依赖 OS RNG | CI job；本地探针记录 |
| C-06 | `rtx-crypto` 保持零依赖 | 新 crate 不把 dalek 依赖反向引入 `rtx-crypto`；`cargo tree -p rtx-crypto` 的运行时依赖仍为空 | CI/人工检查 |
| T-01 | 公开向量 | RFC 8032 §7.1（TEST 1/2/3/1024）、RFC 7748 §5.2（两组标量乘 + 1/1,000 次迭代）、§6.1（Alice/Bob DH）全部逐字节通过 | 测试报告 |
| T-02 | 负向/边界向量 | Wycheproof `testvectors_v1/ed25519_test.json` 与 `x25519_test.json` 中的非规范编码、低阶点、`S >= L`、弱公钥、截断输入全部按预期拒绝或接受 | 测试报告 |
| T-03 | dudect | 至少对 Ed25519 `sign`、X25519 `agree`、全零检查各建一个测量；有阳性对照（故意泄漏的基线必须被检出）；阈值、样本量、目标硬件、运行次数记录在审计报告 | 审计报告 |
| T-04 | ctgrind / valgrind | 在宿主机上把秘密标记为未定义，运行 `sign`/`agree`；不得出现“条件跳转依赖未初始化值”或“地址依赖未初始化值” | 审计报告 |
| T-05 | 反汇编 | 归档审计版本的反汇编，确认秘密路径无 `vartime` 调用、无秘密相关分支/索引；`thumbv7em` 与宿主机分别抽查 | 审计报告附件 |
| T-06 | fuzz | 任意 32/64 字节公钥/签名输入不 panic、不越界、不分配；失败路径返回稳定错误码 | fuzz 语料/报告 |
| T-07 | 差分测试 | 与至少一个独立实现（OpenSSL 3.x 或 libsodium）对随机输入做 X25519/Ed25519 差分；宿主机运行，不作为目标板结论 | 测试报告 |

### 3.3 测试如何发现非常数时间行为

功能测试和公开向量**发现不了**恒时性问题：一个用提前返回（early-return）比较共享秘密的实现可以通过全部 RFC 向量。必须用下面几类方法，并且每类都要有“阳性对照”：

1. **dudect 统计测量。**
   - 构造两类秘密输入：例如两个汉明重量差异明显的 X25519 私钥标量、两个不同的 Ed25519 seed、全零与非零共享秘密。
   - 在固定频率、固定 CPU/开发板上测量每次操作的周期数，随机交错输入顺序，采集足够样本（至少数万次，按噪声调整）。
   - 用 Welch t 检验比较两类分布；阈值不能照搬论文，必须在阳性对照上校准。
   - **阳性对照**：故意实现一个按秘密字节提前返回的基线（例如共享秘密比较），测量工具必须能检出它；否则工具本身无效。
   - 局限：统计测量对编译器、频率缩放、中断、缓存噪声敏感；共享 CI runner 上不可靠，应放在专用机器/目标板夜间跑，PR 只跑冒烟版。

2. **ctgrind / valgrind 动态污点。**
   - 在宿主机 x86_64 上把 seed/标量/共享秘密标记为“未定义”，运行 `sign` / `agree`。
   - 任何基于秘密的条件跳转或内存地址都会报告为“Conditional jump or move depends on uninitialised value”或“Use of uninitialised value”。
   - 局限：只覆盖宿主机指令集，不能代替 `thumbv7em` 的编译产物审计；对缓存时序不敏感。

3. **反汇编与源码结构检查。**
   - 对审计版本的 `sign` / `agree` / 全零检查做 `cargo asm` 或 `objdump`，确认没有 `vartime` 调用、没有秘密相关分支/表索引。
   - 检查编译器没有把常量时间选择优化成按秘密分支；Thumb-2 的条件执行/`it` 块要人工确认。
   - 这是唯一能直接覆盖目标指令集的结构性证据；必须与版本、rustc、opt-level 一起归档。

4. **缓存/内存访问测量。**
   - Cortex-M7 有 D-cache；若启用预计算表，必须确认每次都读取全部候选（输入无关的访问集合），否则用 cache 冲突/周期测量单独验证。
   - 在 M4（无 D-cache）与 M7（有 D-cache）上的结论不能互相替代。

5. **故障注入（非时序，但同属侧信道）。**
   - Ed25519 确定性签名在故障攻击下可能泄露密钥；如果产品威胁模型包含故障注入，需要额外的 hedged signing 或硬件防护。本设计默认不引入 hedged signing，但要把这一风险写进威胁模型，而不是假装不存在。

6. **差分与性质测试。**
   - 用于证明“功能正确、边界处理正确”，不能证明恒时；与上述方法互补。

### 3.4 审计底线

- **一项不通过，对应算法保持 `Unsupported`。** 不允许“先启用 `sign`、审计下周补”；不允许把 `Unsupported` 改成 `BackendFailure` 来“看起来像已实现”。
- **审计结论必须绑定目标。** x86_64 上的 dudect/ctgrind 通过，不等于 `thumbv7em` 通过；目标板必须有反汇编 + 周期测量证据。
- **任一项输入变化都视为审计失效。** dalek 版本、feature 组合、rustc 版本、opt-level、LTO、target-feature、封装层代码发生变化，必须重跑对应项。
- **审计报告是发布门禁，不是文档附件。** 报告必须记录日期、commit、工具版本、阳性对照结果、未通过项与处置；没有签字就不启用。
- **不以“握手能跑通”作为通过标准。** 握手成功只证明功能路径，不证明常数时间；静默错误的握手比明确拒绝更糟。

## 4. 与 DTLS 引擎的接口约定

> 说明：本仓库当前没有 DTLS 引擎 crate；以下是接口约定，供后续 `rtx-dtls` 实现使用。

### 4.1 握手时序中的调用点

| 握手阶段 | provider 调用 | 数据分类 | 备注 |
|---|---|---|---|
| ClientHello / ServerHello | 无 | — | `client_random` / `server_random` 由引擎的 `RandomProvider` 产生；失败即中止 |
| ECDHE 密钥交换（DTLS 1.2 的 ServerKeyExchange / ClientKeyExchange；DTLS 1.3 的 KeyShare） | `generate_key(X25519, public_out)` | 公钥公开、私钥秘密 | 每握手新密钥；输出恰好 32 字节 |
| 收到对端 ECDHE 公钥 | `agree(X25519, own_handle, peer_public, secret_out)` | 对端公钥公开、共享秘密秘密 | 全零 → `InvalidKey` → 中止；输出 32 字节原始值，不做额外哈希 |
| 本端签名（DTLS 1.2 的 ServerKeyExchange 签名；DTLS 1.3 的 CertificateVerify） | `sign(Ed25519, key_handle, signed_bytes, sig_out)` | 长期私钥秘密、被签名字节公开 | 输出 64 字节；确定性签名；被签名内容的编码由引擎按协议版本构造 |
| 验证对端签名（DTLS 1.2 的 ServerKeyExchange 签名 / CertificateVerify；DTLS 1.3 的 CertificateVerify） | `verify(Ed25519, peer_public, signed_bytes, sig)` | 全公开 | 使用严格验签；失败 → `InvalidSignature` |
| 密钥调度 | 不经过本 provider | — | HKDF 走现有 `HmacProvider`；共享秘密在引擎内零化 |
| record 层 | 不经过本 provider | — | AEAD 走现有 `AeadProvider`；nonce/序号由引擎管理 |

协议依据：DTLS 1.2 使用 RFC 6347 的握手，X25519 组与 Ed25519 签名按 RFC 8422 §5.1.1 / §5.1.3 / §5.4 / §5.8；RFC 8422 §5.11 明确要求 X25519 共享秘密全零时中止。DTLS 1.3（RFC 9147）沿用 TLS 1.3 的 X25519 与 Ed25519 语义，见 RFC 8446 §4.2.3、§4.2.8.2、§7.4.2。provider 不区分 DTLS 版本，版本差异由引擎处理。

范围边界：X.509 解析、证书链验证、名称匹配、`signature_algorithms_cert` 策略都不在本 provider；`verify` 只验证“给定公钥字节 + 给定签名字节 + 给定消息”的 Ed25519 签名。把这些职责塞进 provider 会把审计面扩大到解析器与策略层。

### 4.2 密钥句柄与 HSM / 安全元件

- `SignatureProvider::PrivateKey` 与 `KeyExchangeProvider::PrivateKey` 是关联类型，对泛型引擎完全不透明：引擎只能把 `&P::PrivateKey` 原样传回 provider，无法读取、复制或比较。
- **Ed25519 长期密钥可以留在 HSM/安全元件内。** 句柄可以是槽位号、密钥 ID 或会话句柄；`sign` 在安全元件内完成，只有 64 字节签名离开。provider crate 不应提供任何导出私钥字节的方法。
- **X25519 私钥标量也可以留在 HSM/安全元件内。** `generate_key` 只导出 32 字节公钥并返回句柄；`agree` 在安全元件内做标量乘。但 `agree` 按 trait 契约必须把 32 字节共享秘密写到调用方缓冲：这是 TLS 密钥调度的必要输入，无法避免。若安全策略要求“共享秘密也不得出安全元件”，当前 trait 形态不支持（需要 HSM 内部完成 HKDF），应作为未来扩展单独设计，不能在本 provider 里偷偷实现。
- **句柄必须不可复制、不可打印、可销毁。** 软件 provider 的句柄持有 seed/标量并在 `Drop` 零化；HSM provider 的句柄在 `Drop` 释放会话/槽位。两者都不实现 `Copy`/`Clone`，`Debug` 只打印类型名或固定占位符。
- **一个句柄只服务一次密钥交换。** X25519 临时句柄对应一个 key share，握手结束（成功或失败）后销毁，不复用；若 DTLS 1.3 客户端一次发送多个 key share，则每个 share 一个独立句柄；Ed25519 长期句柄可以跨握手，但 `sign` 不改变其状态。
- **`&self` 与内部可变性。** provider trait 的方法是 `&self`；HSM provider 若需要可变会话状态，应在句柄内部使用受限的内部可变性（如单线程会话对象），而不是要求引擎改成 `&mut`。trait 本身没有 `Send` / `Sync` bound，引擎按单线程 Sans-I/O 模型使用。

### 4.3 错误、缓冲与能力协商契约

| 场景 | 返回 | 引擎动作 |
|---|---|---|
| 算法不在 provider 能力集 | `Unsupported` | 视为“该算法不可用”，在协商阶段排除；不得当作内部错误重试同一算法 |
| 公钥长度不是 32 字节 / Ed25519 公钥无法解码 | `InvalidKey` | 中止握手；不区分具体解码失败位置 |
| X25519 共享秘密全零 | `InvalidKey` | 中止握手；销毁临时句柄；不得用全零 secret 继续密钥调度 |
| 签名长度不是 64 字节 / 验签失败 / 小阶公钥 | `InvalidSignature` | 中止握手；映射到证书/签名类告警 |
| 输出缓冲不足 | `OutputTooSmall` | 调用方编程错误；不得截断输出后继续 |
| 熵源不可用 | `RandomProvider` 返回 `Unsupported` 或 `BackendFailure` | 中止握手；不得回退到弱随机 |
| HSM 内部失败 | `BackendFailure` | 中止握手；日志只记录“后端失败”，不记录槽位/密钥细节 |

缓冲契约：

- 全部输出由调用方提供，provider 不分配、不返回 `Vec`、不持有调用方缓冲；
- Ed25519 签名 64 字节、公钥 32 字节；X25519 公钥 32 字节、共享秘密 32 字节；
- 长度检查先于任何写入；失败时缓冲逐字节不变；
- 不静默截断、不把短缓冲补零后返回成功。

能力协商：

- 现有 trait 没有 `supports(algorithm)` 查询；DTLS 引擎在构造 `signature_algorithms` / `supported_groups` 扩展前必须知道 provider 能力。
- 约定：provider crate 以 inherent 常量或方法导出能力表；集成层用它生成扩展，运行时 `Unsupported` 只作为防御性校验。不要靠“试一次失败再换”来协商，因为那会在握手中暴露不确定性。
- `CryptoProvider::name()` 只用于标识/日志，不承担能力查询。

随机数接入：

- `KeyExchangeProvider::generate_key` 的签名里没有 RNG 参数，因此软件 provider 实现必须在构造时持有熵源（例如泛型参数 `R: RandomProvider`，或以引用/句柄持有）；HSM provider 使用安全元件内部熵源。这是实现层约定，不需要改 trait。
- Ed25519 `sign` 不需要 RNG；不要为了“统一接口”强行注入 RNG，否则会把确定性签名变成未审计的随机化路径。

### 4.4 与 ARCH §12 的逐条对照

| ARCH §12 要求 | 本设计如何满足 |
|---|---|
| provider-neutral | 实现现有六个能力 trait 中的两个；不新增并行 trait；引擎只依赖 trait，不依赖 dalek 类型 |
| 边界无分配要求 | 新 crate 不启用 `alloc`；签名/KEX 路径只使用调用方缓冲与栈上临时值；实现阶段用计数分配器验证 |
| 原地 AEAD | 不属于本 provider；现有 `AeadProvider` 已满足 |
| 调用方输出缓冲 | `public_key_out` / `secret_out` / `signature_out` 全部由调用方提供；失败不改缓冲 |
| 私钥不透明句柄、可留在 HSM/安全元件 | 关联类型 + 不透明句柄契约；Ed25519 可全程在 HSM 内；X25519 私钥可留在 HSM，共享秘密按 trait 契约导出 |
| 不假设动态派发或引用计数 | 引擎以 `P: CryptoProvider` 或两个 trait 的泛型上界静态分发；不使用 `dyn CryptoProvider`；Linux 适配层若需要 `Arc`，只包裹对象安全的四个能力 trait，或包裹具体 provider 类型 |

### 4.5 现有 trait 的接口缺口（只记录，不在本 PR 修改）

| 缺口 | 影响 | 当前处置 | 未来方向 |
|---|---|---|---|
| `SignatureProvider` 没有签名密钥的生成/装载入口 | 长期密钥只能由 provider inherent API 或 HSM 提供；引擎无法泛型地“创建签名密钥” | 集成层构造句柄后注入；provider crate 提供显式构造函数 | 未来可增加独立的密钥管理 trait；本次不改 |
| 没有能力查询 | 引擎生成扩展前无法泛型获知支持集 | provider crate 导出能力常量/方法；运行时 `Unsupported` 防御 | 未来可在 trait 增加 `supports`，需评估对象安全 |
| `CryptoProvider` 不能 `dyn` | 无法在引擎内做运行时 provider 切换 | 静态分发；集成层持有具体类型 | 保持 ARCH §12 现状，不引入 `dyn` |
| `agree` 必须导出共享秘密 | HSM 无法独立完成 HKDF | 接受；DTLS 密钥调度本就在引擎内 | 若未来有“密钥不出安全元件”的硬要求，另设 HSM-HKDF trait |
| `sign` 无 RNG 参数 | hedged signing 无法接入 | 默认确定性签名 | 若威胁模型要求抗故障，另加带 RNG 的签名方法并重审 |
| trait 未规定 `Drop`/零化 | provider 可能忘记清理 | 在 provider 契约与审计清单中强制 | 文档约束即可，暂不改 trait |

## 5. 实现阶段划分

> 本节只定义阶段与验收，不包含实现代码。

| 阶段 | 范围 | 启用算法 | 验收向量 / 证据 | 退出标准 |
|---|---|---|---|---|
| P0：设计冻结 | 本文件；锁定 dalek 版本、feature 面、目标三元组、编译器；写威胁模型与审计报告模板 | 无 | 版本/feature 快照；`cargo tree -e features` | 本设计评审通过；未改任何代码 |
| P1：X25519 KEX | `generate_key` + `agree`；不透明句柄；RNG 接入；全零检查 | 仅 `KeyExchangeAlgorithm::X25519` | RFC 7748 §5.2 两组标量乘；§5.2 的 1 次与 1,000 次迭代（1,000,000 次放夜间）；§6.1 Alice/Bob DH；Wycheproof `x25519_test.json`；RFC 7748 §5 非规范编码/高位屏蔽 | 向量全过；`thumbv7em` 无 alloc 编译；契约测试（失败不改缓冲、长度检查、全零）；dudect 冒烟 |
| P2：Ed25519 verify | 只做验签；严格验签；公钥/签名长度与解码边界 | 仅 `SignatureAlgorithm::Ed25519` | RFC 8032 §7.1 TEST 1/2/3/1024；Wycheproof `ed25519_test.json` 的非规范 R、`S >= L`、小阶公钥；RFC 8032 §5.1.7 | 向量全过；负向用例全拒绝；无 alloc；`thumbv7em` 编译；无 panic |
| P3：Ed25519 sign | 不透明长期句柄；确定性 nonce；零化；签名密钥装载路径 | 仅 `SignatureAlgorithm::Ed25519` | RFC 8032 §7.1 的种子/公钥/签名逐字节一致；§5.1.5/§5.1.6；重复签名一致；tamper 检测 | 向量全过；句柄不可复制/不可打印；失败不改缓冲；dudect sign 测量通过 |
| P4：恒时审计签字 | 执行 §3 全部清单；目标板 dudect + 反汇编；宿主机 ctgrind；feature/编译器快照 | 已实现的两个算法 | §3.3 全部证据；审计报告 | 所有项通过并有证据；未通过项对应算法必须回退为 `Unsupported`，不得发布；审计报告归档 |
| P5：DTLS 集成 | 组合 provider；握手中的 ECDHE / ServerKeyExchange 签名 / CertificateVerify；告警映射；HSM mock | X25519 + Ed25519 | 握手场景测试（参考现有 `crates/rtx-crypto/tests/handshake_scenarios.rs` 的 DH → transcript 签名 → 派生 → record 顺序）；与独立实现互操作 | 端到端握手通过；失败路径告警正确；临时密钥销毁；不改变 `rtx-crypto-rustcrypto` |

顺序理由：

- **X25519 先做。** ECDHE 是任何 DTLS 握手的必需项；它只有 Montgomery ladder + 全零检查，秘密路径比 Ed25519 签名短，适合先建立句柄、RNG、缓冲契约与测试脚手架。
- **verify 先于 sign。** 验签只处理公开数据，失败路径的恒时要求最低；先把解析/边界/负向向量做扎实，再进入真正的秘密路径。
- **sign 最后做。** 它同时涉及 seed 展开、确定性 nonce、标量乘、零化与长期密钥生命周期，是审计面最大的一步。
- **审计签字在集成之前。** 不允许带着未审计的 sign/agree 进入 DTLS 集成；否则集成测试会把“能握手”误当成“可发布”。
- **集成放最后。** DTLS 引擎尚不存在；本设计不为它预先写代码。

每阶段红线：

- 未实现的算法必须继续返回 `Unsupported`，包括同一 trait 内的其他枚举值（ECDSA P-256/P-384、X25519 之外的 P-256/P-384）。
- 不得用“功能测试全过”替代 P4；不得把 P4 拆成“上线后补”。
- 不得在 P1/P2/P3 期间顺手修改 `rtx-crypto-rustcrypto`；如果需要组合 provider，放在 P5 或独立 PR。

验收向量来源汇总：

| 来源 | 用途 | 覆盖阶段 |
|---|---|---|
| RFC 8032 §5.1.5 / §5.1.6 / §5.1.7 / §7.1 | Ed25519 密钥生成、签名、验签、TEST 1/2/3/1024 | P2、P3 |
| RFC 7748 §5 / §5.2 / §6.1 | X25519 编码规则、标量乘向量、DH 向量、全零检查 | P1、P4 |
| Wycheproof `testvectors_v1/ed25519_test.json` | Ed25519 非规范 R、`S >= L`、小阶/弱公钥、截断 | P2、P3 |
| Wycheproof `testvectors_v1/x25519_test.json` | X25519 非规范编码、低阶点、全零输出 | P1 |
| RFC 8422 §5.11 / RFC 8446 §7.4.2 | 协议层“全零共享秘密必须中止” | P5 |
| OpenSSL 3.x / libsodium | 宿主机差分测试（非规范来源） | P1、P2、P3 |

## 6. 风险与开放问题

| 问题 | 当前判断 | 需要在何时决定 |
|---|---|---|
| `curve25519-dalek 5.0.0` / `ed25519-dalek 3.0.0` 版本较新且本仓库尚无生产部署记录 | 两者 MSRV 均为 1.85，与本仓库一致，且已在 `thumbv7em` 编译通过；实现时锁定补丁版本并记录上游审计。若出现回归，回退 4.1.3 + 2.1.x，接口面不变。4.1.3 / 2.1.x 是更保守的备选，不是当前首选 | P0 |
| `fast` / `precomputed-tables` 在 MCU 上的取舍 | 默认关闭以控制 flash 与审计面；若握手延迟不达标，再按实测启用并补表访问审计 | P1 完成后 |
| 同时存在 `sha2 0.10` 与 `0.11` | 接受为既有后端的迁移债；不因本 provider 强行升级现有 HMAC/AEAD 栈 | P0 记录，独立迁移 PR |
| `verify` 与 `verify_strict` 的互操作 | 默认 `verify_strict`；若真实对端出现只被 `verify` 接受的合法签名，必须记录具体向量并单独评审，不静默降级 | P2 |
| 确定性 Ed25519 的故障注入风险 | 默认确定性；若产品威胁模型包含故障注入，追加 hedged signing 或硬件防护，并重跑审计 | 威胁建模时 |
| HSM 内部 HKDF | 当前 trait 不支持；DTLS-SRTP 场景可接受共享秘密导出 | P5 前确认产品策略 |
| 审计工具在共享 CI 上不稳定 | dudect 不作为 PR 必过门禁；PR 跑确定性向量/编译/反汇编抽查，统计测量放专用机器夜间跑 | P4 |
| 仓库未提交 `Cargo.lock` | 固件构建需要可复现的依赖版本；至少在发布构建中锁定 lockfile 或记录 checksum | P0 |

## 7. 验收与证据记录

- 本 PR 的 diff 只包含本文件；`git diff --stat` 应只有 `docs/ed25519-x25519-provider-design.md` 一条文件记录。
- 未修改 `rtx-crypto`、`rtx-crypto-rustcrypto`、任何 `Cargo.toml`、CI 配置或测试。
- 文中引用的 trait / crate / 章节与仓库现状一致：
  - `rtx-crypto`：`RandomProvider`、`HashProvider`、`HmacProvider`、`AeadProvider`、`SignatureProvider`、`KeyExchangeProvider`、`CryptoProvider`；
  - `SignatureAlgorithm::Ed25519`、`KeyExchangeAlgorithm::X25519`；
  - `rtx-crypto-rustcrypto` 的 `RustCryptoProvider`、`SigningKey`、`ExchangeKey`、`_AssertCapabilities`；
  - `docs/m2-crypto-backend.md` §2.2（能力矩阵与“故意留空”）、§6（下一步）；
  - `docs/progress-report.md` §7 第 2 项；
  - `ARCHITECTURE.md` §12（Crypto model）。
- 版本与编译探针记录（2026-10-26）：
  - `rustc 1.92.0`，target `thumbv7em-none-eabihf`；
  - `curve25519-dalek 5.0.0`（`default-features = false`，仅 `zeroize`）+ `ed25519-dalek 3.0.0`（`default-features = false`，仅 `zeroize`）；
  - `cargo check --target thumbv7em-none-eabihf` 通过；依赖树无 `rand_core` / `getrandom`；`ed25519-dalek` 拉入 `sha2 0.11.1` / `digest 0.11.3`；
  - 探针使用 rustc 1.92.0；workspace MSRV 1.85 的构建仍需在 CI 的 `msrv` job 上单独验证；
  - 该结果只证明“可编译”，不证明目标板运行时行为；P4 仍需硬件测量。
- 参考规范：
  - RFC 8032 §5.1.5 / §5.1.6 / §5.1.7 / §7.1；
  - RFC 7748 §5 / §5.2 / §6.1 / §7；
  - RFC 8422 §5.1.1 / §5.1.3 / §5.8 / §5.11；
  - RFC 8446 §4.2.3 / §4.2.8.2 / §7.4.2；
  - RFC 9147（DTLS 1.3）；
  - Project Wycheproof `testvectors_v1/ed25519_test.json`、`testvectors_v1/x25519_test.json`。
