# RTX M0 契约冻结测试设计文档

| 项 | 内容 |
|---|---|
| 文档类型 | 测试设计（仅设计，不含测试代码，不改任何 `src/` 与 `Cargo.toml`） |
| 里程碑 | M0 — foundation（契约冻结） |
| 覆盖对象 | `rtx-core` / `rtx-buffer` / `rtx-wire` / `rtx-crypto` 四个 crate 的全部公开 API |
| 作者 | QA 工程师 严过关（Yan） |
| 派发 | 主理人 齐活林，团队 `software-rtx-m0` |
| 权威依据 | `ARCHITECTURE.md`（§7–§12、§18、§20）、四个 crate 的 `src/lib.rs` 与 `Cargo.toml`、`DEPENDENCY_AUDIT.md` |
| 状态 | 已架构审阅（CONDITIONAL PASS）并按审阅报告完成修订；工程师（Alex）已实现，Round 1 验证通过 |

---

## 1. 测试目标与范围

### 1.1 目标

验证 M0 阶段四个基础 crate 的**契约冻结**：时间模型、地址模型、Buffer 契约、Wire-codec 契约、Crypto provider 契约与 §20 退出条件（`ARCHITECTURE.md:478-485`）。本测试集是 M1 协议编解码（RTP/RTCP/STUN/QUIC/H3）之前的质量基座：契约若在此处漂移，上层全部继承错误。

### 1.2 范围内

1. 四个 crate 的**每一个公开 API 项**（类型 / trait / 方法）至少一个测试用例（见 §3 覆盖矩阵）。
2. 行为维度：正常路径、边界值（`u64::MAX`、容量恰恰好、空输入）、错误路径（错误码与"错误无副作用"）、编译期契约（GAT、生命周期、const fn、supertrait）、属性行为（Ord/Hash/Copy/往返守恒）。
3. 工程维度：`no_std` 编译（宿主 + 可选交叉目标）、测试 harness 构建前提（`panic = "unwind"`）、clippy pedantic 零 warning（**含测试代码**）。
4. Mock：各 trait 可被内存 mock 实现（时钟、BufferPool、六个 crypto provider、最小状态机、最小示例消息），全部确定性、无 I/O、无 sleep（§18:422-424）。

### 1.3 范围外（明确不做）

| 不做的事 | 依据 |
|---|---|
| M1+ 协议编解码测试（RTP/RTCP/STUN/QUIC varint/H3） | §20:487-494，属 M1 里程碑 |
| 差分测试（对比 str0m / quinn-proto / web-transport-proto） | §18:425-435，M1 起随协议层落地 |
| Fuzzing 目标（cargo-fuzz / libfuzzer harness） | §18:437-439，M0 仅以 WIRE-CODEC-003 手工多样本往返作占位 |
| 真实加密提供方一致性测试（AWS-LC/Ring/RustCrypto 测试向量） | §20:496-503，M2 |
| 分配计数基准 harness | §20:483 为"设计"项，非 M0 测试项 |
| 跨 crate 集成测试 | §5.2：M0 无可组合 API，决策不建 |
| 互操作测试（Chromium/Firefox） | §18:441-449，M3+ |

### 1.4 证据约定

本文引用源码行为一律给出 `文件:行号`。源码行号以当前 skeleton 为准（下称 core=rtx-core/src/lib.rs，buffer=rtx-buffer/src/lib.rs，wire=rtx-wire/src/lib.rs，crypto=rtx-crypto/src/lib.rs，ws=Cargo.toml〔workspace 根〕）。

**行号效力注记（架构审阅 m9）**：工程师完成 §2.5 源码整改（补 `#[must_use]` 与 `# Errors` 文档）后，四个 lib.rs 的行号必然集体位移。测试实现以 **API 名称** 为准；文中行号仅作设计期证据，QA 如需整改后复审引用，按 API 名重建映射。

### 1.5 环境事实基线（实测记录，2026 基线，rustc/cargo 1.93.0）

| # | 命令 | 结果 | 对设计的影响 |
|---|---|---|---|
| E1 | `cargo check --workspace` | 通过 | — |
| E2 | `cargo check --no-default-features --workspace` | 通过 | ENG-NOSTD-001 的宿主验证手段成立 |
| E3 | `cargo test --no-run`（无 feature，no_std 模式，零测试） | 通过 | 测试模块 gate 到 std feature 后，默认 `cargo test` 不破坏 no_std 构建（ENG-TESTSTRAT-001） |
| E4 | `cargo test --workspace --features std --no-run` | 通过 | workspace 级 `--features std` 可一次性作用于四个 crate，执行计划采用此形态 |
| E5 | 沙箱对照实验：`[profile.dev]/[profile.release] panic="abort"` 的临时 crate 中 `cargo test` 与 `cargo test --release`（含 `#[should_panic]` 用例） | 均通过 | cargo 1.93.0 已对 test/bench profile 自动强制 unwind；`[profile.test] panic="unwind"` 为显式意图声明与防回归（见 §2.1） |
| E6 | 沙箱对照实验：`#![cfg_attr(not(feature="std"), no_std)]` + `default=[]` 的 crate，模式 A（测试 gate 到 `feature="std"`）/ 模式 B（`#[cfg(test)] extern crate std;`） | A：`cargo test` 零测试通过、`--features std` 全通过；B：`vec!` 等宏未进作用域，编译失败 | 测试 std 引入策略选型为模式 A（见 §2.2） |
| E7 | `cargo clippy --workspace --all-targets --all-features` | **34 条既有 warning**（22 条 `missing_errors_doc` + 12 条 `must_use_candidate`，分布于四个 lib） | "零 warning"通过标准当前不满足，属源码级差距，路由 Engineer（见 §2.5、ENG-LINT-001） |
| E8 | `rustup target list --installed` | 仅 `x86_64-unknown-linux-gnu` | thumbv7em 交叉编译为可选降级项（ENG-NOSTD-002） |

---

## 2. 工程前提（实现阶段必须先满足，均需主理人授权）

### 2.1 `[profile.test] panic = "unwind"`（ENG-PROFILE-001）

- 事实：workspace `Cargo.toml:28` 与 `:32` 在 `[profile.release]` 与 `[profile.dev]` 均设置 `panic = "abort"`；`[profile.test]` 默认继承 dev。libtest harness 依赖 unwinding 来捕获失败断言与支持 `#[should_panic]`。
- 要求：实现阶段在 workspace `Cargo.toml` 增加：
  ```toml
  [profile.test]
  panic = "unwind"
  ```
  这是**构建配置前提**，不触碰任何 `src/`，但是运行测试集的硬前提。
- 实测注记（E5）：cargo 1.93.0 实际已对 test/bench profile 自动强制 unwind，暂不声明也能跑测试；显式声明的价值在于（a）意图文档化，避免读者误以为 abort 会影响测试；（b）防工具链行为变化；（c）保证 `cargo test --release` 路径。**设计仍将其列为必需前提**，与任务要求一致。
- **实现注记（工程师 Round 1 实测，偏差报备）**：cargo 1.93.0 对 `[profile.test]` 的显式 `panic` 声明会发出 `` `panic` setting is ignored for `test` profile `` warning——每次 cargo 调用（含 `cargo test`/`cargo clippy`）均出现，并进入 clippy 输出，与 ENG-LINT-001"零 warning"通过标准直接冲突。鉴于 test profile 的 unwind 由 cargo 1.93 强制保证（E5 实测 + 77 用例实测运行验证：断言失败被正确捕获为测试失败），实现阶段**未添加**该显式声明，以零 warning 标准优先；声明意图由工具链行为与 E5 记录保障。此偏差已向主理人报备，待裁决（若裁决要求保留声明，接受该 cargo warning 并在报告中说明）。

### 2.2 no_std 测试模块的 std 引入策略（ENG-TESTSTRAT-001）

- 事实：四个 crate 均为 `#![cfg_attr(not(feature = "std"), no_std)]`（core:1、buffer:1、wire:1、crypto:1），且 `default = []`（各 `Cargo.toml:8-10`）。因此**默认 `cargo test` 在 no_std 模式下编译测试目标**。
- **选定策略（模式 A）**：每个 crate 在 `src/lib.rs` 末尾以
  ```rust
  #[cfg(all(test, feature = "std"))]
  mod tests { /* ... */ }
  ```
  承载全部单元测试；执行测试统一使用 `cargo test --workspace --features std`。
- 选型理由（实测 E3/E4/E6）：
  1. `cargo test`（无 feature）时测试模块被整体裁掉，harness 以零测试编译链接通过（E3 已验证），默认构建保持纯 no_std 语义；
  2. `--features std` 时 crate 完整启用 std，`vec!`/`format!`/`HashSet` 等标准库设施零摩擦可用（E6 模式 A 通过）；
  3. 备选模式 B（`#[cfg(test)] extern crate std;`）实测有宏导入摩擦（`vec!` 不进作用域，需逐个 `use std::vec;`），且使默认 `cargo test` 也构建测试，削弱"默认 = 纯 no_std"的语义（E6 模式 B 失败）。模式 A 无任何优势场景，故不选。
- 测试代码因此**显式依赖 std feature**：CI 与本地执行必须带 `--features std`（见 §6）。

### 2.3 测试放置策略

单元测试与源码同文件（`src/lib.rs` 内 `#[cfg(all(test, feature = "std"))] mod tests`），契合 skeleton 结构（ARCHITECTURE.md:106-114 的仓库形态，无 `tests/` 目录规划）。不新增 dev-dependencies、不新建共享 testkit（`rtx-testkit` 属 M1+ 规划，ARCHITECTURE.md:139-140）。理由与细节见 §5。

### 2.4 lint 约束对测试代码同样生效

- workspace lints：`unsafe_code = "forbid"`（ws:18）、`missing_debug_implementations = "warn"`（ws:19）、clippy `all` + `pedantic` = warn（ws:21-23）。
- 后果：`--all-targets` 下测试代码与 mock 实现**同样受 pedantic 约束**。测试中的 mock 类型如公开导出则必须 `#[derive(Debug)]`（`missing_debug_implementations` 仅对**公开**类型触发；tests 模块内私有 mock 不触发该 lint，但加 derive 零成本，建议统一添加）；mock 方法注意 `must_use_candidate` 等 pedantic 项。通过标准要求**测试代码零 warning**（ENG-LINT-001），实现阶段需与源码整改同步达标。

### 2.5 clippy 基线差距（已知源码级问题，路由 Engineer）

当前 skeleton 源码在 pedantic 下已有 **34 条 warning**（E7 实测）：22 条 `missing_errors_doc`（返回 `Result` 的公开函数缺 `# Errors` 段）+ 12 条 `must_use_candidate`（公开只读方法/构造器建议 `#[must_use]`，其中 11 个为 const fn；`Cursor::remaining` 非常 fn），分布于 core / wire / buffer / crypto 四个 lib。

- 定性：**源码问题，非测试问题**。QA 不代改源码（任务约束）。
- 路由：交 Engineer（Alex）修复（补 `#[must_use]` 与 `# Errors` 文档），修复后 QA 复审 ENG-LINT-001。
- 影响：在源码整改完成前，"clippy 零 warning"通过标准记为**未满足（Known Issue）**，不阻塞测试用例实现与运行。

---

## 3. 覆盖矩阵

覆盖维度图例：**正**=正常 / **边**=边界 / **错**=错误 / **契**=契约（编译期/语义冻结）/ **属**=属性 / **工**=工程。

### 3.1 rtx-core（23 例）

| 公开 API 项 | 源码位置 | 测试用例 ID | 维度 |
|---|---|---|---|
| `Timestamp`（结构体与 derives） | core:6-7 | CORE-TIME-001, 011, 012, 013 | 正/属 |
| `Timestamp::ZERO` | core:10 | CORE-TIME-001 | 正 |
| `Timestamp::from_micros` | core:12-14 | CORE-TIME-001, 003 | 正/契 |
| `Timestamp::as_micros` | core:16-18 | CORE-TIME-001, 011 | 正 |
| `Timestamp::saturating_duration_since` | core:20-22 | CORE-TIME-003, 005, 006, 015 | 边/契 |
| `Duration`（结构体与 derives） | core:26-27 | CORE-TIME-002, 011, 012, 013 | 正/属 |
| `Duration::ZERO` | core:30 | CORE-TIME-002 | 正 |
| `Duration::from_micros` | core:32-34 | CORE-TIME-002, 003 | 正/契 |
| `Duration::from_millis` | core:36-38 | CORE-TIME-003, 009 | 边 |
| `Duration::as_micros` | core:40-42 | CORE-TIME-002 | 正 |
| `impl Add<Duration> for Timestamp` | core:45-51 | CORE-TIME-004 | 边 |
| `impl AddAssign<Duration> for Timestamp` | core:53-57 | CORE-TIME-010 | 正/边 |
| `impl Sub<Timestamp> for Timestamp` | core:59-65 | CORE-TIME-005, 015 | 边/契 |
| `impl Add for Duration` | core:67-73 | CORE-TIME-007 | 边 |
| `impl AddAssign for Duration` | core:75-79 | CORE-TIME-010 | 正/边 |
| `impl Sub for Duration` | core:81-87 | CORE-TIME-008 | 边 |
| `impl SubAssign for Duration` | core:89-93 | CORE-TIME-010 | 正/边 |
| `trait Clock` | core:96-98 | CORE-TIME-014 | 契 |
| `enum IpAddr` | core:100-104 | CORE-ADDR-001, 003 | 正/属 |
| `struct SocketAddr` + `new` | core:106-115 | CORE-ADDR-002, 003 | 正/边/属 |
| `struct DatagramMeta` | core:119-125 | CORE-ADDR-004 | 正 |
| `enum EcnCodepoint` | core:127-132 | CORE-ADDR-004, 005 | 正 |
| `enum Input<'a>` | core:135-142 | CORE-SM-001 | 正 |
| `enum RuntimeAction` | core:145-149 | CORE-SM-002 | 正 |
| `trait ProtocolMachine` | core:152-162 | CORE-SM-003 | 契 |

### 3.2 rtx-buffer（15 例）

| 公开 API 项 | 源码位置 | 测试用例 ID | 维度 |
|---|---|---|---|
| `enum BufferError` | buffer:3-7 | BUF-ERR-001 | 正 |
| `PacketBuf::capacity` | buffer:14 | BUF-FIXED-001/002/007，BUF-BORROWED-001/002/003，BUF-POOL-001 | 正/边 |
| `PacketBuf::len` | buffer:15 | 同上 | 正/边 |
| `PacketBuf::set_len` | buffer:16 | BUF-FIXED-002/003，BUF-BORROWED-002/003 | 正/错 |
| `PacketBuf::as_slice` | buffer:17 | BUF-FIXED-004，BUF-BORROWED-002/003 | 契 |
| `PacketBuf::as_mut_slice` | buffer:18 | BUF-FIXED-005，BUF-BORROWED-003 | 契 |
| `PacketBuf::is_empty`（默认方法） | buffer:20-22 | BUF-FIXED-001/006，BUF-POOL-001 | 正/边 |
| `PacketBuf::remaining_mut`（默认方法） | buffer:24-26 | BUF-FIXED-006，BUF-POOL-001 | 边 |
| `FixedBuf<N>` + `new` + `Default` | buffer:29-48 | BUF-FIXED-001..007 | 正/边/错/契 |
| `impl PacketBuf for FixedBuf` | buffer:50-74 | BUF-FIXED-001..007 | 正/边/错/契 |
| `BorrowedBuf<'a>` + `new` + `with_len` | buffer:76-93 | BUF-BORROWED-001..004 | 正/边/错/契 |
| `impl PacketBuf for BorrowedBuf` | buffer:95-119 | BUF-BORROWED-001..003 | 正/错/契 |
| `trait BufferPool` | buffer:124-129 | BUF-POOL-002, 003 | 契 |

### 3.3 rtx-wire（22 例）

| 公开 API 项 | 源码位置 | 测试用例 ID | 维度 |
|---|---|---|---|
| `enum WireError` | wire:3-9 | WIRE-ERR-001 | 正 |
| `trait Decode<'a>` | wire:12-16 | WIRE-CODEC-001, 003, 004 | 契/正/错/属 |
| `trait Encode` | wire:19-24 | WIRE-CODEC-002, 003 | 契/正/错/属 |
| `Cursor::new` | wire:33-35 | WIRE-CUR-001 | 正/契（const） |
| `Cursor::offset` | wire:37-39 | WIRE-CUR-001/002/010 | 正 |
| `Cursor::remaining` | wire:41-43 | WIRE-CUR-001, 011 | 正/契 |
| `Cursor::take` | wire:45-53 | WIRE-CUR-002..006, 010 | 正/边/错 |
| `Cursor::u8` | wire:55-57 | WIRE-CUR-007, 010 | 正/错 |
| `Cursor::u16_be` | wire:59-62 | WIRE-CUR-008, 010 | 正/错 |
| `Cursor::u32_be` | wire:64-67 | WIRE-CUR-009, 010 | 正/错 |
| `Writer::new` / `Writer::offset` | wire:77-83 | WIRE-WR-001..006 | 正 |
| `Writer::put` | wire:85-97 | WIRE-WR-002/004/005 | 正/边/错 |
| `Writer::u8` / `u16_be` / `u32_be` | wire:99-109 | WIRE-WR-003, 006 | 正 |

### 3.4 rtx-crypto（17 例）

| 公开 API 项 | 源码位置 | 测试用例 ID | 维度 |
|---|---|---|---|
| `enum CryptoError` | crypto:3-12 | CRYPTO-ERR-001 | 正 |
| `enum HashAlgorithm` | crypto:14-19 | CRYPTO-ALG-001, CRYPTO-HASH-001, CRYPTO-HMAC-001 | 契 |
| `enum AeadAlgorithm` | crypto:21-25 | CRYPTO-ALG-001, CRYPTO-AEAD-001..005 | 契 |
| `enum SignatureAlgorithm` | crypto:27-32 | CRYPTO-ALG-001, CRYPTO-SIG-001/002 | 契 |
| `enum KeyExchangeAlgorithm` | crypto:34-39 | CRYPTO-ALG-001, CRYPTO-KEX-001/002 | 契 |
| `trait RandomProvider` | crypto:41-43 | CRYPTO-RAND-001 | 契 |
| `trait HashProvider` | crypto:45-52 | CRYPTO-HASH-001 | 契/错 |
| `trait HmacProvider` | crypto:54-62 | CRYPTO-HMAC-001 | 契/错 |
| `trait AeadProvider` | crypto:65-84 | CRYPTO-AEAD-001..005 | 契/正/错/边 |
| `trait SignatureProvider` | crypto:88-106 | CRYPTO-SIG-001/002 | 契/正/错 |
| `trait KeyExchangeProvider` | crypto:108-124 | CRYPTO-KEX-001/002 | 契/错 |
| `trait CryptoProvider` | crypto:127-131 | CRYPTO-COMBO-001..003 | 契 |

### 3.5 工程项（6 例）

| 工程项 | 依据 | 测试用例 ID | 维度 |
|---|---|---|---|
| `[profile.test] panic = "unwind"` 前提 | ws:25-32 | ENG-PROFILE-001 | 工 |
| no_std 测试 std 引入策略（双模式） | 各 lib.rs:1、Cargo.toml:8-10 | ENG-TESTSTRAT-001 | 工 |
| 宿主 no_std 编译（四 crate） | ARCHITECTURE.md:485 | ENG-NOSTD-001 | 工 |
| thumbv7em 交叉编译（可选降级） | ARCHITECTURE.md:485、DEPENDENCY_AUDIT.md:458-462 | ENG-NOSTD-002 | 工 |
| clippy pedantic 零 warning（含测试代码） | ws:17-23 | ENG-LINT-001 | 工 |
| `unsafe_code = "forbid"` 生效 | ws:18 | ENG-LINT-002 | 工 |

---

## 4. 测试用例清单

格式：**前置条件 / 步骤 / 预期结果**。所有步骤中的类型/方法名即设计意图，实现阶段按 §5.5 规范落为代码。

### 4.1 rtx-core（23 例：CORE-TIME ×15、CORE-ADDR ×5、CORE-SM ×3）

#### CORE-TIME-001 — Timestamp 构造与 `as_micros` 往返
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无（纯函数）
- **步骤**：
  1. 断言 `Timestamp::ZERO == Timestamp::from_micros(0)` 且 `Timestamp::ZERO.as_micros() == 0`（core:10、12、16）。
  2. 对样本值 `[0, 1, 999, 1_000_000, u32::MAX as u64, u64::MAX]` 逐一断言 `Timestamp::from_micros(v).as_micros() == v`。
  3. 断言 `Timestamp::default() == Timestamp::ZERO`（派生 Default，core:6）。
- **预期**：全部断言成立。

#### CORE-TIME-002 — Duration 构造与 `as_micros` 往返
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**：同 001 结构，作用于 `Duration::ZERO`（core:30）、`from_micros`（core:32）、`as_micros`（core:40）；样本含 `u64::MAX`；断言 `Duration::default() == Duration::ZERO`（core:26）。
- **预期**：全部断言成立。

#### CORE-TIME-003 — 时间 API 的 const fn 契约
- **crate**：rtx-core ｜ **维度**：契约
- **前置**：无
- **步骤**：
  1. 在 const 上下文定义 `const T0: Timestamp = Timestamp::from_micros(5);`、`const D0: Duration = Duration::from_millis(3);`、`const D1: Duration = T0.saturating_duration_since(Timestamp::ZERO);`（三者分别为 core:12、36、20 的 const fn）。
  2. 运行期断言 `D1.as_micros() == 5`、`D0.as_micros() == 3_000`。
- **预期**：编译通过且断言成立——锁定 const 语义，使 M1 状态机可在 const 表/静态里构造时间量。

#### CORE-TIME-004 — `Timestamp + Duration` 饱和至 `u64::MAX`
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:45-51，L49 `saturating_add`）：
  1. `Timestamp::from_micros(u64::MAX) + Duration::from_micros(1)` → 断言等于 `Timestamp::from_micros(u64::MAX)`。
  2. `Timestamp::from_micros(u64::MAX - 10) + Duration::from_micros(10)` → 恰等于 `from_micros(u64::MAX)`（不越界的临界）。
  3. `Timestamp::from_micros(u64::MAX - 10) + Duration::from_micros(11)` → 饱和为 `from_micros(u64::MAX)`。
- **预期**：溢出饱和而非回绕（§8:216 "must not wrap"）。

#### CORE-TIME-005 — `Timestamp - Timestamp` 反向得 ZERO
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:59-65，L63 委托 `saturating_duration_since`）：
  1. `from_micros(10) - from_micros(25)` → `Duration::ZERO`。
  2. `from_micros(25) - from_micros(10)` → `Duration::from_micros(15)`。
  3. `t - t`（同值）→ `Duration::ZERO`。
- **预期**：反向/乱序时间戳不回绕成巨大值，恒为 ZERO。

#### CORE-TIME-006 — `saturating_duration_since` 全路径
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:20-22，L21 `saturating_sub`）：`earlier < self`（差值精确）；`earlier == self`（ZERO）；`earlier > self`（ZERO）；`earlier = ZERO, self = from_micros(u64::MAX)`（`u64::MAX`）。
- **预期**：四条路径语义逐一成立。

#### CORE-TIME-007 — `Duration + Duration` 饱和
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:67-73，L71）：`from_micros(u64::MAX) + from_micros(u64::MAX)` → `u64::MAX`；`from_micros(u64::MAX - 1) + from_micros(1)` → `u64::MAX`；`from_micros(u64::MAX - 1) + from_micros(2)` → 饱和 `u64::MAX`。
- **预期**：不回绕。

#### CORE-TIME-008 — `Duration - Duration` 反向饱和为 ZERO
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:81-87，L85）：`from_micros(5) - from_micros(9)` → ZERO；`from_micros(9) - from_micros(5)` → `from_micros(4)`；`from_micros(u64::MAX) - from_micros(0)` → `u64::MAX`。
- **预期**：不回绕。

#### CORE-TIME-009 — `from_millis` 精确换算与饱和乘法边界
- **crate**：rtx-core ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 core:36-38，L37 `saturating_mul(1_000)`）：
  1. `from_millis(0) == ZERO`；`from_millis(1) == from_micros(1_000)`；`from_millis(1_000) == from_micros(1_000_000)`。
  2. 临界：令 `m = u64::MAX / 1_000`（= 18_446_744_073_709_551），断言 `from_millis(m) == from_micros(m * 1_000)`（不饱和）；`from_millis(m + 1)` 饱和为 `from_micros(u64::MAX)`。
  3. `from_millis(u64::MAX) == from_micros(u64::MAX)`。
- **预期**：毫秒→微秒乘法饱和而非回绕。

#### CORE-TIME-010 — `AddAssign`/`SubAssign` 运算符语义
- **crate**：rtx-core ｜ **维度**：正常/边界
- **前置**：无
- **步骤**（覆盖 core:53-57、75-79、89-93）：
  1. `let mut t = Timestamp::from_micros(10); t += Duration::from_micros(5);` → 断言 15。
  2. `let mut t = Timestamp::from_micros(u64::MAX); t += Duration::from_micros(7);` → 断言 `u64::MAX`（经 Add 委托饱和，core:55）。
  3. `let mut d = Duration::from_micros(10); d += Duration::from_micros(5); d -= Duration::from_micros(20);` → 断言 ZERO（SubAssign 饱和归零）。
- **预期**：复合赋值与二元运算符语义逐一对齐（§8:216）。

#### CORE-TIME-011 — `Ord` 派生全序行为
- **crate**：rtx-core ｜ **维度**：属性
- **前置**：无
- **步骤**（覆盖 derives core:6、26）：
  1. 断言 `Timestamp::ZERO < from_micros(1) < from_micros(u64::MAX)`；Duration 同理。
  2. 对样本对 `(a, b)` 断言 `a.cmp(&b)` 与 `a.as_micros().cmp(&b.as_micros())` 一致（排序不变量）。
  3. 相等值 `cmp == Equal`。
- **预期**：全序与内部 u64 表示一致——定时器堆/排序正确性的基础（§8:217）。

#### CORE-TIME-012 — `Hash` 派生一致性
- **crate**：rtx-core ｜ **维度**：属性
- **前置**：std 测试环境（`HashSet`）
- **步骤**：`HashSet<Timestamp>` 插入两个相等值与一个不同值 → 大小为 2；`HashSet<Duration>` 同理；（可选加强）`DefaultHasher` 对相等值得相同哈希。
- **预期**：等值同哈希、可去重（§8 时间量可作键）。

#### CORE-TIME-013 — `Copy`/`Clone` 派生语义
- **crate**：rtx-core ｜ **维度**：属性
- **前置**：无
- **步骤**：`let a = Timestamp::from_micros(7); let b = a;` 断言 `a == b` 且 `a.as_micros() == 7`（原值未移动）；Duration 同理。
- **预期**：Copy 后原值可用——Sans-I/O 热路径按值传递时间量的前提。

#### CORE-TIME-014 — `Clock` trait 可被 mock 实现
- **crate**：rtx-core ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 core:96-98）：
  1. 定义 `struct FixedClock(Timestamp)`，`impl Clock for FixedClock { fn now(&self) -> Timestamp { self.0 } }`；断言 `FixedClock(Timestamp::from_micros(42)).now() == from_micros(42)`。
  2. 定义可推进 mock `struct AdvancingClock { now: Timestamp }`（`advance(&mut self, d: Duration)`，`now()` 返回内部值）；断言推进后 `now()` 反映绝对时间。
- **预期**：trait 可被任意时钟源实现且返回**绝对 Timestamp**（§8:205、217；§18:422 模拟时钟）。

#### CORE-TIME-015 — `Sub` 与 `saturating_duration_since` 同源一致
- **crate**：rtx-core ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 core:59-65，L63 直接委托）：对样本对（含反向）断言 `(a - b) == a.saturating_duration_since(b)`。
- **预期**：运算符与显式方法行为一致，防止未来实现分叉。

#### CORE-ADDR-001 — `IpAddr` V4/V6 构造与相等性
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 core:100-104）：构造 `V4([127,0,0,1])` ×2 与 `V6([0;16])`；断言同变体等值相等、跨变体 `V4(..) != V6(..)`；`format!("{:?}", ..)` 可输出（Debug 派生 core:100）。
- **预期**：成立。

#### CORE-ADDR-002 — `SocketAddr::new` 与字段访问
- **crate**：rtx-core ｜ **维度**：正常/边界
- **前置**：无
- **步骤**（覆盖 core:106-115）：
  1. `SocketAddr::new(IpAddr::V4([8,8,8,8]), 53)`；断言公开字段 `.ip`/`.port`（core:108-109）。
  2. 端口边界：`new(V4([0,0,0,0]), 0)` 与 `new(V6([0x20,0x01,..]), 65535)` 可构造且相等性正确。
  3. const 上下文 `const SA: SocketAddr = SocketAddr::new(IpAddr::V4([1,2,3,4]), 9000);`（new 为 const fn，core:113）。
- **预期**：成立。

#### CORE-ADDR-003 — `IpAddr`/`SocketAddr` Copy/Hash 派生
- **crate**：rtx-core ｜ **维度**：属性
- **前置**：std 测试环境
- **步骤**（覆盖 derives core:100、106）：`HashSet<SocketAddr>` 去重（相同值插入两次大小为 1）；Copy 后原值可用。
- **预期**：成立。

#### CORE-ADDR-004 — `DatagramMeta` 构造
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 core:119-125）：分别以 `ecn: None` 与 `ecn: Some(EcnCodepoint::Ce)` 构造；断言 `PartialEq` 相等/不等；Copy（derive core:119）后可用；Debug 输出。
- **预期**：成立（运行时注入元数据的形状，core:118 注释）。

#### CORE-ADDR-005 — `EcnCodepoint` 三变体
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 core:127-132）：`Ect0 != Ect1`、`Ect1 != Ce`、`Ect0 != Ce`、`Ect0 == Ect0.clone()`。
- **预期**：成立。

#### CORE-SM-001 — `Input::Datagram`/`Timeout` 变体可构造
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 core:135-142）：
  1. 构造 `Input::Datagram { meta, payload: &[1,2,3] }`，`match` 取出 payload 断言内容（借用语义）。
  2. 构造 `Input::Timeout(Timestamp::from_micros(1_000))`，match 取出时间。
  3. `format!("{:?}", input)` 非空（Debug 派生 core:135）。
- **预期**：两变体可构造、可匹配、payload 以**借用**进入状态机（core:139 `payload: &'a [u8]`，Sans-I/O 语义见 §7:190-192）。

#### CORE-SM-002 — `RuntimeAction::WakeAt`/`Idle`
- **crate**：rtx-core ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 core:145-149）：构造 `WakeAt(t)` 与 `Idle`；断言 `Idle == Idle`、`WakeAt(t) != Idle`、`WakeAt(t1) != WakeAt(t2)`；Copy（derive core:145）；Debug。
- **预期**：成立；`WakeAt` 携带**绝对截止时间**（§8:217）。

#### CORE-SM-003 — `ProtocolMachine` 最小 mock 状态机（编译期契约）
- **crate**：rtx-core ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 core:152-162，GAT core:153-155）：
  1. 定义 `struct MiniMachine { events: Vec<MiniEvent>, wakeup: Option<Timestamp> }`（std 测试环境）。
  2. `impl ProtocolMachine for MiniMachine`：`type Input<'a> = crate::Input<'a>;`（满足 `where Self: 'a`，core:154）、`type Event = MiniEvent`、`type Error = core::convert::Infallible`；`handle_input` 记录 Datagram/Timeout；`poll_event` 弹出队列；`next_wakeup` 返回 `self.wakeup`。
  3. 驱动：`handle_input(Input::Timeout(t))` → `Ok(())`；`next_wakeup() == Some(t)`（绝对截止时间原样往返）；`poll_event()` 序列符合预期后返回 `None`。
- **预期**：GAT 与三方法可被实现——验证 trait 是最小 Sans-I/O 形状（§7:190-192）。

### 4.2 rtx-buffer（15 例：BUF-ERR ×1、BUF-FIXED ×7、BUF-BORROWED ×4、BUF-POOL ×3）

#### BUF-ERR-001 — `BufferError` 变体可构造与比较
- **crate**：rtx-buffer ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 buffer:3-7）：构造 `LengthExceedsCapacity` 与 `InsufficientCapacity`；断言互异、Clone/Copy/Eq（derive buffer:3）、Debug。注明 `InsufficientCapacity` 为预留契约变体（当前无实现方使用，仍须可构造可比较）。
- **预期**：成立。

#### BUF-FIXED-001 — `FixedBuf::new`/`Default` 初始状态
- **crate**：rtx-buffer ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 buffer:29-48、50-74）：
  1. const 构造 `const B: FixedBuf<8> = FixedBuf::new();`（const fn buffer:36，编译期验证）；运行期 `let b = FixedBuf::<8>::new();`。
  2. 断言 `b.capacity() == 8`、`b.len() == 0`、`b.is_empty()`、`b.as_slice().is_empty()`、`b.remaining_mut() == 8`。
  3. `FixedBuf::<8>::default()`（buffer:44-48）与 `new()` 行为一致。
- **预期**：初始 `len = 0`、`capacity = N`（§10:245-253 基础契约）。

#### BUF-FIXED-002 — `set_len` 正常路径
- **crate**：rtx-buffer ｜ **维度**：正常/边界
- **前置**：`FixedBuf::<8>::new()`
- **步骤**（覆盖 buffer:59-65）：`set_len(4)` → `Ok`，`len()==4`，`as_slice().len()==4`；`set_len(0)` → `Ok`；`set_len(8)`（== capacity 临界）→ `Ok`。
- **预期**：`0..=N` 全部接受。

#### BUF-FIXED-003 — `set_len` 超限报错且状态不变
- **crate**：rtx-buffer ｜ **维度**：错误
- **前置**：`set_len(4)` 成功的 buffer
- **步骤**（覆盖 buffer:59-65，L60-62）：`set_len(9)` → `Err(BufferError::LengthExceedsCapacity)`；再断言 `len()==4`、`as_slice()` 内容未变；`set_len(usize::MAX)` 同样 `Err` 且状态不变。
- **预期**：错误路径无副作用，M1 协议层可安全重试/降级。

#### BUF-FIXED-004 — `as_slice` 只暴露 `len`
- **crate**：rtx-buffer ｜ **维度**：契约
- **前置**：`FixedBuf::<8>`
- **步骤**（覆盖 buffer:67-69）：经 `as_mut_slice` 写入 `[1,2,3,4,5,6,7,8]`；`set_len` 前 `as_slice().is_empty()`；`set_len(3)` 后 `as_slice() == &[1,2,3]`；`set_len(8)` 后等于全 8 字节。
- **预期**：可见区间恰为 `storage[..len]`——零拷贝读取契约（§10:258-260）。

#### BUF-FIXED-005 — `as_mut_slice` 全容量可写且经 `set_len` 可见
- **crate**：rtx-buffer ｜ **维度**：契约
- **前置**：`FixedBuf::<8>`
- **步骤**（覆盖 buffer:71-73）：断言 `as_mut_slice().len() == capacity()`（与 `len` 无关）；写入 `[0xAA; 8]`；`set_len(5)` 后 `as_slice()` 前 5 字节全为 `0xAA`；`set_len(8)` 后 8 字节可见。
- **预期**：**写视图 = 全容量，读视图 = len**——冻结此不对称语义，防 M1 误用（见风险 R1）。

#### BUF-FIXED-006 — `is_empty`/`remaining_mut` 边界
- **crate**：rtx-buffer ｜ **维度**：边界
- **前置**：`FixedBuf::<8>`
- **步骤**（覆盖 buffer:20-26）：`len=N` → `!is_empty()` 且 `remaining_mut()==0`；`len=0` → `is_empty()` 且 `remaining_mut()==N`；`len=N/2` → `remaining_mut()==N-N/2`；验证 `saturating_sub`（buffer:25）不下溢。
- **预期**：成立。

#### BUF-FIXED-007 — `FixedBuf<0>` 零容量边界
- **crate**：rtx-buffer ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 buffer:29-42）：`FixedBuf::<0>::new()`：`capacity()==0`、`len()==0`、`is_empty()`、`remaining_mut()==0`；`set_len(0)` → `Ok`；`set_len(1)` → `Err(LengthExceedsCapacity)`；`as_mut_slice()` 为空切片。
- **预期**：零容量类型可用且不 panic。

#### BUF-BORROWED-001 — `BorrowedBuf::new` 初始状态
- **crate**：rtx-buffer ｜ **维度**：正常
- **前置**：预填 `let mut storage = [0x5A; 16];`
- **步骤**（覆盖 buffer:76-85、95-119）：`BorrowedBuf::new(&mut storage)` → `capacity()==16`、`len()==0`、`is_empty()`、`as_slice()` 为空（新 buffer 不暴露既有内容，buffer:84 `len: 0`）。
- **预期**：成立。

#### BUF-BORROWED-002 — `with_len` 正常、边界与超限
- **crate**：rtx-buffer ｜ **维度**：正常/边界/错误
- **前置**：预填 `[0x11; 16]`
- **步骤**（覆盖 buffer:87-92，L88-90）：
  1. `with_len(&mut storage, 4)` → `Ok`；`len()==4`；`as_slice() == &[0x11; 4]`。
  2. `with_len(&mut storage, 16)`（== `storage.len()` 临界）→ `Ok`。
  3. `with_len(&mut storage, 17)` → `Err(LengthExceedsCapacity)`。
  4. 空 storage：`with_len(&mut [], 0)` → `Ok`；`with_len(&mut [], 1)` → `Err`。
- **预期**：`len <= storage.len()` 接受，否则显式报错。

#### BUF-BORROWED-003 — `BorrowedBuf` 的 PacketBuf 行为
- **crate**：rtx-buffer ｜ **维度**：正常/错误
- **前置**：`BorrowedBuf::new(&mut [0u8; 16])`
- **步骤**（覆盖 buffer:95-119）：`set_len` 正常（0..=16）与超限（17 → `Err` 且状态不变）；`as_mut_slice().len() == 16`（全 storage，buffer:116-118）；经 `as_mut_slice` 写入后 `set_len(k)`、`as_slice` 可见。
- **预期**：与 FixedBuf 契约逐条对齐（两实现可互换，§10:235-240）。

#### BUF-BORROWED-004 — `BorrowedBuf` 借用生命周期（编译期）
- **crate**：rtx-buffer ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 buffer:76-80 生命周期参数）：内层作用域创建 `BorrowedBuf::new(&mut storage)` 并 drop；外层再次 `&mut storage` 写入——若实现错误地转移/冻结所有权则编译失败。记录（不进入测试）：同一 storage 上两个 BorrowedBuf 并存应被借用检查器拒绝。
- **预期**：编译通过；借用语义与 `&mut [u8]` 一致。

#### BUF-POOL-001 — `PacketBuf` 默认方法的 saturating 语义
- **crate**：rtx-buffer ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 buffer:20-26）：定义最小 mock `struct OddBuf;`，实现 `capacity()==4`、`len()==8`（`len > capacity` 的不变量违反场景，其余方法最小实现）；断言 `remaining_mut()==0`（`saturating_sub` 不回绕为巨大值，buffer:25）、`is_empty()==false`（buffer:21）。
- **预期**：默认方法对异常实现稳健（契约防御性）。

#### BUF-POOL-002 — `BufferPool` 固定块池 mock：acquire/release 往返
- **crate**：rtx-buffer ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 buffer:124-129）：
  1. 定义 `struct FixedBlockPool<const SLOTS: usize> { blocks: [Option<FixedBuf<64>>; SLOTS] }`；`acquire` 取出首个 `Some`（取出后置 `None`）；`release` 将 buffer `set_len(0)` **重置后**放入首个空槽（**mock 约定：回收即重置，池中 buffer 恒为 `len=0`**）；槽满时丢弃（mock 约定：丢弃并记账，不 panic）。
  2. 新建 `SLOTS=2` 池：`acquire()` → `Some` 且 `len()==0`；经 PacketBuf 写入数据 + `set_len(10)`；`release`；再次 `acquire()` → `Some` 且 `len()==0`（重置约定生效）、旧内容不可见。
  3. 连续 `acquire` 至耗尽 → 第 3 次返回 `None`；`release` 一块后再 `acquire` → `Some`。
  4. 向已满池 `release` → 不 panic（丢弃策略）。
- **预期**：acquire/release 往返契约成立——嵌入式固定块池场景（§10:255、§12:288 无分配边界）。

#### BUF-POOL-003 — `BufferPool` 关联类型约束编译期验证
- **crate**：rtx-buffer ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 buffer:125 `type Buffer: PacketBuf`）：泛型函数 `fn use_pool<P: BufferPool>(p: &mut P) -> Option<usize> { let b = p.acquire()?; let cap = b.capacity(); p.release(b); Some(cap) }`，以 `FixedBlockPool<2>` 与 `BorrowedBuf` 池两种 mock 实例化调用。
- **预期**：`type Buffer: PacketBuf` 上界编译通过；池产出物可直接按 PacketBuf 契约消费。

### 4.3 rtx-wire（22 例：WIRE-ERR ×1、WIRE-CUR ×11、WIRE-WR ×6、WIRE-CODEC ×4）

#### WIRE-ERR-001 — `WireError` 变体可构造与比较
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:3-9）：构造 `UnexpectedEnd`/`OutputTooSmall`/`InvalidValue`/`Overflow`；断言互异、Clone/Copy/Eq（derive wire:3）、Debug。注明 `InvalidValue` 为预留变体（当前无使用方）。
- **预期**：成立。

#### WIRE-CUR-001 — `Cursor::new`/`offset`/`remaining` 初始状态
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:26-43）：const 构造 `const C: Cursor = Cursor::new(b"abcd");`（const fn wire:33）；运行期断言 `offset()==0`、`remaining() == b"abcd"`（内容与长度）。
- **预期**：成立。

#### WIRE-CUR-002 — `take` 正常路径
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:45-53）：`Cursor::new(&[1,2,3,4,5])`；`take(2)` → `Ok(&[1,2])` 且 `offset()==2`；`take(1)` → `Ok(&[3])`、`offset()==3`；`remaining() == &[4,5]`。
- **预期**：顺序 take 推进 offset、返回借切片（wire:51）。

#### WIRE-CUR-003 — `take` 恰好耗尽边界
- **crate**：rtx-wire ｜ **维度**：边界
- **前置**：5 字节输入
- **步骤**（覆盖 wire:45-53）：`take(5)` → `Ok`（全部）、`offset()==5`；再 `take(1)` → `Err(UnexpectedEnd)`；再 `take(0)` → `Ok(&[])`（`offset == len` 时零长 take 合法，wire:49 `get(5..5)` 为 `Some`）。
- **预期**：恰好耗尽不出错；零长 take 在边界仍合法。

#### WIRE-CUR-004 — `take` 越界错误且 `offset` 不变
- **crate**：rtx-wire ｜ **维度**：错误
- **前置**：5 字节输入
- **步骤**（覆盖 wire:47-50）：`take(6)` → `Err(UnexpectedEnd)`；断言 `offset()` 保持 0（错误路径不推进，wire:50 提前返回）；随后 `take(5)` 仍成功。
- **预期**：错误无副作用，游标可恢复（防 M1 在错误后状态错乱）。

#### WIRE-CUR-005 — 空输入行为
- **crate**：rtx-wire ｜ **维度**：边界
- **前置**：无
- **步骤**（覆盖 wire:45-57）：`Cursor::new(&[])`：`take(0)` → `Ok(&[])`；`take(1)` → `Err(UnexpectedEnd)`；`u8()` → `Err(UnexpectedEnd)`；`offset()` 恒 0。
- **预期**：空输入不 panic。

#### WIRE-CUR-006 — `take` 的 `checked_add` Overflow 防护
- **crate**：rtx-wire ｜ **维度**：错误/边界
- **前置**：无
- **步骤**（覆盖 wire:46）：
  1. 5 字节输入先 `take(5)`（offset=5），再 `take(usize::MAX)` → `Err(WireError::Overflow)`（`5 + usize::MAX` 溢出，wire:46）。
  2. 对照：空输入直接 `take(usize::MAX)` → `Err(UnexpectedEnd)`（`0 + usize::MAX` 不溢出，落入 wire:50）——区分两条错误路径。
- **预期**：`Overflow` 与 `UnexpectedEnd` 语义分离；畸形/恶意长度得到显式错误而非 panic 或静默截断（wire:46 `checked_add` 先行，对应 §16:401 超限必须显式错误）。

#### WIRE-CUR-007 — `u8` 读取
- **crate**：rtx-wire ｜ **维度**：正常/错误
- **前置**：无
- **步骤**（覆盖 wire:55-57）：`[0x42]` → `Ok(0x42)`、offset 1；`[]` → `Err(UnexpectedEnd)`；`[1,2]` 连读两次 → `Ok(1)`、`Ok(2)`，第三次 `Err`。
- **预期**：成立。

#### WIRE-CUR-008 — `u16_be` 大端读取
- **crate**：rtx-wire ｜ **维度**：正常/错误
- **前置**：无
- **步骤**（覆盖 wire:59-62）：`[0x12,0x34]` → `Ok(0x1234)`、offset 2；`[0xFF,0x00]` → `0xFF00`；剩 1 字节 → `Err(UnexpectedEnd)`。
- **预期**：大端序（网络序）正确；不足 2 字节报错。

#### WIRE-CUR-009 — `u32_be` 大端读取
- **crate**：rtx-wire ｜ **维度**：正常/错误
- **前置**：无
- **步骤**（覆盖 wire:64-67）：`[0x12,0x34,0x56,0x78]` → `0x12345678`、offset 4；`[0xDE,0xAD,0xBE,0xEF]` → `0xDEADBEEF`；剩 3 字节 → `Err(UnexpectedEnd)`。
- **预期**：成立。

#### WIRE-CUR-010 — 混合读取序列与 `offset` 一致性
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:45-67 组合）：输入 `[0xAA, 0xBB, 0x01,0x02, 0x03,0x04,0x05,0x06, 0xCC,0xDD, 0x09]`：依序 `u8()`→0xAA、`u8()`→0xBB、`u16_be()`→0x0102、`u32_be()`→0x03040506、`u16_be()`→0xCCDD、`u8()`→0x09；每步后断言 `offset()` 等于累计字节数；末态 `remaining()` 为空。
- **预期**：offset 累加精确，各读取互不串扰。

#### WIRE-CUR-011 — `remaining()` 返回与输入同生命周期
- **crate**：rtx-wire ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 wire:41-43，签名 `&'a [u8]`）：`let input: &'static [u8] = b"xyz"; let slice: &'static [u8] = { let mut c = Cursor::new(input); c.take(1).unwrap(); c.remaining() };` 在 cursor 离开作用域后仍使用 `slice`——若返回生命周期绑定到 `&self` 则编译失败。
- **预期**：编译通过（借用输入而非借用游标，wire:41-42）。

#### WIRE-WR-001 — `Writer::new`/`offset` 初始状态
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:70-83）：`Writer::new(&mut [0u8; 8])`：`offset()==0`；Debug（derive wire:70）。
- **预期**：成立。

#### WIRE-WR-002 — `put` 正常路径与空片边界
- **crate**：rtx-wire ｜ **维度**：正常/边界
- **前置**：无
- **步骤**（覆盖 wire:85-97）：`put(&[1,2,3])` → `Ok`、offset 3、output 前三字节正确；`put(&[])` → `Ok` 且 offset 不变（wire:91 `get_mut(3..3)` 为 `Some`）；`put(&[4])` → offset 4。
- **预期**：写入推进 offset、内容逐字节正确（wire:94 `copy_from_slice`）。

#### WIRE-WR-003 — `u8`/`u16_be`/`u32_be` 大端写入
- **crate**：rtx-wire ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 wire:99-109）：依序写入 `0x42`、`0x1234`、`0xDEADBEEF`；断言 output == `[0x42, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF]`、`offset()==7`。
- **预期**：与 Cursor 大端读取互为逆运算。

#### WIRE-WR-004 — `OutputTooSmall` 错误且 `offset` 不变
- **crate**：rtx-wire ｜ **维度**：错误
- **前置**：2 字节 output
- **步骤**（覆盖 wire:90-93）：`put(&[1,2,3])` → `Err(OutputTooSmall)`；断言 `offset()==0` 且 output 未被写入（无部分写入，wire:93 提前返回）；`u16_be` 于剩 1 字节 → `Err(OutputTooSmall)`。
- **预期**：错误无副作用。

#### WIRE-WR-005 — 恰好写满边界
- **crate**：rtx-wire ｜ **维度**：边界
- **前置**：4 字节 output
- **步骤**：`u32_be(0x01020304)` → `Ok`、`offset()==4 == output.len()`；再 `u8(0)` → `Err(OutputTooSmall)`；`put(&[])` 于已满 output → `Ok`（零长不越界）。
- **预期**：恰恰好写满是合法上界。

#### WIRE-WR-006 — Writer→Cursor 往返一致
- **crate**：rtx-wire ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 wire:85-109 + 45-67）：用 Writer 依序写 `u8(0x42)`、`u16_be(0x1234)`、`u32_be(0xDEADBEEF)`、`put(b"END")`；再用 `Cursor::new(&buf[..w.offset()])` 依序读回同类型值；断言每个值相等且 `cursor.offset() == writer.offset()`（consumed == written）。
- **预期**：编解码往返一致（§11:272-274）。

#### WIRE-WR 组注（覆盖决策，架构审阅 m1）
- **`Writer::put` 的 `checked_add` Overflow 分支（wire:86-89）故意不覆盖**：该分支不可达——由不变式 `offset ≤ output.len()` 且合法切片长度 ≤ `isize::MAX`，有 `offset + input.len() ≤ 2·isize::MAX = usize::MAX − 1 < usize::MAX`，加法永不溢出。不测试它是正确决策；此处显式记录，防止留白被误读为遗漏。

#### WIRE-CODEC-001 — `Decode` 最小示例消息（Ping）
- **crate**：rtx-wire ｜ **维度**：契约/正常/错误
- **前置**：无
- **步骤**（覆盖 wire:12-16）：
  1. 定义 `struct Ping { seq: u32, tag: u8 }`；`impl Decode<'_> for Ping { type Error = WireError; fn decode(input: &[u8]) -> Result<(Self, usize), WireError> { let mut c = Cursor::new(input); let seq = c.u32_be()?; let tag = c.u8()?; Ok((Ping { seq, tag }, c.offset())) } }`。
  2. `decode(&[0,0,0,7, 0x2A])` → `(Ping{seq:7,tag:0x2A}, 5)`；`decode(&[0,0,0,7, 0x2A, 0xFF, 0xFF])` → consumed == 5（多余字节不属于本消息，wire:15 契约）。
  3. `decode(&[0,0,0])` → `Err(UnexpectedEnd)`（`?` 传播）。
- **预期**：`(Message, consumed)` 形状成立（§11:273）。

#### WIRE-CODEC-002 — `Encode` 最小示例消息（Ping）
- **crate**：rtx-wire ｜ **维度**：契约/正常/错误
- **前置**：无
- **步骤**（覆盖 wire:19-24）：`impl Encode for Ping { type Error = WireError; fn encoded_len(&self) -> usize { 5 } fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> { let mut w = Writer::new(out); w.u32_be(self.seq)?; w.u8(self.tag)?; Ok(w.offset()) } }`；断言 `encoded_len()==5`；精确 5 字节缓冲 → `Ok(5)` 且字节符合预期；4 字节缓冲 → `Err(OutputTooSmall)`；`encode` 返回值与 `encoded_len` 一致。
- **预期**：`encoded_len` 与 `encode` 自洽——调用方可按 `encoded_len` 预备缓冲（§11:274）。

#### WIRE-CODEC-003 — Encode→Decode 往返属性
- **crate**：rtx-wire ｜ **维度**：属性
- **前置**：Ping 的 Decode/Encode 实现
- **步骤**：对样本 `[(0,0), (1,0xFF), (u32::MAX,0x80), (0xDEADBEEF,0x01)]`：`let n = p.encode(&mut buf).unwrap(); let (p2, m) = Ping::decode(&buf[..n]).unwrap();` 断言 `p2 == p` 且 `m == n`。
- **预期**：多样本往返守恒（M1 fuzzing 占位的手工版，§18:437-439）。

#### WIRE-CODEC-004 — `Decode` borrowed lifetime 验证（Blob）
- **crate**：rtx-wire ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 wire:11-16，doc wire:11 "Returned values may borrow directly from `input`"）：定义 `struct Blob<'a> { data: &'a [u8] }`，`impl<'a> Decode<'a> for Blob<'a>`：`decode` 以 `Cursor::take(len)` 借用输入切片；测试 `let input = [1,2,3,4]; let (blob, n) = Blob::decode(&input).unwrap();` 断言 `blob.data == &input[..n]`，且 `blob` 不可比 `input` 活得更久（编译期）；另断言声称 `len=2` 而输入仅 1 字节时 `Err(UnexpectedEnd)`。
- **预期**：消息体可零拷贝借用输入；生命周期由类型系统强制（§10:259、§11:273）。
- **实现注记（工程师 Round 1）**：上文断言 `blob.data == &input[..n]` 与本节格式定义（`[claimed_len: u8][payload: claimed_len bytes]`，由错误用例"声称 len=2 而输入仅 1 字节 → UnexpectedEnd"所固定）存在 off-by-one 矛盾——两种解读无法同时满足。实现以格式定义与机制描述（`Cursor::take(len)`）为准，断言 `blob.data == &input[1..n]`（payload 位于 1 字节长度前缀之后），零拷贝性以 `blob.data.as_ptr() == input[1..].as_ptr()` 直接证明。设计文档该处按笔误处理，待 QA 确认。

### 4.4 rtx-crypto（17 例）

> 全部 mock 为**内存确定性实现**（禁止真随机/真时间，§18:422）；真实提供方与测试向量属 M2（§20:496-503）。mock 策略常量见 §5.4。

#### CRYPTO-ERR-001 — `CryptoError` 变体可构造与比较
- **crate**：rtx-crypto ｜ **维度**：正常
- **前置**：无
- **步骤**（覆盖 crypto:3-12）：构造全部 7 个变体（crypto:4-10：`Unsupported`/`InvalidKey`/`InvalidNonce`/`InvalidSignature`/`AuthenticationFailed`/`OutputTooSmall`/`BackendFailure`）；断言互异、Clone/Copy/Eq（derive crypto:3）、Debug。
- **预期**：成立。

#### CRYPTO-ALG-001 — 算法枚举穷举可构造与互异
- **crate**：rtx-crypto ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 crypto:14-39）：对 `HashAlgorithm`（3 变体）、`AeadAlgorithm`（2）、`SignatureAlgorithm`（3）、`KeyExchangeAlgorithm`（3）逐一穷举：构造、互异比较（如 `Sha1 != Sha256 != Sha384`）、Debug、`matches!` 覆盖。
- **预期**：成立；穷举写法使未来新增变体时测试失败，强制同步评审（契约冻结保护）。

#### CRYPTO-RAND-001 — `RandomProvider` 内存 mock
- **crate**：rtx-crypto ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 crypto:41-43）：定义 `struct MockRandom { counter: Cell<u64> }`（确定性 xorshift；trait 方法收 `&self`，内部序列用 `Cell` 推进，见 §5.4 注记）；`impl RandomProvider`：以状态流填满 output。断言：`fill_random(&mut [0u8;32])` → `Ok` 且输出非全零（确定性图案）；空 output → `Ok`（无操作）；连续两次调用输出不同（序列推进）。
- **预期**：trait 可被无堆 mock 实现；调用方拥有输出缓冲（§12:290）。

#### CRYPTO-HASH-001 — `HashProvider` 内存 mock
- **crate**：rtx-crypto ｜ **维度**：契约/错误
- **前置**：无
- **步骤**（覆盖 crypto:45-52）：mock 摘要长度策略 Sha1→20、Sha256→32、Sha384→48；`digest(alg, input, out)` 写入确定性摘要并返回 written。断言：三种算法返回长度分别为 20/32/48 且 `out[..written]` 与直接调用确定性函数一致；相同 input → 相同输出（确定性）；不同 input → 不同输出（基本区分性）；`out` 长度 < 摘要长度 → `Err(OutputTooSmall)`（mock 策略：写入前检查）。
- **预期**：输出缓冲与返回长度契约成立。

#### CRYPTO-HMAC-001 — `HmacProvider` 内存 mock
- **crate**：rtx-crypto ｜ **维度**：契约/错误
- **前置**：无
- **步骤**（覆盖 crypto:54-62）：mock mac 长度 = 对应摘要长度。断言：返回长度正确；同一 `(key, input)` 确定可复现；更换 key → mac 变化（密钥参与）；更换 input → mac 变化；`out` 过小 → `Err(OutputTooSmall)`。
- **预期**：成立。

#### CRYPTO-AEAD-001 — `AeadProvider` seal→open 原地往返
- **crate**：rtx-crypto ｜ **维度**：契约/正常
- **前置**：无
- **步骤**（覆盖 crypto:65-84）：
  1. mock 策略：`TAG_LEN = 16`；`seal_in_place` 先检查 `payload_and_tag.len() >= plaintext_len + TAG_LEN`，随后 `[0..plaintext_len)` 写密文（明文 XOR 由 key+nonce 决定的确定性流），`[plaintext_len..plaintext_len+TAG_LEN)` 写 tag（对 aad+密文+key 的确定性 MAC），返回 `plaintext_len + TAG_LEN`；`open_in_place` 先按同参数重算 tag 比对，再原地解密，返回 `plaintext_len`。
  2. 测试：明文 `b"rtx-m0-aead"`（10 字节）、缓冲 26 字节；seal → 返回值 == 10+16 == 26；断言密文区 != 明文区、tag 区 16 字节；open → 返回 10 且 `buf[..10] == 明文`。
- **预期**：原地往返守恒；**tag 空间语义 = `plaintext_len + tag`**（§12:289）。

#### CRYPTO-AEAD-002 — AAD 认证失败路径
- **crate**：rtx-crypto ｜ **维度**：错误
- **前置**：无
- **步骤**（覆盖 crypto:71、81 的 aad 参数）：seal 用 `aad = b"header"`；open 用 `aad = b"HEADER"` → `Err(AuthenticationFailed)`；断言失败后缓冲未被解密篡改（mock 策略：先验证后解密）。
- **预期**：aad 参与认证（AEAD 标准语义）。

#### CRYPTO-AEAD-003 — tag 篡改检测
- **crate**：rtx-crypto ｜ **维度**：错误
- **前置**：seal 后的缓冲
- **步骤**（覆盖 crypto:76-83）：将 tag 区首字节翻转一 bit；open → `Err(AuthenticationFailed)`。
- **预期**：完整性校验生效。

#### CRYPTO-AEAD-004 — key/nonce 不匹配
- **crate**：rtx-crypto ｜ **维度**：错误
- **前置**：seal 后的缓冲
- **步骤**（覆盖 crypto:69-70、79-80）：seal 用 `(key K, nonce N)`；open 分别用 `(K', N)` 与 `(K, N')` → 均 `Err(AuthenticationFailed)`。
- **预期**：密钥/一次性数值绑定。

#### CRYPTO-AEAD-005 — tag 空间不足
- **crate**：rtx-crypto ｜ **维度**：边界/错误
- **前置**：无
- **步骤**（覆盖 crypto:72-73）：缓冲 25 字节、`plaintext_len=10`、`TAG_LEN=16`（需 26）→ `Err(OutputTooSmall)`；断言缓冲未被修改；边界：恰 26 字节 → `Ok`。
- **预期**：调用方缓冲不足时显式报错而非 panic/截断（§12:290）。

#### CRYPTO-SIG-001 — `SignatureProvider` sign→verify 往返
- **crate**：rtx-crypto ｜ **维度**：契约/正常
- **前置**：无
- **步骤**（覆盖 crypto:88-106）：mock：`struct MockPrivateKey(u64)`（不透明句柄概念，crypto:86-87），公钥由私钥确定性导出；`sign(Ed25519, key, msg, out)` 写 64 字节确定性签名返回 written；`verify(alg, pub, msg, sig)` 重算比对。断言：sign 返回 64；verify（正确 pub/msg/sig）→ `Ok(())`；`out` 小于 64 → `Err(OutputTooSmall)`；同一 msg 两次签名一致（确定性）。
- **预期**：签名/验签往返成立；私钥以不透明类型停留在 provider 内（§12:291）。

#### CRYPTO-SIG-002 — 篡改消息 verify 失败
- **crate**：rtx-crypto ｜ **维度**：错误
- **前置**：无
- **步骤**（覆盖 crypto:99-105）：对 msg 签名；verify 时 msg 翻转一字节 → `Err(CryptoError::InvalidSignature)`（mock 策略：验签失败统一返回 `InvalidSignature`，与 `AuthenticationFailed` 的分工在实现注释中注明）；篡改签单一字节 → 同样 `Err`。
- **预期**：消息或签名任何比特被改均拒绝。

#### CRYPTO-KEX-001 — `KeyExchangeProvider` 双方 agree 得到相同 secret
- **crate**：rtx-crypto ｜ **维度**：契约
- **前置**：无
- **步骤**（覆盖 crypto:108-124）：mock：`generate_key(X25519, out)` 生成确定性 `(priv, pub)`（priv 来自 `Cell<u64>` 内部序列，`pub = priv.wrapping_mul(G)`，`G` 为固定常数）；`agree(alg, priv, peer_pub, out)` 计算 `priv.wrapping_mul(peer_pub)` 写入并返回 32。断言：A 生成 `(a_priv, a_pub)`、B 生成 `(b_priv, b_pub)`；`A.agree(a_priv, b_pub) == B.agree(b_priv, a_pub)`（逐字节相等）；secret 长度 32；更换对端公钥 → secret 变化。
- **预期**：DH 交换对称性成立——wrapping 乘法模 2^64 天然交换（`a·(b·G) == b·(a·G)`），双方 agree 结果逐字节相等（§12:284-294 provider 中立）。

#### CRYPTO-KEX-002 — KEX 错误路径
- **crate**：rtx-crypto ｜ **维度**：错误
- **前置**：无
- **步骤**（覆盖 crypto:111-123）：`public_key_out` 小于所需公钥长度 → `Err(OutputTooSmall)`；`agree` 传入错误长度的 `peer_public_key` → `Err(CryptoError::InvalidKey)`（mock 策略）；`secret_out` 过小 → `Err(OutputTooSmall)`。
- **预期**：显式错误、无 panic。

#### CRYPTO-COMBO-001 — `CryptoProvider` 组合 mock 与 `name()`
- **crate**：rtx-crypto ｜ **维度**：契约
- **前置**：前述各 provider mock 已定义
- **步骤**（覆盖 crypto:127-131）：定义单一 `struct MockCrypto { .. }` 同时实现 Random/Hash/Hmac/Aead/Signature/KeyExchange 六个 trait（可组合持有前述 mock 逻辑）；`impl CryptoProvider for MockCrypto { fn name(&self) -> &'static str { "rtx-mock-crypto" } }`；断言 `name()` 非空；冒烟：以 `MockCrypto` 实例**静态分发**直接调用（泛型 + `&P`，见 CRYPTO-COMBO-002），依次调用六类能力各一次成功。
- **预期**：supertrait 组合（crypto:127-128）可被单结构体满足；`name()` 返回非空 `&'static str`。
- **严禁 `&dyn CryptoProvider`**（架构审阅 M1 修订）：`SignatureProvider::sign` 以 `&Self::PrivateKey` 为参数、`KeyExchangeProvider::generate_key` 返回 `Self::PrivateKey`——关联类型 `PrivateKey` 出现在方法参数/返回位，违反对象安全规则，`dyn CryptoProvider` 不可构造（rustc E0191，架构师以真实 crate 实测复现）；且 ARCHITECTURE.md §12:292 明确 "no assumption that provider types are dynamically dispatched"。六个 provider mock 与组合冒烟**一律静态分发**，实现中禁止出现任何 `dyn CryptoProvider` / `dyn SignatureProvider` / `dyn KeyExchangeProvider` 写法（组合形态见 CRYPTO-COMBO-002 泛型函数）。

#### CRYPTO-COMBO-002 — `CryptoProvider` 泛型上界编译期契约
- **crate**：rtx-crypto ｜ **维度**：契约
- **前置**：无
- **步骤**：泛型函数 `fn exercise<P: CryptoProvider>(p: &P) -> Result<(), CryptoError> { p.fill_random(&mut [0u8;8])?; p.digest(HashAlgorithm::Sha256, b"x", &mut [0u8;32])?; p.hmac(HashAlgorithm::Sha256, b"k", b"x", &mut [0u8;32])?; /* aead/sig/kex 各一次 */ assert!(!p.name().is_empty()); Ok(()) }`；以 `MockCrypto` 实例化并调用。
- **预期**：`CryptoProvider` 蕴含全部子能力，可作为协议层泛型边界（§12:294）。

#### CRYPTO-COMBO-003 — 加密边界无分配/原地语义设计核验
- **crate**：rtx-crypto ｜ **维度**：契约（设计评审 + 代码检查）
- **前置**：无
- **步骤**：核验全部 mock 与用例仅使用栈数组/调用方缓冲，provider trait 调用路径无 `Vec`/`Box`/堆分配（mock 实现自身零堆分配作为范式）；对照 crypto:64 注释 "In-place AEAD avoids forcing an allocation at the crypto boundary" 与 §12:287-292 **六条**要求（provider-neutral / no allocation / in-place AEAD / caller-owned buffers / opaque keys / no dyn-or-rc assumption）逐条确认。
- **预期**：trait 边界无分配要求在测试范式中被示范与固化（真实分配计数测量属 M0 基准 harness 设计项，§20:483，不在本测试集）。

### 4.5 工程与构建（6 例）

#### ENG-PROFILE-001 — `[profile.test] panic = "unwind"` 工程前提落地
- **crate**：workspace ｜ **维度**：工程
- **前置**：主理人授权修改 workspace `Cargo.toml`（构建配置，非源码）
- **步骤**：按 §2.1 增加 `[profile.test] panic = "unwind"`；执行 `cargo test --workspace --features std` 验证 harness 正常构建运行。
- **预期**：测试 harness 获得 unwinding（含 `#[should_panic]` 能力）。实测注记见 §1.5 E5。

#### ENG-TESTSTRAT-001 — no_std 测试策略双模式验证
- **crate**：workspace ｜ **维度**：工程
- **前置**：测试模块按 §2.2 模式 A 落地
- **步骤**：
  1. `cargo test --workspace --no-run`（无 feature，no_std 模式）：测试模块被裁掉，harness 以零测试编译链接通过（基线 E3 已验证）。
  2. `cargo test --workspace --features std`：全部用例运行。
- **预期**：默认构建保持纯 no_std；测试显式依赖 std feature。

#### ENG-NOSTD-001 — 四 crate 宿主 no_std 编译
- **crate**：workspace ｜ **维度**：工程
- **前置**：无
- **步骤**：`cargo check --no-default-features --workspace` → 通过（基线 E2 已验证）；再逐一 `cargo check --no-default-features -p rtx-core`（及 buffer/wire/crypto）确认无遗漏。
- **预期**：零错误。该命令同时是 **§9:221 不依赖 `std::net` 的强制验证**——no_std 下无法引用 `std::net`，编译通过即证明地址模型未泄漏（core:100-110 为自建表示）。

#### ENG-NOSTD-002 — thumbv7em 交叉编译（可选，允许降级）
- **crate**：workspace ｜ **维度**：工程
- **前置**：沙箱网络可用
- **步骤**：`rustup target add thumbv7em-none-eabihf`；`cargo check --no-default-features --workspace --target thumbv7em-none-eabihf`；若目标安装或网络失败 → 记录降级原因。
- **预期**：尽力通过；失败不阻塞 M0（宿主 no_std 编译 + CI 占位已满足退出条件，§20:485 "at least one no_std target"）。

#### ENG-LINT-001 — clippy pedantic 零 warning（含测试代码）
- **crate**：workspace ｜ **维度**：工程
- **前置**：Engineer 完成源码级 warning 整改（§2.5）
- **步骤**：
  1. `cargo clippy --workspace --all-targets --all-features` → 零 warning（`--all-targets` 覆盖测试目标；mock 须 `#[derive(Debug)]` 满足 ws:19）。
  2. `cargo clippy --workspace --no-default-features` → 零 warning（no_std 路径）。
- **预期**：两路径均零 warning。**已知基线差距**：当前 34 条源码级 warning（E7），整改前本条记 Known Issue。

#### ENG-LINT-002 — `unsafe_code = "forbid"` 生效
- **crate**：workspace ｜ **维度**：工程
- **前置**：无
- **步骤**：§6 全部编译/测试/clippy 命令通过即证明无 unsafe（forbid 为硬错误，ws:18）；测试代码同样禁止 unsafe。
- **预期**：任何 unsafe 引入都会立即使构建失败。

---

## 5. 测试策略与放置

### 5.1 单元测试放置

- 位置：各 crate `src/lib.rs` 末尾，`#[cfg(all(test, feature = "std"))] mod tests { ... }`（模式 A，§2.2）。
- 自足：每个 tests 模块自带 helper 构造器（如 `fn sample_meta() -> DatagramMeta`）与 mock；`use super::*;` 引入被测 API。
- 结构：AAA（Arrange-Act-Assert）；一个 `#[test]` 对应一个用例 ID（以注释 `// CORE-TIME-001` 标注）；测试函数名描述行为（如 `timestamp_add_saturates_at_u64_max`）。
- 数据：固定样本内联（无需 fixture 文件）；样本值显式列出（含 `u64::MAX` 等边界）。
- 可读性：测试按 §4 的分组（TIME/ADDR/SM、FIXED/BORROWED/POOL、CUR/WR/CODEC、各 provider）以子模块或命名前缀聚合，与用例 ID 一一对应。

### 5.2 跨 crate 集成测试：M0 不建

- 事实：四个 crate 相互无依赖（各 `Cargo.toml` 无 `[dependencies]` 节）；公开 API 尚无可组合点（Cursor/Writer 作用于裸 `&[u8]`/`&mut [u8]`；PacketBuf 自含；crypto trait 边界无协议消费者）。
- 决策：**不建 `tests/` 集成测试目录**。强行引入需处理 feature 传递（集成测试目标默认不带 feature）且无可测行为，属负收益。
- 演进：M1 起在 `rtx-testkit`（ARCHITECTURE.md:139-140）承载差分测试与协议向量；届时 wire 编解码 × buffer 所有权的组合测试自然落入该 crate。

### 5.3 mock 提供方集中位置

全部 mock **就近自足**于各 crate 的 tests 模块，不建共享 mock crate：

| mock | 位置 | 服务用例 |
|---|---|---|
| `FixedClock`/`AdvancingClock` | rtx-core tests | CORE-TIME-014 |
| `MiniMachine` | rtx-core tests | CORE-SM-003 |
| `FixedBlockPool<SLOTS>` | rtx-buffer tests | BUF-POOL-002/003 |
| `OddBuf`（默认方法探测） | rtx-buffer tests | BUF-POOL-001 |
| `Ping`/`Blob<'a>` | rtx-wire tests | WIRE-CODEC-001..004 |
| `MockRandom`/`MockHash`/`MockHmac`/`MockAead`/`MockSignature`/`MockKeyExchange`/`MockCrypto` | rtx-crypto tests | CRYPTO-RAND-001..COMBO-003 |

### 5.4 crypto mock 策略常量与失败码约定

| 常量 | 值 | 用途 |
|---|---|---|
| `TAG_LEN` | 16 | AEAD tag 长度（CRYPTO-AEAD-001..005） |
| `SHA1_LEN` / `SHA256_LEN` / `SHA384_LEN` | 20 / 32 / 48 | 摘要长度（CRYPTO-HASH/HMAC-001） |
| `SIG_LEN` | 64 | Ed25519 风格签名长度（CRYPTO-SIG-001/002） |
| `PUB_LEN` / `SECRET_LEN` | 32 / 32 | X25519 公钥/共享秘密长度（CRYPTO-KEX-001/002） |

失败码约定（mock 策略，实现时以注释固化）：认证/验签失败 → `AuthenticationFailed`（AEAD）/ `InvalidSignature`（验签）；尺寸不足 → `OutputTooSmall`；畸形对端公钥 → `InvalidKey`；不支持的算法参数 → `Unsupported`。所有 mock 算法为确定性算术（XOR 流、标量运算、简单 MAC），**不使用真实密码学**——本测试集验证的是 trait 契约与缓冲语义，不是密码学正确性（后者属 M2 提供方一致性测试，§20:496-503）。

**mock 实现注记（架构审阅 m2）**：`MockRandom`（CRYPTO-RAND-001）与 `MockKeyExchange`（CRYPTO-KEX-001）对应的 trait 方法均收 `&self`，但 mock 需要推进内部序列——使用 `core::cell::Cell<u64>` 提供内部可变性（`no_std` 友好；`RefCell` 亦可但无必要）。KEX mock 采用交换算术：`pub = priv.wrapping_mul(G)`、`secret = priv.wrapping_mul(peer_pub)`（见 §4.4 CRYPTO-KEX-001）。

### 5.5 确定性与无 I/O 原则

全部用例纯函数式确定：无 sleep、无真实时钟、无真实随机、无文件/网络（§18:422-424）。mock 时钟/mock 随机使协议层未来的确定性测试（§18:421-424）在本契约层已有范式。

### 5.6 doc-test 说明

四个 crate 的 doc 注释当前不含可运行 rust 代码块，`cargo test` 跑 0 个 doc-test。M0 不新增 doc 示例；未来若添加，须保证其在 `--no-default-features`（no_std）下可编译，或标注为 `text`/`ignore` 并在 std feature 下可运行。

---

## 6. 执行计划

### 6.1 命令序列（实现阶段按序执行）

```bash
# 步骤 0（工程前提，需主理人授权）：workspace Cargo.toml 增加
#   [profile.test]
#   panic = "unwind"

# 步骤 1：静态检查（含测试代码）
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features      # 预期零 warning（依赖 §2.5 源码整改）
cargo clippy --workspace --no-default-features             # no_std 路径

# 步骤 2：默认 no_std 模式构建（零测试，验证 gate 策略不破坏默认构建）
cargo test --workspace --no-run

# 步骤 3：std 模式全量测试（77 个单元测试；另 6 项 ENG 为规程核查，非 #[test]）
cargo test --workspace --features std

# 步骤 4：no_std 编译验证（M0 退出条件）
cargo check --no-default-features --workspace
for c in rtx-core rtx-buffer rtx-wire rtx-crypto; do
  cargo check --no-default-features -p "$c"
done

# 步骤 5：可选交叉编译（允许降级并记录）
rustup target add thumbv7em-none-eabihf
cargo check --no-default-features --workspace --target thumbv7em-none-eabihf

# 步骤 6：文档构建（可选，防断链）
cargo doc --workspace --no-deps --all-features
```

### 6.2 CI 矩阵建议（对应 §20:481-482 "CI matrix for std and no_std targets"）

| Job | 命令 | 门槛 |
|---|---|---|
| `linux-std` | fmt check + clippy（`--all-targets --all-features` 与 `--no-default-features` 两路径）+ `cargo test --workspace --features std` + `cargo check --no-default-features --workspace` | 全绿 + 零 warning |
| `no-std-target` | `cargo check --no-default-features --target thumbv7em-none-eabihf`（先 `rustup target add`） | 通过；基础设施不具备时允许 skip 并在报告注明 |

---

## 7. 通过标准与 M0 退出条件

1. **用例全通过**：`cargo test --workspace --features std` 下 **77 个单元测试全部通过**（core 23 + buffer 15 + wire 22 + crypto 17），0 failure；另 **6 项工程核查**（ENG-PROFILE/TESTSTRAT/NOSTD-001/002、LINT-001/002）为命令/配置级核查规程（非 `#[test]` 函数），按 §6.1 序列逐项满足。Round 1/2 报告按"77 单测 + 6 工程核查"口径计数（架构审阅 M2 修订；合计设计项 83）。
2. **no_std 编译通过**：`cargo check --no-default-features --workspace` 零错误（宿主）；thumbv7em 交叉编译尽力通过或记录降级。
3. **clippy 零 warning**：`--all-targets --all-features` 与 `--no-default-features` 两路径均零 warning，**含测试代码**。前置：Engineer 完成既有 34 条源码级 warning 整改（§2.5）。
4. **工程前提落地**：`[profile.test] panic = "unwind"` 已加入 workspace `Cargo.toml`（ENG-PROFILE-001）。
5. **M0 退出条件达成**（ARCHITECTURE.md:485）：foundation crates 在至少一个 no_std target 无 default features 编译通过 + Linux 上带 std 编译并通过测试。
6. **无 Known Issue 遗留**：第 2 轮复测仍失败项按 §9 路由并记入最终报告。

---

## 8. 风险登记（按严重度排序）

| # | 风险 | 等级 | 说明与证据 | 缓解 |
|---|---|---|---|---|
| R1 | **`set_len`/`as_mut_slice` 语义不对称被误用** | 高 | `FixedBuf::as_mut_slice` 返回**全容量**（buffer:71-73）、`BorrowedBuf` 同样（buffer:116-118），而 `as_slice` 只暴露 `len`（buffer:67-69、112-114）；`set_len` 超限只报错不改状态（buffer:59-65）。若 M1 协议层把 `as_mut_slice().len()` 当可用空间、或忽略 `set_len` 失败继续写，将引入脏数据/逻辑越界 | BUF-FIXED-004/005、BUF-BORROWED-003 以契约形式冻结"写视图=capacity、读视图=len、错误无副作用"；§4 用例预期中显式警示 |
| R2 | **no_std 测试 harness 与 `panic=abort` 的构建耦合** | 高 | `default = []`（Cargo.toml:8-10）使 `cargo test` 默认在 no_std 模式编译测试目标；ws:28/32 两处 `panic = "abort"`。若策略选择错误（如模式 B）或未来工具链改变 test profile 行为，测试构建断裂 | ENG-PROFILE-001 显式 `[profile.test] panic = "unwind"`；ENG-TESTSTRAT-001 双模式验证；§1.5 E3/E5/E6 已实测两种模式与 panic 行为 |
| R3 | **clippy pedantic 基线已有 34 条源码级 warning** | 中高 | E7 实测：22 条 `missing_errors_doc` + 12 条 `must_use_candidate`，分布于四个 lib。"零 warning"通过标准当前不满足 | ENG-LINT-001 记录并路由 Engineer 整改；QA 不代改源码；整改前后状态在最终报告如实记载 |
| R4 | `Cursor::remaining` 潜在 panic 路径 | 中 | wire:42 直接以 `self.input[self.offset..]` 切片索引，若 `offset > input.len()` 会 panic。当前公开 API 不可达该状态（`take` 失败不推进 offset，wire:50），但 M1 若新增操作 offset 的 API 有回归风险 | WIRE-CUR-004/011 固定"错误路径 offset 不变 + `remaining` 返回 `&'a`"契约；文档向 M1 明示该不变量 |
| R5 | AEAD 缓冲触碰顺序 | 中 | 若 mock/实现在尺寸检查失败前就写缓冲，违反"调用方缓冲"契约语义（§12:290） | CRYPTO-AEAD-005 断言"`OutputTooSmall` 时缓冲未被修改"；mock 策略（§5.4）文档化 |
| R6 | thumbv7em 目标缺失 | 低 | 沙箱仅装 x86_64 target（E8），交叉验证可能因网络/目标安装失败降级 | ENG-NOSTD-002 设计为可降级；宿主 no_std 编译 + CI 占位兜底（§20:485） |
| R7 | `BufferError::InsufficientCapacity`/`WireError::InvalidValue` 预留变体语义未定义 | 低 | buffer:6、wire:7 定义了但无使用方；M1 启用时若无统一约定易出现同错多码 | BUF-ERR-001/WIRE-ERR-001 冻结可构造性；语义分配留待 M1 codec 设计时统一（本文档记录备忘） |

---

## 9. 测试轮次与路由规则（团队协议）

1. **Round 1**：工程师按本设计实现测试 → QA 运行 `cargo test --workspace --features std` 及静态检查 → 分析。
2. 路由决策：
   - **→ Engineer（Alex）**：断言符合 ARCHITECTURE/PRD 契约但实现输出不符（源码 bug）。报告：失败用例、期望 vs 实际、源码位置、错误信息。
   - **→ QA（自修）**：断言自身写错（测试 bug），QA 自行修正，计 Round 1 完成。
   - **→ NoOne**：全部通过，出具成功报告。
3. **Round 2**：收到修复后回归复测；仍失败则**立即收尾**，剩余项记入最终报告 "Known Issues"，不进入 Round 3。
4. 特殊路由：§2.5 的 34 条源码级 clippy warning 与 §8 风险项属**源码问题**，一律路由 Engineer，QA 不代改。

---

## 附录 A：用例索引与统计

| Crate | 分组 | 用例数 | ID 区间 |
|---|---|---:|---|
| rtx-core | CORE-TIME | 15 | CORE-TIME-001..015 |
| rtx-core | CORE-ADDR | 5 | CORE-ADDR-001..005 |
| rtx-core | CORE-SM | 3 | CORE-SM-001..003 |
| rtx-buffer | BUF-ERR | 1 | BUF-ERR-001 |
| rtx-buffer | BUF-FIXED | 7 | BUF-FIXED-001..007 |
| rtx-buffer | BUF-BORROWED | 4 | BUF-BORROWED-001..004 |
| rtx-buffer | BUF-POOL | 3 | BUF-POOL-001..003 |
| rtx-wire | WIRE-ERR | 1 | WIRE-ERR-001 |
| rtx-wire | WIRE-CUR | 11 | WIRE-CUR-001..011 |
| rtx-wire | WIRE-WR | 6 | WIRE-WR-001..006 |
| rtx-wire | WIRE-CODEC | 4 | WIRE-CODEC-001..004 |
| rtx-crypto | CRYPTO-ERR/ALG | 2 | CRYPTO-ERR-001、CRYPTO-ALG-001 |
| rtx-crypto | CRYPTO-RAND/HASH/HMAC | 3 | CRYPTO-RAND-001、CRYPTO-HASH-001、CRYPTO-HMAC-001 |
| rtx-crypto | CRYPTO-AEAD | 5 | CRYPTO-AEAD-001..005 |
| rtx-crypto | CRYPTO-SIG | 2 | CRYPTO-SIG-001/002 |
| rtx-crypto | CRYPTO-KEX | 2 | CRYPTO-KEX-001/002 |
| rtx-crypto | CRYPTO-COMBO | 3 | CRYPTO-COMBO-001..003 |
| 工程 | ENG | 6 | ENG-PROFILE-001、ENG-TESTSTRAT-001、ENG-NOSTD-001/002、ENG-LINT-001/002 |
| **小计：单元测试** | — | **77** | — |
| **小计：工程核查** | — | **6** | — |
| **合计（设计项）** | — | **83** | — |

口径说明（架构审阅 M2 修订）：`cargo test` 只执行 77 个 `#[test]`；6 个 ENG 项是验证规程（命令/配置核查），不计入单测数。通过标准表述为"77 个单元测试全部通过 + 6 项工程核查全部满足"。

覆盖核对：§3 矩阵中每个公开 API 项均映射到 ≥1 个用例 ID；任务要求逐项核对结果——rtx-core 12 项要求全部覆盖（TIME-001..015、ADDR-001..005、SM-001..003）；rtx-buffer 7 项全部覆盖（ERR-001、FIXED-001..007、BORROWED-001..004、POOL-001..003）；rtx-wire 6 项全部覆盖（ERR-001、CUR-001..011、WR-001..006、CODEC-001..004）；rtx-crypto 7 项全部覆盖（ERR-001、ALG-001、RAND/HASH/HMAC/AEAD-001..005、SIG-001/002、KEX-001/002、COMBO-001..003）；工程 4 项全部覆盖（NOSTD-001、PROFILE-001、TESTSTRAT-001、LINT-001）。

---

*本文档仅含测试设计，不含测试代码，未修改任何 `src/` 与 `Cargo.toml`。实现阶段由工程师按 §4/§5 落码，QA 按 §6/§9 执行与路由。*

---

**修订记录（按架构审阅报告）**：本文档已按《RTX M0 测试用例设计 — 架构审阅报告》（架构师 高见远，结论 CONDITIONAL PASS：2 major + 9 minor）完成表述级修订——

| 项 | 修订内容 |
|---|---|
| M1 | CRYPTO-COMBO-001 删除"经 `&MockCrypto as &dyn`"错误表述，改为纯静态分发冒烟，并记录 `dyn CryptoProvider` 不可构造的原因（关联类型 `PrivateKey` 违反对象安全 E0191 + §12:292） |
| M2 | §6.1 步骤 3、§7 通过标准、附录 A 合计行统一改为"77 个单元测试 + 6 项工程核查"口径（合计设计项 83 不变） |
| m1 | §4.3 新增 WIRE-WR 组注：`Writer::put` Overflow 分支不可达的推导与"故意不覆盖"决策显式记录 |
| m2 | §4.4 CRYPTO-RAND-001 与 §5.4 补充 `Cell<u64>` 内部可变性注记 |
| m3 | §4.4 CRYPTO-KEX-001 给出交换算术具体公式（`pub = priv·G`、`secret = priv·peer_pub`，wrapping） |
| m4 | §2.4 更正"mock 须 Debug"论断为"公开导出才触发，私有 mock 不触发但建议加" |
| m5 | §2.5 更正 `must_use_candidate` 定性为"公开只读方法/构造器（11 个 const fn + `Cursor::remaining`）" |
| m6 | §4.1 CORE-SM-001 引用由 §7:174-176 改引 core:139 与 §7:190-192 |
| m7 | §4.4 CRYPTO-COMBO-003 "五条要求"更正为"六条要求" |
| m8 | §4.3 WIRE-CUR-006 引用由 §11:277 改引 §16:401 |
| m9 | §1.4 增补行号效力注记：整改后行号位移，实现以 API 名称为准 |

本次修订**不改变用例集合与预期结果**，仅表述与引用修正。另：§2.1 附工程师 Round 1 实测的实现注记（`[profile.test] panic` 显式声明在 cargo 1.93 触发 warning 与零 warning 标准冲突，实现阶段未添加，已报备主理人裁决）。
