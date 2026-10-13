# RTX M0 测试用例设计 — 架构审阅报告

| 项 | 内容 |
|---|---|
| 文档类型 | 架构审阅（只读审阅，未编写/修改任何测试代码与 `src/`、`Cargo.toml`） |
| 审阅对象 | `docs/m0-test-design.md`（QA 工程师 严过关，83 例设计） |
| 审阅人 | 架构师 高见远（Bob） |
| 派发 | 主理人 齐活林，团队 `software-rtx-m0` |
| 契约权威来源 | `ARCHITECTURE.md`（§7–§12、§18、§20、§21）、四个 crate `src/lib.rs`、workspace 与各 crate `Cargo.toml`、`DEPENDENCY_AUDIT.md` |
| 环境 | rustc/cargo 1.93.0（沙箱实测，与 QA 基线一致） |
| 结论 | **CONDITIONAL PASS**（2 项必须修复，均为文档/流程级，不回退重设计） |

---

## 一、审阅结论

### CONDITIONAL PASS

设计文档整体质量高：覆盖矩阵完整、预期结果与源码语义逐条一致、行号引用准确（抽查约 70 处全部正确）、工程策略经过实测验证且我本人已独立复现关键实验。**无需回退 QA 重新设计**，可直接进入实现阶段，但以下 2 项必须修复（详见 §四 问题清单）：

| # | 必须修复项 | 级别 | 处理方式 |
|---|---|---|---|
| F1 | CRYPTO-COMBO-001 中"经 `&MockCrypto as &dyn`…"表述错误：`dyn CryptoProvider` **不可构造**（`SignatureProvider`/`KeyExchangeProvider` 的关联类型 `PrivateKey` 出现在方法参数/返回位，违反对象安全规则；本人以真实 crate 实测复现 E0191 编译错误）。工程师若按字面实现必然编译失败 | major | QA 修订文档为静态分发；工程师按本报告 §五 指令执行 |
| F2 | 通过标准"83/83 通过"表述不精确：`cargo test` 实际只执行 **77 个 `#[test]`**，另 6 个 ENG 项是验证规程（命令/配置核查）而非测试函数。按现表述，Round 1 验收时必然出现计数对不上数的争议 | major | QA 修订 §7.1/§6.1/附录 A 为"77 单测 + 6 工程核查" |

另有一项架构裁定（非文档缺陷）：**源码 34 条 clippy pedantic warning 的整改纳入工程师实现范围**（§3.5 详述理由）。

问题总量：**11 项 = blocker 0 / major 2 / minor 9**。

---

## 二、审阅范围与方法

本审阅为只读操作。除逐行核对文档与源码外，本人在沙箱独立复现/复核了 QA 的全部关键实测声明：

| 复验命令 | QA 声明 | 本人复验结果 | 结论 |
|---|---|---|---|
| `cargo check --no-default-features --workspace` | E2 通过 | 通过 | ✅ 属实 |
| `cargo test --no-run`（无 feature） | E3 零测试编译通过 | 通过（4 个 test 可执行文件生成） | ✅ 属实 |
| `cargo test --workspace --features std --no-run` | E4 workspace 级 feature 一次性生效 | 通过（4 crate 全部带 std 构建） | ✅ 属实 |
| 沙箱对照：`panic="abort"` 下 `#[should_panic]` | E5：cargo 1.93 test profile 已强制 unwind | dev 与 release 下 `should panic ... ok` 均通过 | ✅ 属实 |
| `cargo clippy --workspace --all-targets --all-features` | E7：34 条（22 `missing_errors_doc` + 12 `must_use_candidate`） | **34 条，分类与数量完全一致**（详见附录 A） | ✅ 属实 |
| `cargo clippy --workspace --no-default-features` | — | 同样 34 条（源码级，与 feature 无关） | 补充事实 |
| `rustup target list --installed` | E8：仅 x86_64 | 仅 `x86_64-unknown-linux-gnu` | ✅ 属实 |
| `&dyn CryptoProvider` 对象安全性（以真实 rtx-crypto 建临时 crate 实测） | QA 未测 | **E0191 编译错误**：`associated types PrivateKey ... must be specified` | ⚠️ 发现 F1 |

另核对：`DEPENDENCY_AUDIT.md:458-462` 确为 target 构建命令清单（含 `thumbv7em-none-eabihf`，:460），QA 引用准确。

---

## 三、分项审阅记录

### 3.1 覆盖完整性 — PASS

**矩阵完整性**：逐项核对四个 crate 的全部公开 API（类型/trait/方法/运算符 impl/关联类型），矩阵 §3.1–§3.4 每一行均有 ≥1 个用例 ID，无遗漏：

- **rtx-core**：`Timestamp`/`Duration` 全部方法与 derives、6 个运算符 impl（Add/AddAssign/Sub/SubAssign × 两类）、`Clock`、`IpAddr`/`SocketAddr`/`DatagramMeta`/`EcnCodepoint`、`Input`/`RuntimeAction`/`ProtocolMachine`（含 GAT）→ 全部覆盖。
- **rtx-buffer**：`BufferError` 两变体、`PacketBuf` 5 个必需方法 + 2 个默认方法（`is_empty` buffer:20-22、`remaining_mut` buffer:24-26）、`FixedBuf`（含 `new`/`Default`）、`BorrowedBuf`（含 `new`/`with_len`）、`BufferPool`（含 `type Buffer: PacketBuf` 上界 buffer:125）→ 全部覆盖。
- **rtx-wire**：`WireError` 4 变体、`Decode`/`Encode` 两 trait、`Cursor` 6 方法、`Writer` 6 方法 → 全部覆盖。
- **rtx-crypto**：`CryptoError` 7 变体、4 个算法枚举、6 个 provider trait + `CryptoProvider` 组合、两个 `PrivateKey` 关联类型 → 全部覆盖。

**M0 契约点冻结核验**（对照 ARCHITECTURE.md）：

| 契约点 | 冻结用例 | 结论 |
|---|---|---|
| 饱和算术（§8:216） | CORE-TIME-004/005/006/007/008/009/010 | ✅ |
| 禁止 wall-clock（§8:205、§18:422） | CORE-TIME-014（mock 时钟）；全集无真实时钟/随机/sleep | ✅ |
| 地址模型不依赖 `std::net`（§9:221） | CORE-ADDR-001..005 + ENG-NOSTD-001（no_std 编译即强制验证） | ✅ |
| PacketBuf 契约（§10:245-253） | BUF-FIXED-001..007、BUF-BORROWED-001..004、BUF-POOL-001..003 | ✅ |
| Decode/Encode borrowed 语义（§11:273） | WIRE-CODEC-004（Blob 借用输入 + 编译期生命周期） | ✅ |
| 原地 AEAD（§12:289） | CRYPTO-AEAD-001..005 | ✅ |
| 不透明私钥句柄（§12:291） | CRYPTO-SIG-001（`MockPrivateKey(u64)` 停留在 provider 内） | ✅ |

**任务点名的四个细节**全部覆盖：
- `Duration::from_millis` 饱和 → CORE-TIME-009（core:37 `saturating_mul`，临界值算术正确，见 §3.2）；
- `Cursor::take` 的 `checked_add` Overflow 防护 → WIRE-CUR-006（wire:46，且正确区分 Overflow 与 UnexpectedEnd 两条路径）；
- Writer `OutputTooSmall` 后 offset 不回退 → WIRE-WR-004（wire:93 提前返回，offset 未推进）；
- `FixedBuf::new` 为 const fn → BUF-FIXED-001 步骤 1（buffer:36 const 上下文构造）。

**唯一未覆盖分支**（minor m1）：`Writer::put` 的 `checked_add` Overflow 分支（wire:86-89）无用例。经分析该分支**不可达**：由不变式 `offset ≤ output.len()` 且合法切片长度 ≤ `isize::MAX`，有 `offset + input.len() ≤ 2·isize::MAX = usize::MAX − 1 < usize::MAX`，加法永不溢出。不测试它是正确决策，但设计文档未显式记录该决策（留白易被误读为遗漏）。

### 3.2 预期结果正确性 — PASS

抽查约 40 个用例的"预期结果"与源码实际语义逐条比对，全部一致。关键抽查证据：

| 用例 | 设计断言 | 源码证据 | 结论 |
|---|---|---|---|
| CORE-TIME-009 | `m = u64::MAX/1000` 时 `from_millis(m)` 不饱和；`m+1` 饱和为 `u64::MAX` | core:37 `saturating_mul(1_000)`；`m·1000 = 18_446_744_073_709_551_000 < u64::MAX`；`(m+1)·1000 = 18_446_744_073_709_552_000 > u64::MAX` | ✅ 算术精确 |
| CORE-TIME-004 | `MAX−10 + 10` 恰等于 MAX；`+11` 饱和 | core:49 `saturating_add` | ✅ |
| CORE-TIME-015 | `(a−b) == a.saturating_duration_since(b)` | core:63 `Sub` 直接委托 `saturating_duration_since` | ✅ 同源 |
| CORE-TIME-003 | 三个构造器均可用于 const 上下文 | core:12/20/36 均为 `const fn` | ✅ |
| CORE-ADDR-002 | `SocketAddr::new` 可用于 const | core:113 `pub const fn new` | ✅ |
| BUF-FIXED-003 / BUF-BORROWED-003 | `set_len` 超限报错且状态不变 | buffer:60-62（FixedBuf）/ buffer:105-107（BorrowedBuf）：先校验后赋值，错误路径不触达 `self.len = len` | ✅ 无副作用 |
| BUF-FIXED-005 | `as_mut_slice().len() == capacity()` 与 `len` 无关 | buffer:71-73 返回 `&mut self.storage`（全容量） | ✅ |
| BUF-FIXED-004 | `as_slice` 仅暴露 `[..len]` | buffer:67-69 | ✅ |
| BUF-POOL-001 | `len>capacity` 时 `remaining_mut()==0` 不回绕 | buffer:25 `saturating_sub` | ✅ |
| WIRE-CUR-003 | `offset==len` 时 `take(0)` 合法 | wire:49 `get(5..5)` 为 `Some` | ✅ |
| WIRE-CUR-006 | 5 字节输入 `take(usize::MAX)` → `Overflow`；空输入同样调用 → `UnexpectedEnd` | wire:46 `checked_add` 溢出先行返回；`0+MAX` 不溢出落入 wire:50 `get` 失败 | ✅ 双路径区分正确 |
| WIRE-CUR-011 | `remaining()` 生命周期绑定输入而非 `&self` | wire:41-42 签名 `&'a [u8]`，索引 `self.input[self.offset..]` | ✅ 编译期可冻结 |
| WIRE-WR-004 | `OutputTooSmall` 后 offset 不变、无部分写入 | wire:90-93 `get_mut` 失败即返回，:94 `copy_from_slice` 与 :95 赋值在其后 | ✅ |
| WIRE-WR-002/005 | `put(&[])` 在任意 offset 合法 | wire:91 `get_mut(k..k)` 恒 `Some` | ✅ |
| WIRE-CODEC-001 | 多余字节时 `consumed==5` | wire:15 `(Self, usize)` 契约 | ✅ |
| CRYPTO-AEAD-001 | seal 返回 `plaintext_len + tag`，原地往返 | crypto:66-74/76-83 签名即该语义 | ✅ |

**QA 风险点专项核验**：

- **R1（写视图=全容量 / 读视图=len / set_len 错误无副作用）**：设计文档的冻结描述（§4.2 BUF-FIXED-004/005、BUF-BORROWED-003 及 §8 R1 行）与源码**完全一致**——`as_mut_slice` 返回全容量（buffer:71-73、buffer:116-118），`as_slice` 只暴露 `len`（buffer:67-69、buffer:112-114），`set_len` 超限报错且不改状态（buffer:59-65）。冻结描述准确，**R1 的语义警示成立且必要**（这是 M1 最容易误用的不对称契约）。
- **R4（`Cursor::remaining` 潜在 panic）**：QA 的次级风险分析**成立且结论正确**。不变式证明：`offset` 初值 0；`take`（wire:45-53）仅在 `get(offset..end)` 成功（即 `end ≤ input.len()`）后才执行 `self.offset = end`（wire:51）；`u8`/`u16_be`/`u32_be` 全部委托 `take`。故对公开 API 的所有调用序列恒有 `offset ≤ input.len()`，`&self.input[self.offset..]`（wire:42）**不可能 panic**。QA 将其降级为"当前不可达、M1 新增操作 offset 的 API 时有回归风险"并保留 WIRE-CUR-004/011 固化该不变量，处理得当。

**行号引用审计**：抽查约 70 处 `文件:行号`（core/buffer/wire/crypto/ws/ARCHITECTURE/DEPENDENCY_AUDIT），除 4 处轻微不贴切外全部准确（见 minor m5–m8）。

### 3.3 策略可行性 — PASS

1. **模式 A gate + `cargo test --workspace --features std`：成立**（本人复现 E3/E4）。四个 crate `#![cfg_attr(not(feature = "std"), no_std)]`（各 lib.rs:1）+ `default = []`（各 Cargo.toml:8-10）事实无误；`--features std` 在 workspace 级一次性作用于四 crate 已实测。模式 B（`#[cfg(test)] extern crate std`）的宏导入摩擦分析合理，选 A 正确。
2. **`[profile.test] panic = "unwind"`：非功能必需，但建议保留**。本人独立复现 E5：在 `[profile.dev]/[profile.release] panic="abort"` 的临时 crate 中，`#[should_panic]` 用例在 `cargo test` 与 `cargo test --release` 下均通过——cargo 1.93.0 确已对 test profile 强制 unwind。显式声明的价值在于意图文档化与防工具链行为回归，且为零风险的单行构建配置变更（不触碰 `src/`）。**裁定：按 ENG-PROFILE-001 保留**，但工程师与 QA 应知晓其在 1.93 上不构成硬前提（E5 注记已在文档中如实说明，无需修改）。
3. **no_std 验证策略满足 M0 退出条件**：§20:485 要求"at least one no_std target + Linux std"。架构裁定：
   - 宿主 `cargo check --no-default-features --workspace` 以 `#![no_std]` 形态编译四个 crate，**已在编译期证明 crate 代码零 std 依赖**（含 §9:221 的 `std::net` 禁令），满足退出条件的实质；
   - 为对齐字面与 ARCHITECTURE.md:522（"compile-test CI for Linux plus one `no_std` target"），ENG-NOSTD-002 的 thumbv7em 交叉编译应**尽力执行**（`rustup target add thumbv7em-none-eabihf`）；沙箱仅装 x86_64（E8 复验属实），网络不可用时允许降级，但**必须在最终测试报告记录降级原因**，且 CI 矩阵保留该 job。设计现行处理（可降级 + 宿主兜底 + CI 占位）**认可**。

### 3.4 范围与粒度 — PASS

- **总量核验**：77 个单元测试（core 23 + buffer 15 + wire 22 + crypto 17）+ 6 个工程核查规程 = 设计所称 83 项。附录 A 分组计数正确。
- **冗余度**：无明显冗余或过度测试。近似项均有独立契约理由：CORE-TIME-015 冻结"运算符与显式方法同源"（防未来实现分叉）；CORE-TIME-011/012/013 分别冻结 Ord/Hash/Copy 三个 derive（定时器堆、哈希键、热路径按值传递三个不同消费场景）。BUF 组的正/边/错分层与 wire 组的 offset 不变量逐案固化，粒度与契约风险匹配。
- **M0 范围边界**：无 M1+ 协议编解码混入。WIRE-CODEC-001..004 的 `Ping`/`Blob` 是冻结 `Decode`/`Encode` trait 形状的**最小示例消息**（wire:12-24 属 M0 契约），非 RTP/RTCP/STUN/QUIC/H3 协议测试；差分/fuzz/互操/真实密码学向量均已正确划到 M1/M2/M3+（§1.3 与 §20 各里程碑一一对应）。
- **mock 复杂度**：与 trait 数量匹配（6 个 crypto provider mock + 组合体、2 时钟、1 状态机、1 池、1 探测 buf、2 示例消息），全部确定性、无 I/O、无堆分配范式（CRYPTO-COMBO-003 显式固化）。合理。跨 crate 不建集成测试的决策（§5.2）正确——四 crate 无相互依赖（各 Cargo.toml 无 `[dependencies]`，已核验），无可组合点。

### 3.5 源码级已知问题 — 数量确认，架构结论：纳入工程师范围

**独立复核结果**（`cargo clippy --workspace --all-targets --all-features`，沙箱实测）：

| 类别 | 数量 | 分布 |
|---|---|---|
| `missing_errors_doc`（公开 fn 返 `Result` 缺 `# Errors` 段） | 22 | core 1（core:159 `handle_input`）、buffer 2（:16 `set_len`、:87 `with_len`）、wire 10（:15/:23/:45/:55/:59/:64/:85/:99/:103/:107）、crypto 9（:42/:46/:55/:66/:76/:91/:99/:111/:117） |
| `must_use_candidate` | 12 | core 7（:12/:16/:20/:32/:36/:40/:113）、buffer 1（:36）、wire 4（:33/:37/:41/:81） |
| **合计** | **34** | core 8 / buffer 3 / wire 14 / crypto 9 |

与 QA E7 声称的数量、类别、分布**完全一致**。`--no-default-features` 路径同样 34 条（源码级，与 feature 无关）。完整清单见附录 A。

**架构结论：将"源码整改达到零 warning"纳入工程师实现范围。** 理由：

1. **质量定位**：RTX 是高质量基础库，M0 是契约冻结里程碑；workspace lints 已显式配置 clippy `all` + `pedantic`（ws:21-23），这 34 条是**lint 配置与源码现状之间的差距**，属源码完成度问题，不是测试问题。
2. **闭环必要**：ENG-LINT-001 的通过标准是"两路径零 warning，**含测试代码**"。源码 34 条不整改，该标准永远无法满足，测试实现无法闭环，M0 退出条件 #3 落空。
3. **成本与风险**：整改均为属性/文档级（12 个 `#[must_use]` + 22 段 `# Errors` 文档），**不触碰任何契约语义与 API 形状**，零行为风险；且 `#[must_use]` 与契约冻结方向一致（构造器/读取器的返回值本就不应被忽略）。
4. **时点恰当**：M0 冻结期是补文档锁定的最后自然时点；拖到 M1 会让协议层继承一套带警告的基线。

**整改约束（须写入工程师指令）**：只加 `#[must_use]` 与 `# Errors` 文档段；不得为消 warning 改变 API 签名、错误码或行为；`# Errors` 内容须与源码实际错误路径逐条对应（不得虚写）。

---

## 四、问题清单

### Blocker（0 项）

无。

### Major（2 项）

**M1 — CRYPTO-COMBO-001 的 `&dyn` 表述错误，按字面实现必然编译失败**
- 位置：`docs/m0-test-design.md` §4.4 CRYPTO-COMBO-001 步骤："冒烟：经 `&MockCrypto as &dyn`…（静态分发）依次调用各类能力各一次成功"。
- 证据：`SignatureProvider`（crypto:88-106）的 `sign` 以 `&Self::PrivateKey` 为参数、`KeyExchangeProvider`（crypto:108-124）的 `generate_key` 返回 `Self::PrivateKey`——关联类型出现在方法参数/返回位，`dyn CryptoProvider` 不可构造。本人以真实 rtx-crypto 建临时 crate 实测：`let _d: &dyn CryptoProvider = p;` → `error[E0191]: the value of the associated types PrivateKey ... must be specified`。文中"（静态分发）"与 "`as &dyn`" 自相矛盾。
- 建议：QA 将该句改为纯静态分发冒烟（依次调用六类能力各一次）；并在注释中记录"dyn 化被 §12:292（no assumption that provider types are dynamically dispatched）与关联类型 `PrivateKey` 排除"。工程师实现时**禁止**出现任何 `dyn CryptoProvider` / `dyn SignatureProvider` / `dyn KeyExchangeProvider` 写法。

**M2 — 通过标准"83/83 通过"与实际可执行测试数不符**
- 位置：`docs/m0-test-design.md` §7.1、§6.1 步骤 3 注释（"全部 83 例"）、附录 A 合计行。
- 证据：6 个 ENG 项中，ENG-PROFILE-001 是 Cargo.toml 配置变更，ENG-TESTSTRAT/NOSTD/LINT-001/002 是命令级核查规程，均非 `#[test]` 函数；`cargo test --workspace --features std` 只会报告 77 个测试。
- 建议：QA 将表述改为"77 个单元测试全部通过 + 6 项工程核查全部满足"，Round 1/2 报告按此口径计数，避免验收争议。

### Minor（9 项）

**m1 — `Writer::put` 的 Overflow 分支无覆盖且未显式记录决策**
- 位置：§3.3 矩阵 `Writer::put` 行 / §4.3 WIRE-WR 组。
- 说明：wire:86-89 的 `checked_add` Overflow 分支不可达（`offset ≤ output.len() ≤ isize::MAX`，`input.len() ≤ isize::MAX`，和 ≤ `usize::MAX−1`）。
- 建议：在 WIRE-WR 组补一句"该分支不可达，故意不覆盖（附推导）"，将留白变为显式决策。

**m2 — 确定性 mock 需要内部可变性，设计未提及**
- 位置：§4.4 CRYPTO-RAND-001（`MockRandom { counter }`，`fill_random(&self)`，crypto:42）、CRYPTO-KEX-001（`generate_key(&self)`，crypto:111）。
- 说明：两个 trait 方法均收 `&self`，但 mock 需推进内部序列——必须使用 `core::cell::Cell<u64>`（no_std 友好；`RefCell` 亦可但无必要）。
- 建议：§5.4 补一条 mock 实现注记；工程师实现时直接采用 `Cell`。

**m3 — CRYPTO-KEX-001 的 mock 算术未指定，交换律无保证**
- 位置：§4.4 CRYPTO-KEX-001："`agree` 计算 `g(priv, peer_pub)`"。
- 说明：断言 `A.agree(a_priv, b_pub) == B.agree(b_priv, a_pub)` 要求 `g` 交换；若工程师自选非交换算术，用例必失败。
- 建议：给出具体公式，如 `pub = priv.wrapping_mul(G)`、`secret = priv.wrapping_mul(peer_pub)`（天然交换），或至少在用例中断言"必须满足交换律"。

**m4 — "mock 须 `#[derive(Debug)]` 满足 ws:19" 论断过度**
- 位置：§2.4。
- 说明：`missing_debug_implementations` 仅对**公开**类型触发；tests 模块内 mock 为私有类型，不触发该 lint。无害但表述不精确。
- 建议：改为"mock 如公开导出则须 Debug；私有 mock 不触发，但加 derive 零成本"。

**m5 — E7 对 12 条 `must_use_candidate` 的定性不够精确**
- 位置：§1.5 E7、§2.5："公开 const fn 建议 `#[must_use]`"。
- 说明：12 条中 11 条为 const fn，wire:41（`Cursor::remaining`）**不是** const fn。数量无误。
- 建议：改为"公开只读方法/构造器建议 `#[must_use]`（其中 11 个为 const fn）"。

**m6 — §7:174-176 引用与"payload 借用"论断不完全匹配**
- 位置：§4.1 CORE-SM-001 预期（"payload 以**借用**进入状态机（§7:174-176）"）。
- 说明：ARCHITECTURE.md:174-176 是"可无 socket 驱动 + 图示起句"；借用语义的直接证据是 core:139 `payload: &'a [u8]`（用例步骤已引）。
- 建议：改引 core:139 或 §7:190-192。

**m7 — "五条要求"计数错误**
- 位置：§4.4 CRYPTO-COMBO-003（"对照 crypto:64 注释与 §12:287-292 五条要求"）。
- 说明：§12:287-292 实为 6 条要求（provider-neutral / no allocation / in-place AEAD / caller-owned buffers / opaque keys / no dyn-or-rc assumption）。
- 建议：改"六条"。

**m8 — §11:277 引用支撑"恶意/畸形长度防御"不贴切**
- 位置：§4.3 WIRE-CUR-006 预期（"§11:277 对恶意/畸形长度的防御"）。
- 说明：ARCHITECTURE.md:277 是"No codec should require Tokio I/O merely to parse..."；畸形长度防御的直接证据是 wire:46 的 `checked_add`（用例已引）。
- 建议：删除该处 ARCHITECTURE 引用或改引 §16:401（超限必须显式错误而非静默）。

**m9 — 源码整改会使设计文档的行号引用集体失准**
- 位置：全文约 70 处 `文件:行号`。
- 说明：工程师补 `#[must_use]` 与 `# Errors` 文档后，四个 lib.rs 行号必然位移。
- 建议：工程师以 **API 名称**为准实现测试；行号仅作设计期证据。QA 如需在整改后复审引用，按 API 名重建映射（低优先，可在 Round 1 前不做）。

---

## 五、给工程师的实现指令摘要

1. **源码整改纳入本次范围（架构裁定）**：将四个 crate 的 34 条 pedantic warning 清零——12 处补 `#[must_use]`（core:12/16/20/32/36/40/113、buffer:36、wire:33/37/41/81）、22 处补 `# Errors` 文档段（清单见附录 A）。**只加属性与文档，不得改变任何 API 签名、错误码与行为**；`# Errors` 须与真实错误路径逐条对应。注意：整改会移动 lib.rs 行号，测试以实现 **API 名称** 为准（设计文档行号仅作设计期证据）。
2. **CRYPTO-COMBO-001 严禁 `&dyn`**：`dyn CryptoProvider` 不可构造（实测 E0191）。六个 crypto provider 一律静态分发（泛型 + `&P`）；组合冒烟按 CRYPTO-COMBO-002 的泛型函数形态写，并在代码注释记录原因（关联类型 `PrivateKey` + §12:292）。
3. **测试放置与执行**：每个 crate 在 `src/lib.rs` 末尾以 `#[cfg(all(test, feature = "std"))] mod tests` 承载全部单元测试（模式 A）；执行统一 `cargo test --workspace --features std`，预期 **77 个测试**（非 83；另 6 项 ENG 为规程核查）。默认 `cargo test`（无 feature）必须保持零测试通过。
4. **工程前提**：workspace `Cargo.toml` 增加 `[profile.test] panic = "unwind"`（防回归声明；cargo 1.93 上非硬前提）；随后依次执行 §6.1 命令序列，含 `cargo check --no-default-features --workspace`（退出条件实质）与 thumbv7em 交叉编译（尽力，失败记录降级原因）。
5. **mock 实现要点**：`MockRandom`/`MockKeyExchange` 的内部序列用 `core::cell::Cell`（trait 方法收 `&self`）；KEX mock 用交换算术（`pub = priv·G`、`secret = priv·peer_pub`，wrapping）；AEAD mock 先校验尺寸与 tag、后写缓冲（CRYPTO-AEAD-005 的"失败不修改缓冲"才有保障）；`FixedBlockPool` 遵循"回收即 `set_len(0)` 重置"约定。
6. **测试代码同样过 pedantic 零 warning**：测试 helper 会触发 `must_use_candidate` 等 pedantic 项——优先补 `#[must_use]`/重构而非 `#[allow]`；确需 allow 时最小化并注释理由。通过标准是 `--all-targets --all-features` 与 `--no-default-features` 两路径均零 warning。
7. **WIRE-WR 的 Overflow 分支**：不写用例（不可达，推导见 m1），但在代码注释中记录该决策。

---

## 六、路由建议

| 事项 | 路由 |
|---|---|
| F1/M1（`&dyn` 表述）、M2（83/83 口径）、m1–m9（文档精确性） | → QA（严过关）修订 `docs/m0-test-design.md`；修订不改变用例集合与预期，仅改表述 |
| 34 条源码 clippy warning 整改 | → Engineer（Alex），按 §五.1 约束执行 |
| 测试实现与 Round 1 执行 | → Engineer 实现 → QA 按修订后口径运行 |

---

## 附录 A：clippy 34 条 warning 完整清单（审阅人实测，`cargo clippy --workspace --all-features --message-format=short`）

**`missing_errors_doc`（22）**：

```
rtx-core/src/lib.rs:159:5     (ProtocolMachine::handle_input)
rtx-buffer/src/lib.rs:16:5    (PacketBuf::set_len)
rtx-buffer/src/lib.rs:87:5    (BorrowedBuf::with_len)
rtx-wire/src/lib.rs:15:5      (Decode::decode)
rtx-wire/src/lib.rs:23:5      (Encode::encode)
rtx-wire/src/lib.rs:45:5      (Cursor::take)
rtx-wire/src/lib.rs:55:5      (Cursor::u8)
rtx-wire/src/lib.rs:59:5      (Cursor::u16_be)
rtx-wire/src/lib.rs:64:5      (Cursor::u32_be)
rtx-wire/src/lib.rs:85:5      (Writer::put)
rtx-wire/src/lib.rs:99:5      (Writer::u8)
rtx-wire/src/lib.rs:103:5     (Writer::u16_be)
rtx-wire/src/lib.rs:107:5     (Writer::u32_be)
rtx-crypto/src/lib.rs:42:5    (RandomProvider::fill_random)
rtx-crypto/src/lib.rs:46:5    (HashProvider::digest)
rtx-crypto/src/lib.rs:55:5    (HmacProvider::hmac)
rtx-crypto/src/lib.rs:66:5    (AeadProvider::seal_in_place)
rtx-crypto/src/lib.rs:76:5    (AeadProvider::open_in_place)
rtx-crypto/src/lib.rs:91:5    (SignatureProvider::sign)
rtx-crypto/src/lib.rs:99:5    (SignatureProvider::verify)
rtx-crypto/src/lib.rs:111:5   (KeyExchangeProvider::generate_key)
rtx-crypto/src/lib.rs:117:5   (KeyExchangeProvider::agree)
```

**`must_use_candidate`（12）**：

```
rtx-core/src/lib.rs:12:18     (Timestamp::from_micros)
rtx-core/src/lib.rs:16:18     (Timestamp::as_micros)
rtx-core/src/lib.rs:20:18     (Timestamp::saturating_duration_since)
rtx-core/src/lib.rs:32:18     (Duration::from_micros)
rtx-core/src/lib.rs:36:18     (Duration::from_millis)
rtx-core/src/lib.rs:40:18     (Duration::as_micros)
rtx-core/src/lib.rs:113:18    (SocketAddr::new)
rtx-buffer/src/lib.rs:36:18   (FixedBuf::new)
rtx-wire/src/lib.rs:33:18     (Cursor::new)
rtx-wire/src/lib.rs:37:18     (Cursor::offset)
rtx-wire/src/lib.rs:41:12     (Cursor::remaining)
rtx-wire/src/lib.rs:81:18     (Writer::offset)
```

注：`--all-targets` 下"lib test"目标会重复报告同样 34 条（当前无测试代码，test 目标与 lib 同源）；测试代码加入后，测试目标将出现其独立的新增 warning，ENG-LINT-001 要求一并清零。

---

*本审阅报告为只读产出，未修改任何 `src/`、`Cargo.toml` 与被审文档。审阅人：高见远（Bob）。*
