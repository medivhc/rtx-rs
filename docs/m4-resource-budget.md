# M4 资源预算（GAP-M4-T-01）

| 项 | 内容 |
|---|---|
| 文档编号 | P8-2 / M4-RB1（资源预算文档） |
| 基线 | `main` @ `52e4ac9`（2026-11-05 PR #52 合并后的头；派单前以 `git ls-remote` 与本地 HEAD 复核一致；原稿起草于 `ea870b6`，已 rebase） |
| 交付形态 | 只新增本文档；不建 `firmware/`、不改 CI、不改门禁、不做选型结论、不合入 |
| 预算对象 | 候选 A：STM32H723ZG / NUCLEO-H723ZG；候选 B：STM32F767ZI / NUCLEO-F767ZI |
| 结论 | 目标选择仍为**未选定**；`M4-V4` 仍为**未核实**（须待 T-02 的 ELF/map 与 T-04 之后的栈/堆实测） |
| 缺口 | `GAP-M4-T-01`，登记在 `docs/m4-target-selection.md` §6，不在 `docs/m3-m4-gates.md` §5 |

> **状态声明**：本文档合并不构成 `M4-V4` 的判定依据，也不构成 `M4-0` 的证据。本文档只把“静态占用 + 最小栈 + 最小堆”的可核实部分与不可核实部分分开登记；`M4-0-2`（最小启动固件链接出 ELF）、`M4-0-3`（`embedded-build` CI 绿）、`M4-0-4`（板上启动）均未开始，本文档不冒称其中任何一项。

---

## 1. 范围与基线

### 1.1 本单范围

- 只新增 `docs/m4-resource-budget.md`。
- 未新建 `measurements/m4/<日期>-<commit>/heap-limit.log`：本单没有在宿主上用固定大小堆跑过“最大负载”，因此不建该目录、不写估算日志；门禁 `M4-RB6` 记未核实（见 §2.3）。
- 未新建 `firmware/`、未加 `embedded-build`/`embedded-lint`/`embedded-size`/`embedded-smoke`/`embedded-memory` 作业（属 T-02 / M4-0-3 范围）。
- 未改 `docs/m4-target-selection.md`、未改 `docs/m3-m4-gates.md`、未改任何 crate 代码或测试、未改 `state.json`/`PIPELINE-LOG.md`/`ERROR-LOG.md`。
- 候选 C（MIMXRT1062DVL6A / MIMXRT1060-EVK）已被 `M4-V9` 否决，本单不做 C，也不以 EVKB/EVKC 替换来规避否决。

### 1.2 基线复核（本单在工作树上逐项重跑）

| 项 | 复核命令/动作 | 结果 |
|---|---|---|
| 主线头 | `git ls-remote https://github.com/medivhc/rtx-rs.git HEAD refs/heads/main` | `52e4ac9269d2237d803c070e4a2c3137b7456470`（PR #52 合并后），与本地 `HEAD` 一致，无漂移 |
| 选型结论 | 读 `docs/m4-target-selection.md` §5.1 | 仍为**未选定**；A/B 的 T 项 2 通过 / 6 未核实，V 项 6 通过 / 4 未核实；C 被 `M4-V9` 否决 |
| 预算文档 | `git cat-file -e 52e4ac9:docs/m4-resource-budget.md` | 存在（`budget-on-main=0`）；本文档已在 main 上，本单只刷新基线快照 |
| 固件目录 | `git ls-tree 52e4ac9 -- firmware` | 空输出（main 上不存在） |
| QUIC 决策/内存报告 | `git cat-file -e 52e4ac9:docs/m4-quic-decision.md`、`git cat-file -e 52e4ac9:docs/m4-memory-report.md` | 均不存在（属 T-04 / M4-M，不是本单产物） |
| CI 作业 | `git show 52e4ac9:.github/workflows/ci.yml` + `grep -n '^  [a-z-]*:'` | 只有 `test`、`suite`、`coverage`、`crypto-vectors`、`proptest`、`fuzz`；无 `embedded-build`。注：该 grep 模式另匹配 `push`（:4）、`group`（:10）、`cancel-in-progress`（:11）三个非 job 键，六作业结论以 job 名核对（YAML `jobs` 解析）为准 |
| ELF/map | `git ls-tree -r --name-only 52e4ac9 -- '*.elf' '*.map'` | 无输出 |
| PR refs | `git ls-remote origin 'refs/pull/4[0-9]/head' 'refs/pull/5[0-9]/head'` | 最大为 `#52`（已合并，2026-11-05；只改 Chrome 互操作报告）；`#46`–`#51` 亦已合并（只改文档/互操作报告）；`#43` 已合并（B0-02 门禁一行）；`#44` 为本文档原始 PR（已合并）。无 M4-T-01 重复单 |
| 代码面差异 | `git diff --stat ea870b6 52e4ac9 -- crates Cargo.toml Cargo.lock .github` | 0 改动；§2.2 的对象级测量仍以 `ea870b6` 工作树为准。口径限定：该命令的 pathspec 中 `Cargo.toml` 只匹配根 `Cargo.toml`；`ea870b6..52e4ac9` 在 `interop/m3/quinn/Cargo.toml` 新增 35 行（quinn 互通 harness 的独立 `[workspace]`，不在根 workspace 成员内、不在 `crates/` 下），不在该命令覆盖范围内 |
| 额外任务列表 | 协调者派前复核（本环境无法访问任务列表） | 无 GAP-M4-T-01 / 资源预算重复项；本单为 M4-T-01 的派单授权 |

> 说明：PR `#43`–`#52` 均已合并，`main` 头为 `52e4ac9`（PR #52 合并后）；本单已 rebase 到该头。`ea870b6..52e4ac9` 只改 `docs/`、`benchmarks/m3/results/` 与 `interop/m3/` 证据文件（含本文档），`crates/`、CI、`Cargo.toml`/`Cargo.lock` 0 改动，§2.2 的对象级测量仍有效。若后续 `main` 再漂移，作者须重新 rebase 并重核 §1.2。

### 1.3 状态口径

本文档每行都给出两个 profile 的独立状态，避免用“一个状态”掩盖其中一列未核实：

- **已核实**：该单元格的数值或“不适用”判定有可复现来源（数据手册修订版 + 页码、仓库代码/测试路径、或本单记录的命令输出）。
- **未核实**：缺来源，或依赖尚未完成的实验/实现。

状态按 profile 分列（`状态（embedded）`、`状态（Linux）`），每格只取 `已核实` 或 `未核实` 之一；“对象级/类型级/本文件登记值”等口径写在来源列或行内说明中。

`已核实` 只表示“该行数值/来源成立”，**不代表** `M4-V4`、`M4-RB2`–`M4-RB6` 或 `M4-0` 的判定结果。

### 1.4 数据手册核对方法

- 候选 A 使用 ST **DS13313 Rev 5（May 2025）** 的 `stm32h723zg.pdf`；核对第 1 页（Features）、第 14 页（Description）、第 17 页（Table 1）。`stm32h723zg.pdf` 直链在沙箱内被站点反爬页拦截，本次用同一 ST 官方 PDF 的阅读结果核对页码与文字；未使用第三方改写页。
- 候选 B 使用 ST **DS11532 Rev 7（February 2021）** 的 `stm32f767zi.pdf`；核对第 1 页（Features）、第 2 页（Table 1 器件汇总）。同族 `stm32f765ig.pdf` 的现行版本为 Rev 9，本单**未采用**，所有 B 的页码均以 Rev 7 为准，不混用两版。
- 板卡侧：UM2407 Rev 6（April 2026）第 7 页 Features；UM1974 Rev 11 第 6 页 Features。
- 每个硬件上限数字都带“修订版 + 页码”；软件上限另给代码/测试路径。

---

## 2. 预算口径

### 2.1 两个 profile

| Profile | 定义 | 本单覆盖度 |
|---|---|---|
| **E0（embedded 基线）** | `no_std` 组件集合：`rtx-core`、`rtx-buffer`、`rtx-wire`、`rtx-crypto`、`rtx-crypto-rustcrypto`、`rtx-stun`、`rtx-ice`、`rtx-dtls`、`rtx-srtp`、`rtx-rtp`、`rtx-rtcp`、`rtx-h3`、`rtx-webtransport`；单会话、单 ICE checklist、单 DTLS 关联（`RecordMachine<1200, RustCryptoProvider>`）、单 RTP 流的 SRTP/SRTCP 上下文各一。**不含 QUIC**（`rtx-quic` 是 Tier D `std` 外观，`quinn-proto` 需要 `std`；M4-Q 尚未判定）。 | 静态与类型尺寸可推导；栈/堆未实测；QUIC 状态未核实 |
| **L0（Linux 基线）** | 现有 `rtx-quic`（`std` + `quinn-proto` + `rustls`）及其配置默认值；其余 crates 在宿主上编译。 | 只登记配置值与已有常量；Linux 二进制、栈、堆均未测 |

E0 的“单会话”是预算单位，不是产品结论：每增加一条 RTP 流，SRTP/SRTCP 上下文增加 `64 + 88 + 64 + 80 = 296` B（Sender + Receiver + SrtcpSender + SrtcpReceiver，见 §2.2 类型尺寸表）；每增加一个 ICE checklist，增加 `10,704` B。

### 2.2 静态占用推导（对象级，不是链接实测）

**方法**：在基线 `ea870b6` 上，用 `rustc 1.92.0`、`--target thumbv7em-none-eabihf`、`--release` 构建 workspace 的 `--no-default-features` 版本；为让对象文件可读，临时覆盖 `CARGO_PROFILE_RELEASE_LTO=false`、`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`（仓库默认 release 是 thin LTO + cgu=1，产物为位码，无法直接取节大小）。随后 `ar x` 解包每个 rlib，用 `size -A *.o` 汇总 `.text*`、`.rodata*`、`.data*`、`.bss*`。这不是 `firmware/m4-smoke` 的链接产物，**不能替代 T-02 的 ELF/map**。

对象级合计按“包含 E0 的全部已实现组件及其 RustCrypto 依赖闭包、不做裁剪”取值，是对 E0 静态代码量的**保守估计**；链接期裁剪可能让它变小，因此它不是链接实测值，也不是“最小代码量”的严格下界。

| crate（E0，排除 `rtx-testkit`、`rtx-quic`） | `.text` (B) | `.rodata` (B) | `.data` (B) | `.bss` (B) |
|---|---:|---:|---:|---:|
| rtx-buffer | 30 | 45 | 0 | 0 |
| rtx-core | 0 | 0 | 0 | 0 |
| rtx-crypto | 0 | 0 | 0 | 0 |
| rtx-crypto-rustcrypto | 17,600 | 578 | 0 | 0 |
| rtx-dtls | 7,622 | 377 | 0 | 0 |
| rtx-h3 | 9,222 | 3,855 | 0 | 0 |
| rtx-ice | 10,350 | 336 | 0 | 0 |
| rtx-rtcp | 13,122 | 742 | 0 | 0 |
| rtx-rtp | 1,638 | 3 | 0 | 0 |
| rtx-srtp | 1,296 | 163 | 0 | 0 |
| rtx-stun | 8,660 | 2,662 | 0 | 0 |
| rtx-webtransport | 2,150 | 272 | 0 | 0 |
| rtx-wire | 2,058 | 123 | 0 | 0 |
| RustCrypto 依赖闭包（`aes-gcm`、`aes`、`ctr`、`ghash`、`polyval`、`universal-hash`、`aead`、`cipher`、`inout`、`opaque-debug`、`crypto-common`、`generic-array`、`typenum`、`subtle`、`zeroize`、`hmac`、`digest`、`sha1`、`sha2`、`block-buffer` 等） | 61,630 | 1,360 | 0 | 0 |
| **合计** | **135,378** | **10,516** | **0** | **0** |

- `.data = 0`：E0 内没有 `static mut`，也没有带初值的可变静态量；`rtx-ice`/`rtx-dtls`/`rtx-srtp` 的状态都是结构体实例，实例化后落 `.bss`。`rtx-quic` 的 `static EPOCH: OnceLock<Instant>`（`crates/rtx-quic/src/time.rs:13`）属 Tier D，不在 E0。
- 上述合计不含编译器内置 `core`/`compiler_builtins` 的运行时支持代码；这部分随链接方式变化，留给 T-02 的 ELF 统计。
- 对象级 `.bss = 0` 只说明“rlib 里没有静态实例”，不是“运行时不需要 RAM”。E0 的固定状态实例按类型尺寸计：

| 对象（每个 profile 一份） | 类型 | thumbv7em 尺寸 (B) | 来源/说明 |
|---|---|---:|---|
| ICE checklist | `rtx_ice::Checklist` | 10,704 | 含两侧 16 候选表、64 pair 表、64 触发队列、8 事件队列；与 `MAX_ICE_CANDIDATES`/`MAX_ICE_PAIRS` 对账一致 |
| ICE 候选 | `rtx_ice::Candidate` | 52 | 单个元素；`16 × 52 × 2 = 1,664` B |
| ICE pair | `rtx_ice::CandidatePair` | 120 | 单个元素；`64 × 120 = 7,680` B |
| DTLS 记录机 | `rtx_dtls::RecordMachine<1200, RustCryptoProvider>` | 4,976 | `N = 1200` 是预算假设（1200 B UDP 负载），不是板上实测 |
| SRTP 发送上下文 | `rtx_srtp::SenderContext<RustCryptoProvider>` | 64 | 单流 |
| SRTP 接收上下文 | `rtx_srtp::ReceiverContext<RustCryptoProvider>` | 88 | 单流 |
| SRTCP 发送上下文 | `rtx_srtp::SrtcpSenderContext<RustCryptoProvider>` | 64 | 单流 |
| SRTCP 接收上下文 | `rtx_srtp::SrtcpReceiverContext<RustCryptoProvider>` | 80 | 单流 |
| H3 SETTINGS 表 | `rtx_h3::settings::Settings` | 520 | `[Setting; MAX_SETTINGS_ITEMS(32)]` |
| **E0 固定状态合计** | — | **16,496** | 上表求和；不含栈、堆、QUIC 状态、板级缓冲 |

**类型尺寸的来源与复现**：在仓库外（`/tmp`）建临时 `no_std` 探针 crate，对每个类型声明 `pub static S: [u8; core::mem::size_of::<T>()] = [0; size_of::<T>()];`，以同一 target/`--release` 编译，再用 `nm -S --size-sort` 读符号大小。探针 crate 不提交，不进入仓库。得到的是**类型尺寸**，不是运行时内存实测。

### 2.3 栈与堆

- **最小栈**：本单没有 `-fstack-usage`（Rust 稳定工具链无此选项）、没有链接 map、没有板上高水位扫描，也没有 ISR 代码。最深调用链只能从代码阅读列出构成，不能给出字节数。因此主栈、中断嵌套栈、栈合计一律**未核实**（见各候选表）。E0 只假设一个主任务；若运行时增加任务，每个任务按其最深链另计（同样未核实）。
  - 已阅读的候选最深链：`RecordMachine::handle_input` → `record::decode` → `RecordCipher::open` → `RustCryptoProvider::open_in_place` → `aes-gcm` 解密；ICE 链：`Checklist::handle_input` → `stun::Message::decode` → 属性遍历 → `MessageWriter` 编码。链上没有递归。
- **最小堆**：E0 内唯一的 `alloc` 使用是 `rtx-crypto-rustcrypto` 的 HMAC 路径：`hmac_parts` 把摘要 `.to_vec()` 成 `Vec<u8>`（`crates/rtx-crypto-rustcrypto/src/lib.rs:214-239`）。E0 实际调用点为 SRTP `HashAlgorithm::Sha1`（`crates/rtx-srtp/src/cipher.rs:149`，20 B）与 DTLS `HashAlgorithm::Sha256`（`crates/rtx-dtls/src/keyschedule.rs:128,145,160`、`crates/rtx-dtls/src/handshake.rs:521`，32 B），因此 **E0 单次分配 ≤32 B（SRTP 20 B / DTLS 32 B）**；SHA-384 的 48 B 仅为 provider 通用面上的摘要长度上界，E0 未选用。这不是全路径 `peak_live_bytes`。
- **固定堆**：本文件把 E0 的初始固定堆登记为 **64 KiB**（门禁 `M4-RB6` 允许由目标决定并登记）。该值是 E0 的整机堆配置（不是每连接/每流），是配置决策，不是实测结论。
- **RB6**：没有在宿主上用固定大小堆跑过 E0 的最大负载（E0 的“最大负载”还缺 QUIC/栈/堆路径），因此没有 `measurements/m4/<日期>-<commit>/heap-limit.log`，`M4-RB6` 记未核实。**不得**用 32 B 或 64 KiB 冒充 RB6 的实测日志。

### 2.4 超限行为口径

超限只允许三类结果之一：

1. **背压**：返回 `WouldBlock`/要求调用方重试；
2. **丢弃**：显式丢弃并计数；
3. **类型化错误**：返回可匹配的错误变体。

不允许第四类结果（无界增长或非类型化终止）。达到上限后继续输入时，`alloc_count` 与 `peak_live_bytes` 不得增加；初始化时按上限预分配是允许的，但必须在实现文档中写明。任何一项写不出这三类行为，就记该项**未核实**，不写“待定”再给一个已核实数值。

> 硬件上限行（Flash/SRAM）的“超限行为”指预算判定动作（越界即 `M4-V4` 否决），不适用 RB2 的三分类；该列在表中另行标注。

---

## 3. 候选 A：STM32H723ZG / NUCLEO-H723ZG

### 3.1 预算表

| 项目 | 数值（embedded） | 数值（Linux） | 单位 | 来源 | 超限行为 | 状态（embedded） | 状态（Linux） |
|---|---|---|---|---|---|---|---|
| 数据手册 Flash 总量 | 1024（ZGT 档） | 不适用（L0 为宿主） | KB | DS13313 Rev 5 p1（up to 1 MB）+ Table 1 p17（ZGT/ZET 列：1024/512） | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| 数据手册 SRAM 总量 | 564 | 不适用（L0 为宿主） | KB | DS13313 Rev 5 p1、p14、Table 1 p17 | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| SRAM 分块 | 128 AXI + 16 SRAM1 + 16 SRAM2 + 16 SRAM4 + 192 shared + 64 ITCM + 128 DTCM + 4 backup = 564 | 不适用（L0 为宿主） | KB | DS13313 Rev 5 p14、Table 1 p17 | 分块用途越界 → 预算修订 | 已核实 | 已核实 |
| 可用 SRAM（剔除 backup） | 560 | 不适用（L0 为宿主） | KB | 564 − 4 的本文档算术；backup 仅低功耗域使用 | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| 外部 RAM（FMC） | 不计入 | 不适用（L0 为宿主） | — | DS13313 Rev 5 p1 说明 FMC 能力；UM2407 Rev 6 p7 Features 未列板载外部 RAM | 未核实到板级预留前不纳入预算 | 未核实 | 已核实 |
| 两处分法对账 | 432 system = 128 AXI + 48 AHB + 192 shared + 64 ITCM；564 = 432 + 128 DTCM + 4 backup | 不适用（L0 为宿主） | KB | DS13313 Rev 5 p1 与 p14/Table 1 p17 的算术对账 | 无冲突；采用 p14/Table 1 的分块明细 | 已核实 | 已核实 |
| `.text`（对象级合计） | 135,378 | —（未构建 L0） | B | §2.2 的 `size -A` 命令与 per-crate 表；commit `ea870b6` | Flash 越界 → `M4-V4` 否决 | 已核实 | 未核实 |
| `.rodata`（对象级合计） | 10,516 | —（未构建 L0） | B | 同 `.text` | 同上 | 已核实 | 未核实 |
| `.data` | 0 | —（未构建 L0） | B | E0 内无 `static mut`；`size -A` 输出 | 同上 | 已核实 | 未核实 |
| `.bss`（固定状态实例） | 16,496 | —（未构建 L0） | B | §2.2 类型尺寸表（`nm -S` 探针） | 同上 | 已核实 | 未核实 |
| Flash 静态合计 | 145,894 | —（未构建 L0） | B | `.text + .rodata + .data` 算术 | 同上 | 已核实 | 未核实 |
| RAM 静态合计 | 16,496 | —（未构建 L0） | B | `.data + .bss` 算术 | 同上 | 已核实 | 未核实 |
| ELF/map 校核 | — | — | — | 待 T-02 链接 `firmware/m4-smoke` 出 ELF 后复核 `cargo size`/`arm-none-eabi-size` 与 map；本单无 ELF/map | 与上表差异 >10% 时修订预算 | 未核实 | 未核实 |
| 主任务栈（最深调用链） | —（无 `-fstack-usage`/map/高水位） | —（未测） | B | 只有 §2.3 的调用链构成，无字节数 | 未核实 | 未核实 | 未核实 |
| 中断嵌套栈 | —（无 ISR/固件） | —（未测） | B | 无中断栈填充扫描 | 未核实 | 未核实 | 未核实 |
| 栈合计 | —（主栈 + 中断栈均无来源） | —（未测） | B | 见上两行 | 未核实 | 未核实 | 未核实 |
| 固定堆大小（初始配置） | 64 | —（系统分配器，未登记上限） | KiB | 本文件 §2.3 登记；`M4-RB6` 允许由目标决定 | 本行只登记大小；耗尽行为见下一行 | 已核实 | 未核实 |
| `peak_live_bytes` | —（未跑固定堆最大负载） | —（未测） | B | 无 `heap-limit.log` | 未核实 | 未核实 | 未核实 |
| E0 单次分配上界（HMAC 摘要） | ≤32（SRTP 20 / DTLS 32） | ≤32（SRTP 20 / DTLS 32） | B | 所属 crate：rtx-crypto-rustcrypto / rtx-srtp / rtx-dtls；`digest_len`（`crates/rtx-crypto-rustcrypto/src/lib.rs:52-58`）Sha1=20 / Sha256=32 / Sha384=48；SRTP 调用 `HashAlgorithm::Sha1`（`crates/rtx-srtp/src/cipher.rs:149`），DTLS 调用 `HashAlgorithm::Sha256`（`crates/rtx-dtls/src/keyschedule.rs:128,145,160`、`crates/rtx-dtls/src/handshake.rs:521`）；SHA-384 的 48 B 仅为 provider 通用面上界，E0 未选用 | 不构成本行峰值 | 已核实 | 已核实 |
| 堆耗尽行为 | 未映射到三类结果 | 未映射到三类结果 | — | E0 无 fallible 分配路径、无分配器失败钩子；`to_vec()` 为不可失败接口 | 必须改为背压或类型化错误 | 未核实 | 未核实 |
| `MAX_ICE_CANDIDATES`（M4-R1） | 16（每侧；机器最多 32） | 16（每侧） | 个 | 所属 crate：rtx-ice；`crates/rtx-ice/src/checklist.rs:28`；`tests/resource_limits.rs::m4_r01_max_ice_candidates_overflow_is_explicit`（本单已跑，2 passed） | 拒绝新候选并返回 `IceError::CandidateTableFull`；已有候选不变；固定数组，无分配（RB3 断言未接入，见 §5.4） | 已核实 | 已核实 |
| `MAX_ICE_PAIRS`（M4-R2） | 64 | 64 | 对 | 所属 crate：rtx-ice；`crates/rtx-ice/src/checklist.rs:39`；`m4_r02_max_ice_pairs_overflow_is_explicit`（本单已跑） | 拒绝整次生成并返回 `IceError::PairTableFull`；已有 pair 不变；固定数组，无分配（RB3 断言未接入，见 §5.4） | 已核实 | 已核实 |
| `MAX_RTP_STREAMS`（M4-R3） | — | — | 个 | 所属 crate：无（`rtx-webrtc` 是 ARCH §5 规划名，仓库不存在）；无流表实现；`rtx-rtp` 只有编解码，无 stream 状态 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_REORDERED_PACKETS`（M4-R4） | — | — | 个 | 所属 crate：rtx-rtp / rtx-webrtc（均无实现）；无 RTP 重排窗口；`rtx-dtls`/`rtx-srtp` 的 replay window 是重放保护，不是 R4 的重排缓冲 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_NACK_HISTORY`（M4-R5） | — | — | 个 | 所属 crate：rtx-webrtc / rtx-rtp（无历史表）；`crates/rtx-rtcp/src/nack.rs` 只有 NACK 编解码与迭代器，`rtx-webrtc` 不存在 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_QUIC_STREAMS_BIDI`（M4-R6） | — | —（`config.rs:50` 的 100 只是传输参数，非本地状态上限） | 个 | 所属 crate：rtx-quic（Tier D）；`quinn-proto` 内部 map 未在本仓库受限 | 未核实 | 未核实 | 未核实 |
| `MAX_QUIC_STREAMS_UNI`（M4-R7） | — | —（`config.rs:51` 的 100 只是传输参数） | 个 | 所属 crate：rtx-quic（Tier D） | 未核实 | 未核实 | 未核实 |
| `MAX_QUIC_DATAGRAM_QUEUE_BYTES`（M4-R8） | — | —（`config.rs:54-55` 的 1,250,000 / 1,048,576 B 是缓冲配置，非显式队列上限） | 字节 | 所属 crate：rtx-quic（Tier D）；`Endpoint::pending_transmits` 无界（`endpoint.rs:92`） | 未核实 | 未核实 | 未核实 |
| `MAX_REASSEMBLY_BYTES`（M4-R9） | — | — | 字节 | 所属 crate：rtx-quic（Tier D）；无显式常量；`stream_receive_window_bytes`（默认 1,250,000 B）语义不同，未映射 | 未核实 | 未核实 | 未核实 |
| `MAX_CONNECTION_IDS`（M4-R10） | — | — | 个 | 所属 crate：rtx-quic（Tier D）；无显式常量；CID 表由 `quinn-proto` 内部拥有 | 未核实 | 未核实 | 未核实 |
| `MAX_PENDING_TIMERS`（M4-R11） | — | — | 个 | 所属 crate：rtx-core / rtx-quic；`rtx_core::ProtocolMachine::next_wakeup` 返回 `Option<Timestamp>`（`crates/rtx-core/src/lib.rs:177`），每状态机至多一个 deadline；全系统 timer 表未登记 | 未核实 | 未核实 | 未核实 |
| `MAX_ACK_STATE_BYTES`（M4-R12） | — | — | 字节 | 所属 crate：rtx-quic（Tier D）；无显式常量；ACK 状态由 `quinn-proto` 内部拥有 | 未核实 | 未核实 | 未核实 |

> 表内“已核实”若用于 `.text`/`.rodata`/`.data`，其口径是“对象级测量”；若用于 `.bss`，其口径是“类型尺寸推导”。两者都不是 ELF/map 校核，ELF/map 行仍为未核实。

### 3.2 容量余量算术（不是 V4 判定）

- Flash：`1,048,576 − 145,894 = 902,682` B，静态对象级余量 86.1%。
- 可用 SRAM：`560 KiB = 573,440` B；`573,440 − 16,496 = 556,944` B，静态固定状态余量 97.1%。
- 该算术**只说明静态部分没有把目标撑爆**；最小栈、最小堆、QUIC 状态、板级缓冲尚未计入，`M4-V4` 仍为未核实。

---

## 4. 候选 B：STM32F767ZI / NUCLEO-F767ZI

### 4.1 预算表

| 项目 | 数值（embedded） | 数值（Linux） | 单位 | 来源 | 超限行为 | 状态（embedded） | 状态（Linux） |
|---|---|---|---|---|---|---|---|
| 数据手册 Flash 总量 | 2048（ZI 档） | 不适用（L0 为宿主） | KB | DS11532 Rev 7 p1（up to 2 Mbytes）+ p2 Table 1 器件汇总（STM32F767ZI 在列） | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| 数据手册 SRAM 总量 | 532（512 + 16 + 4） | 不适用（L0 为宿主） | KB | DS11532 Rev 7 p1（512 Kbytes，含 128 Kbytes data TCM；+16 Kbytes instruction TCM；+4 Kbytes backup） | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| SRAM 已知分块 | 512 内含 128 DTCM；另 16 ITCM；另 4 backup | 不适用（L0 为宿主） | KB | DS11532 Rev 7 p1 | 分块用途越界 → 预算修订 | 已核实 | 已核实 |
| SRAM 其余 384 KB 的 SRAM1/SRAM2 细分 | — | 不适用（L0 为宿主） | KB | 本单只逐页核对了 p1 与 p2；未核对 Table 2 的逐块行 | 未核实 | 未核实 | 已核实 |
| 可用 SRAM（剔除 backup） | 528 | 不适用（L0 为宿主） | KB | 532 − 4 的本文档算术 | 预算越界 → `M4-V4` 否决 | 已核实 | 已核实 |
| 外部 RAM（FMC） | 不计入 | 不适用（L0 为宿主） | — | DS11532 Rev 7 p1 说明 FMC 能力；UM1974 Rev 11 p6 Features 未列板载外部 RAM | 未核实到板级预留前不纳入预算 | 未核实 | 已核实 |
| `.text`（对象级合计） | 135,378 | —（未构建 L0） | B | §2.2 的 `size -A` 命令与 per-crate 表；commit `ea870b6` | Flash 越界 → `M4-V4` 否决 | 已核实 | 未核实 |
| `.rodata`（对象级合计） | 10,516 | —（未构建 L0） | B | 同 `.text` | 同上 | 已核实 | 未核实 |
| `.data` | 0 | —（未构建 L0） | B | E0 内无 `static mut`；`size -A` 输出 | 同上 | 已核实 | 未核实 |
| `.bss`（固定状态实例） | 16,496 | —（未构建 L0） | B | §2.2 类型尺寸表（`nm -S` 探针） | 同上 | 已核实 | 未核实 |
| Flash 静态合计 | 145,894 | —（未构建 L0） | B | `.text + .rodata + .data` 算术 | 同上 | 已核实 | 未核实 |
| RAM 静态合计 | 16,496 | —（未构建 L0） | B | `.data + .bss` 算术 | 同上 | 已核实 | 未核实 |
| ELF/map 校核 | — | — | — | 待 T-02 链接 `firmware/m4-smoke` 出 ELF 后复核尺寸与 map；本单无 ELF/map | 与上表差异 >10% 时修订预算 | 未核实 | 未核实 |
| 主任务栈（最深调用链） | —（无 `-fstack-usage`/map/高水位） | —（未测） | B | 只有 §2.3 的调用链构成，无字节数 | 未核实 | 未核实 | 未核实 |
| 中断嵌套栈 | —（无 ISR/固件） | —（未测） | B | 无中断栈填充扫描 | 未核实 | 未核实 | 未核实 |
| 栈合计 | —（主栈 + 中断栈均无来源） | —（未测） | B | 见上两行 | 未核实 | 未核实 | 未核实 |
| 固定堆大小（初始配置） | 64 | —（系统分配器，未登记上限） | KiB | 本文件 §2.3 登记；`M4-RB6` 允许由目标决定 | 本行只登记大小；耗尽行为见下一行 | 已核实 | 未核实 |
| `peak_live_bytes` | —（未跑固定堆最大负载） | —（未测） | B | 无 `heap-limit.log` | 未核实 | 未核实 | 未核实 |
| E0 单次分配上界（HMAC 摘要） | ≤32（SRTP 20 / DTLS 32） | ≤32（SRTP 20 / DTLS 32） | B | 所属 crate：rtx-crypto-rustcrypto / rtx-srtp / rtx-dtls；`digest_len`（`crates/rtx-crypto-rustcrypto/src/lib.rs:52-58`）Sha1=20 / Sha256=32 / Sha384=48；SRTP 调用 `HashAlgorithm::Sha1`（`crates/rtx-srtp/src/cipher.rs:149`），DTLS 调用 `HashAlgorithm::Sha256`（`crates/rtx-dtls/src/keyschedule.rs:128,145,160`、`crates/rtx-dtls/src/handshake.rs:521`）；SHA-384 的 48 B 仅为 provider 通用面上界，E0 未选用 | 不构成本行峰值 | 已核实 | 已核实 |
| 堆耗尽行为 | 未映射到三类结果 | 未映射到三类结果 | — | E0 无 fallible 分配路径、无分配器失败钩子；`to_vec()` 为不可失败接口 | 必须改为背压或类型化错误 | 未核实 | 未核实 |
| `MAX_ICE_CANDIDATES`（M4-R1） | 16（每侧；机器最多 32） | 16（每侧） | 个 | 所属 crate：rtx-ice；`crates/rtx-ice/src/checklist.rs:28`；`m4_r01_max_ice_candidates_overflow_is_explicit`（本单已跑） | 拒绝新候选并返回 `IceError::CandidateTableFull`；已有候选不变；固定数组，无分配（RB3 断言未接入，见 §5.4） | 已核实 | 已核实 |
| `MAX_ICE_PAIRS`（M4-R2） | 64 | 64 | 对 | 所属 crate：rtx-ice；`crates/rtx-ice/src/checklist.rs:39`；`m4_r02_max_ice_pairs_overflow_is_explicit`（本单已跑） | 拒绝整次生成并返回 `IceError::PairTableFull`；已有 pair 不变；固定数组，无分配（RB3 断言未接入，见 §5.4） | 已核实 | 已核实 |
| `MAX_RTP_STREAMS`（M4-R3） | — | — | 个 | 所属 crate：无（`rtx-webrtc` 规划中，仓库不存在）；无流表实现；`rtx-rtp` 只有编解码 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_REORDERED_PACKETS`（M4-R4） | — | — | 个 | 所属 crate：rtx-rtp / rtx-webrtc（均无实现）；无 RTP 重排窗口；DTLS/SRTP replay window 不是 R4 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_NACK_HISTORY`（M4-R5） | — | — | 个 | 所属 crate：rtx-webrtc / rtx-rtp（无历史表）；`rtx-rtcp/src/nack.rs` 只有编解码 | 未核实（无实现/无超限测试） | 未核实 | 未核实 |
| `MAX_QUIC_STREAMS_BIDI`（M4-R6） | — | —（`config.rs:50` 的 100 只是传输参数） | 个 | 所属 crate：rtx-quic（Tier D）；`quinn-proto` 内部 map 未受限 | 未核实 | 未核实 | 未核实 |
| `MAX_QUIC_STREAMS_UNI`（M4-R7） | — | —（`config.rs:51` 的 100 只是传输参数） | 个 | 所属 crate：rtx-quic（Tier D） | 未核实 | 未核实 | 未核实 |
| `MAX_QUIC_DATAGRAM_QUEUE_BYTES`（M4-R8） | — | —（`config.rs:54-55` 的 1,250,000 / 1,048,576 B 是缓冲配置） | 字节 | 所属 crate：rtx-quic（Tier D）；`pending_transmits` 无界（`endpoint.rs:92`） | 未核实 | 未核实 | 未核实 |
| `MAX_REASSEMBLY_BYTES`（M4-R9） | — | — | 字节 | 所属 crate：rtx-quic（Tier D）；无显式常量；`stream_receive_window_bytes` 语义不同 | 未核实 | 未核实 | 未核实 |
| `MAX_CONNECTION_IDS`（M4-R10） | — | — | 个 | 所属 crate：rtx-quic（Tier D）；无显式常量；由 `quinn-proto` 内部拥有 | 未核实 | 未核实 | 未核实 |
| `MAX_PENDING_TIMERS`（M4-R11） | — | — | 个 | 所属 crate：rtx-core / rtx-quic；`next_wakeup` 每状态机至多一个 deadline；全系统表未登记 | 未核实 | 未核实 | 未核实 |
| `MAX_ACK_STATE_BYTES`（M4-R12） | — | — | 字节 | 所属 crate：rtx-quic（Tier D）；无显式常量；由 `quinn-proto` 内部拥有 | 未核实 | 未核实 | 未核实 |

### 4.2 容量余量算术（不是 V4 判定）

- Flash：`2,097,152 − 145,894 = 1,951,258` B，静态对象级余量 93.0%。
- 可用 SRAM：`528 KiB = 540,672` B；`540,672 − 16,496 = 524,176` B，静态固定状态余量 97.0%。
- 结论边界同上：静态部分不构成否决，但 `M4-V4` 仍为未核实。

---

## 5. 容器 → 上限映射（M4-RB4）

### 5.1 动态容器清单（`Vec` / `VecDeque` / `BTreeMap`）

扫描范围：`crates/*/src/*.rs`（排除测试目录与 `rtx-testkit`）。命令见 §8。E0 内没有 `HashMap`/`BTreeMap`/`VecDeque`；`rtx-quic` 的容器全部属 Tier D。

| 容器 | 类型 | 所属 crate | 状态路径用途 | 映射的 R 条目 | 当前是否有界 | 来源 | 状态 |
|---|---|---|---|---|---|---|---|
| `Endpoint::connections` | `BTreeMap<ConnectionId, ConnectionState>` | rtx-quic | Linux endpoint 连接表 | 无（R10 只覆盖 CID） | 否 | `crates/rtx-quic/src/endpoint.rs:89` | 未核实 |
| `Endpoint::by_quinn_handle` | `BTreeMap<usize, ConnectionId>` | rtx-quic | handle → id 反查 | 无 | 否 | `endpoint.rs:90` | 未核实 |
| `Endpoint::pending_incoming` | `BTreeMap<ConnectionId, Incoming>` | rtx-quic | incoming 待接受队列 | 无 | 否 | `endpoint.rs:91` | 未核实 |
| `Endpoint::pending_transmits` | `VecDeque<PendingTransmit>` | rtx-quic | 发送队列 | 无（R8 只覆盖 DATAGRAM 字节） | 否 | `endpoint.rs:92` | 未核实 |
| `Endpoint::events` | `VecDeque<Event>` | rtx-quic | 事件队列 | 无 | 否 | `endpoint.rs:93` | 未核实 |
| `PendingTransmit::payload` | `Vec<u8>` | rtx-quic | 待发送载荷 | 无 | 否 | `endpoint.rs:75-78` | 未核实 |
| `PeerTransportParameters::encoded` | `Vec<u8>` | rtx-quic | 对端 transport parameters 编码 | 无 | 否 | `crates/rtx-quic/src/event.rs:56` | 未核实 |
| `CloseReason::Application::reason` | `Vec<u8>` | rtx-quic | 关闭原因字节 | 无 | 否 | `crates/rtx-quic/src/event.rs:122` | 未核实 |
| `EndpointConfig::alpn` / `certificate_chain_der` / `client_roots_der` | `Vec<Vec<u8>>` | rtx-quic | 配置期 TLS/ALPN | 无（仅单项 255 B 上限） | 否（列表长度无上限） | `crates/rtx-quic/src/config.rs:62-75` | 未核实 |
| `ServerIdentity::private_key_pkcs8_der` | `Vec<u8>` | rtx-quic | 配置期私钥 DER | 无 | 否（长度无上限） | `crates/rtx-quic/src/config.rs:63`、`crates/rtx-quic/src/config.rs:115` | 未核实 |
| `HandshakeInfo::alpn` | `Option<Vec<u8>>` | rtx-quic | 握手完成时的协商 ALPN | 无 | 否（单个协议 ≤255 B，堆上限未登记） | `crates/rtx-quic/src/event.rs:38` | 未核实 |
| `RustCryptoProvider::hmac_parts` 的 `written` | `Vec<u8>`（每次调用的临时摘要） | rtx-crypto-rustcrypto | HMAC/AEAD 鉴权 | 无（不在 R1–R12；有界但无 R 条目） | 是（E0 ≤32 B；provider 通用面 ≤48 B，SHA-384 未选用） | `crates/rtx-crypto-rustcrypto/src/lib.rs:214-239` | 未核实 |

### 5.2 有界容器与 R 条目

| 容器 | 类型 | 所属 crate | 上限 | 映射的 R 条目 | 来源 | 状态 |
|---|---|---|---|---|---|---|
| `CandidateTable`（local/remote） | `[Option<Candidate>; 16]` + len | rtx-ice | 每侧 16，共 32 | R1 | `checklist.rs:28`；类型尺寸 52 B | 已核实 |
| `PairTable` | `[Option<CandidatePair>; 64]` | rtx-ice | 64 | R2 | `checklist.rs:39`；类型尺寸 120 B | 已核实 |
| `TriggerQueue` | `[u16; 64]` 环 + 头尾 | rtx-ice | 64（复用 `MAX_ICE_PAIRS`） | R2（容量复用） | `checklist.rs:1109-1133` | 已核实 |
| `EventQueue` | `[Option<Event>; 8]` | rtx-ice | 8（`MAX_EVENTS`） | 无 | `checklist.rs:42`、`1157-1178` | 未核实（有界但无 R 条目） |
| `RecordMachine::events` | `[Option<RecordEvent<N>>; 4]` | rtx-dtls | 4（`EVENT_QUEUE_CAPACITY`） | 无 | `machine.rs:47`、`machine.rs:120` | 未核实（有界但无 R 条目） |
| `ReplayWindow`（DTLS） | `u64` 位图 + 游标 | rtx-dtls | 64 个序号 | 无（R4 不是重放窗口） | `replay.rs` | 未核实（有界但无 R 条目） |
| `ReplayWindow`（SRTP） | `u64` 位图 + 最高序号 | rtx-srtp | 64（`REPLAY_WINDOW_SIZE`） | 无 | `crates/rtx-srtp/src/lib.rs:270` | 未核实（有界但无 R 条目） |
| `Settings::items` | `[Setting; 32]` | rtx-h3 | 32（`MAX_SETTINGS_ITEMS`） | 无 | `settings.rs:113` | 未核实（有界但无 R 条目） |
| QPACK 行解码 scratch | `[u8; 1024]` | rtx-h3 | 1024（`MAX_FIELD_LINE_LEN`） | 无 | `connect.rs:52` | 未核实（有界但无 R 条目） |

### 5.3 映射结论

- **E0（embedded）**：没有“无上限的 `Vec`/`Map`/`Deque`”留在协议状态路径上；R1/R2 有固定数组与测试证据。唯一动态分配是 HMAC 摘要的临时 `Vec`（E0 ≤32 B，SRTP 20 B / DTLS 32 B；provider 通用面上界 48 B 未选用），它没有对应的 R 条目，按 §2.2 要求单列并记未核实。
- **L0（Linux）**：`rtx-quic::Endpoint` 的 5 个 `BTreeMap`/`VecDeque` 容器 + 3 个 `Vec<u8>` 载荷（`PendingTransmit::payload`、`PeerTransportParameters::encoded`、`CloseReason::Application::reason`）+ 5 个配置/握手 `Vec` 字段（`EndpointConfig::alpn`、`certificate_chain_der`、`client_roots_der`、`ServerIdentity::private_key_pkcs8_der`、`HandshakeInfo::alpn`）全部**无显式上限**，且没有映射到 R6–R12。Linux profile 的 RB4/RB5 因此未满足、记未核实；修复属后续单，不在本单范围。
- R3/R5 的 `rtx-webrtc` 在仓库中不存在，R4 的重排缓冲、R6–R10/R12 的 QUIC 状态也没有实现；这些 R 条目没有“容器 → 上限”可映射，只能记未核实。

### 5.4 M4-RB1–RB6 状态

| 条目 | 状态 | 本单证据/缺口 |
|---|---|---|
| M4-RB1 | 未核实 | 只有 R1/R2 有明确数值；R3–R12 无实现，数值/单位/拥有 crate/失败模式未能全部登记 |
| M4-RB2 | 未核实 | R1/R2 已返回类型化错误并有测试；其余 R 无超限实现，无法对全部条目断言三类结果 |
| M4-RB3 | 未核实 | R1/R2 测试未接入计数分配器，没有 `alloc_count`/`peak_live_bytes` delta 断言；其余 R 无实现 |
| M4-RB4 | 未核实 | E0 状态路径无无界容器；L0 的 `rtx-quic` 容器无显式上限（§5.1） |
| M4-RB5 | 未核实 | Linux 列只对 R1/R2 有值；R6–R12 的 Linux 上限未在本仓库登记 |
| M4-RB6 | 未核实 | 没有固定堆最大负载的 `measurements/m4/<日期>-<commit>/heap-limit.log`；§2.3 的 64 KiB 只是初始配置 |

---

## 6. 未核实项清单与阻塞原因

| 项 | 状态 | 阻塞原因 | 解除条件 |
|---|---|---|---|
| ELF/map 校核（两候选） | 未核实 | 无 `firmware/m4-smoke`、无链接 ELF/map | T-02 完成 `M4-0-2`/`M4-0-3` 后按 §3.1/§4.1 的行复核 |
| 主栈/中断栈/栈合计 | 未核实 | 无 `-fstack-usage`、map、板上高水位 | T-02 的最小固件 + `M4-M2` 栈填充扫描 |
| `peak_live_bytes`、堆耗尽行为 | 未核实 | 无固定堆最大负载、无 fallible 分配路径 | `M4-RB6` 固定堆实测 + 分配失败处理实现 |
| R3/R5 的所属 crate | 未核实 | `rtx-webrtc` 是 ARCH §5 规划名，仓库不存在；无实际流表/NACK 历史拥有者 | 由后续单在预算文档登记实际拥有 crate 并补测试 |
| R4、R6–R10、R12 | 未核实 | 无 RTP 重排缓冲、无嵌入式 QUIC 实现；`rtx-quic` 是 Tier D，`quinn-proto` 内部状态未受限 | M4-Q（T-04）+ M4-S 移植/裁剪后补显式上限 |
| R11 | 未核实 | `rtx-core` 只提供每状态机一个 `Option<Timestamp>`；全系统 timer 表未登记 | 目标运行时定下状态机数量与 timer 归属后登记 |
| Linux profile 的 RB4/RB5 | 未核实 | `rtx-quic` 的 `BTreeMap`/`VecDeque`/`Vec` 无显式上限 | 后续单给 `Endpoint`/事件/发送队列加上限与超限测试 |
| 候选 A/B 的外部 RAM | 未核实 | 板卡手册 Features 未列外部 RAM；未核实板级预留 | 若未来核实到板级预留，作为新预算行登记 |
| 候选 B 的 SRAM 其余 384 KB 细分 | 未核实 | 本单只核对 DS11532 Rev 7 p1/p2，未逐页核对 Table 2 | 后续需要逐块预算时补 Table 2 页码 |
| `M4-V4` | 未核实 | 静态部分可推导，但栈/堆/QUIC 状态与 ELF/map 未完成 | T-02 ELF/map + `M4-M` 最坏内存报告；在此之前不写判定结论 |

---

## 7. 协调者需裁决/后续单

1. **R3/R5 的实际拥有 crate**：`rtx-webrtc` 在仓库中不存在，`rtx-rtp` 没有流表、`rtx-rtcp` 没有 NACK 历史表。门禁允许登记“实际拥有流表的 crate”，但当前没有可登记对象；需要在后续 M4-S/移植单中指派拥有者并补 `resource_limits` 测试。
2. **Linux profile 的无界容器**：`rtx-quic::Endpoint` 的 `connections`/`by_quinn_handle`/`pending_incoming`/`pending_transmits`/`events` 与各 `Vec` 字段（事件/TP/关闭原因、ALPN/证书/私钥）没有上限，RB4/RB5 不能记已核实；本单不修，留给后续单。
3. **PR 引用现状**：`#43`（B0-02 门禁一行）、`#45`（closeout 刷新）、`#46`–`#52`（文档/互操作报告刷新）均已合并，`main` 头为 `52e4ac9`（PR #52 合并后）；`#44` 是本文档原始 PR（已合并）。派前记录中的“最大 #42，无 #43+”已过时，以本条为准。本单已 rebase 到 `52e4ac9`，无 M4-T-01 重复单。
4. **`M4-V4` 的判定边界**：本单只交付预算文档；`M4-V4` 的最终判定必须等 T-02 的 ELF/map 与后续最坏内存实测，不能把本文档合并当成 V4 的结论。

---

## 8. 复现命令与自查

### 8.1 基线复核

```bash
git rev-parse HEAD
git ls-remote https://github.com/medivhc/rtx-rs.git HEAD refs/heads/main
git cat-file -e 52e4ac9:docs/m4-resource-budget.md; echo "budget-on-main=$?"
git cat-file -e 52e4ac9:docs/m4-quic-decision.md; echo "quic-decision-on-main=$?"
git cat-file -e 52e4ac9:docs/m4-memory-report.md; echo "memory-report-on-main=$?"
git ls-tree 52e4ac9 -- firmware
git show 52e4ac9:.github/workflows/ci.yml | grep -n '^  [a-z-]*:'
git ls-tree -r --name-only 52e4ac9 | grep -E '\.(elf|map)$'
git ls-remote origin 'refs/pull/4[0-9]/head' 'refs/pull/5[0-9]/head'
git diff --stat ea870b6 52e4ac9 -- crates Cargo.toml Cargo.lock .github
```

### 8.2 R1/R2 超限测试

```bash
cargo test -p rtx-ice --test resource_limits
# 本单输出：2 passed; 0 failed
```

### 8.3 对象级静态量

```bash
CARGO_TARGET_DIR=/tmp/rtx-thumb-all \
CARGO_PROFILE_RELEASE_LTO=false \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
cargo build --workspace --no-default-features --release --target thumbv7em-none-eabihf

# 对每个 librtx_*.rlib（排除 testkit、quic）：
#   ar x <rlib>; size -A *.o | awk 汇总 .text*/.rodata*/.data*/.bss*
```

### 8.4 类型尺寸探针（不提交）

```rust
#![no_std]
pub static S_ICE_CHECKLIST: [u8; core::mem::size_of::<rtx_ice::Checklist>()] =
    [0; core::mem::size_of::<rtx_ice::Checklist>()];
// 其余类型同式：RecordMachine<1200, RustCryptoProvider>、SenderContext、
// ReceiverContext、SrtcpSenderContext、SrtcpReceiverContext、Settings
```

以同一 target/`--release` 编译后：

```bash
nm -S --size-sort <probe-object> | tail -12
# Checklist 0x29d0 = 10,704；RecordMachine<1200> 0x1370 = 4,976；
# Sender 0x40、Receiver 0x58、SrtcpSender 0x40、SrtcpReceiver 0x50、Settings 0x208
```

### 8.5 文档结构自查

```bash
# 表头列数一致性（每个表头行的 | 数量应固定）
grep -c '^|' docs/m4-resource-budget.md
# 结论仍为未选定、M4-V4 仍为未核实
grep -n '未选定' docs/m4-resource-budget.md
grep -n 'M4-V4.*未核实' docs/m4-resource-budget.md
# 只允许一个新增文件
git status --porcelain
git diff --stat 52e4ac9
```

---

## 9. 结论

- 本文档只交付**预算文档**；没有选型结论。目标选择仍为**未选定**：候选 A/B 的 T 项仍有 6 项未核实、V 项仍有 4 项未核实，候选 C 已被 `M4-V9` 否决。
- `M4-V4`（“数据手册资源上限低于静态 + 最小栈 + 最小堆下界”）仍为**未核实**：静态对象级部分已推导（A：Flash 145,894 B / RAM 16,496 B；B 同），但最小栈、最小堆、QUIC 状态与 ELF/map 均未完成。本文档合并不能作为 `M4-V4` 的判定依据。
- 下一步按选型文档 §5.4 的顺序：先 T-02（`firmware/m4-smoke` 链接 ELF + `embedded-build` CI 绿），再由 T-02 的 ELF/map 回填本文档的 ELF 行；T-04（M4-Q）判定是否需要 QUIC 后，R6–R10/R12 才有实现可登记。

---

## 10. 来源清单

| 编号 | 来源 | 修订版/版本 | 使用页码/位置 | 用于 |
|---|---|---|---|---|
| S1 | ST DS13313 `stm32h723zg.pdf` | Rev 5（May 2025） | p1、p14、p17–19（Table 1 跨 p17–19，首页 p17） | 候选 A Flash/SRAM/分块/外部 RAM 能力 |
| S2 | ST DS11532 `stm32f767zi.pdf` | Rev 7（February 2021） | p1、p2（Table 1） | 候选 B Flash/SRAM |
| S3 | ST UM2407 | Rev 6（April 2026） | p7（Features） | 候选 A 板卡功能页（无外部 RAM 行） |
| S4 | ST UM1974 | Rev 11 | p6（Features） | 候选 B 板卡功能页（无外部 RAM 行） |
| S5 | `docs/m4-target-selection.md` | `ea870b6` | §2.2、§3、§4、§5.1、§5.4、§6 | 候选、V 状态、缺口与顺序 |
| S6 | `docs/m3-m4-gates.md` | `ea870b6` | §2.0、§2.2、§2.2.1、§2.3、§2.6 | M4-R1–R12、RB1–RB6、V4、M4-M |
| S7 | `ARCHITECTURE.md` | `ea870b6` | §14 第 5 阶段、§16 | 显式 limits、ACK state、Linux/embedded 口径 |
| S8 | `crates/rtx-ice/src/checklist.rs` | `ea870b6` | 28、39、42、1109-1178 | R1/R2、事件/触发队列 |
| S9 | `crates/rtx-ice/tests/resource_limits.rs` | `ea870b6` | 26、76 | R1/R2 超限测试 |
| S10 | `crates/rtx-quic/src/config.rs` | `ea870b6` | 46-57 | L0 配置值（流参数、DATAGRAM 缓冲） |
| S11 | `crates/rtx-quic/src/endpoint.rs` | `ea870b6` | 75-78、89-93 | 无界容器 |
| S12 | `crates/rtx-quic/src/event.rs` | `ea870b6` | 38、56、122 | `Vec<u8>` 载荷 |
| S13 | `crates/rtx-crypto-rustcrypto/src/lib.rs` | `ea870b6` | 26-28、214-239 | 唯一 `alloc` 路径、HMAC 摘要 |
| S14 | `crates/rtx-core/src/lib.rs` | `ea870b6` | 177 | `next_wakeup` 单 deadline |
| S15 | `crates/rtx-dtls/src/machine.rs` | `ea870b6` | 47、115-120 | DTLS 事件队列上限 |
| S16 | `crates/rtx-srtp/src/lib.rs` | `ea870b6` | 270 | SRTP replay window |
| S17 | `crates/rtx-h3/src/settings.rs`、`qpack.rs`、`connect.rs` | `ea870b6` | 113、41、52 | H3 固定上限 |
| S18 | `.github/workflows/ci.yml` | `ea870b6` | 按 job 名核查全部 6 个 job：`test`、`suite`、`coverage`、`crypto-vectors`、`proptest`、`fuzz` | 无 `embedded-build` |
| S19 | 本单 `cargo`/`size`/`nm` 输出 | rustc 1.92.0、thumbv7em-none-eabihf | §2.2、§8.3、§8.4 | 对象级/类型级数值 |
