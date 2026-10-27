# RV-PR15 独立评审报告 — rtx-rs PR #15（R4-2-F1 文档措辞单）

| 项 | 值 |
|---|---|
| 评审对象 | rtx-rs PR #15 `R4-2-F1: converge rtx-ice doc wording to the R4-2 decision` |
| PR head SHA | `a92d1df015f2a4d7bccc36d246beace1dc0d51e3`（分支 `trae/p4-r4-2-f1-wording`） |
| 评审基线 main 头 | `c5453313ac16423886e8724686e5eb9e48db7268`（= PR #14 合并点） |
| merge-base | `c545331`（`git merge-base origin/pr15 origin/main`） |
| mergeable | `MERGEABLE` / `mergeStateStatus=CLEAN`（GitHub API），`refs/pull/15/merge` = `2f8151c` 存在 |
| 评审结论 | **批准合并** |

评审者以独立 git/gh/cargo 复核，不采信协调者转述的结论。所有命令在 `/workspace`（origin = `https://github.com/medivhc/rtx-rs`）执行，PR head 以 `git fetch origin refs/pull/15/head:refs/remotes/origin/pr15` 取得；评审结束后工作区已恢复原分支 `trae/agent-1aUm15` @ `c545331`，`git status` 干净，未改动任何远端分支、未合并、未新建 PR。

---

## 一、结论

**批准合并。阻塞项 0。**

F1 任务书的约束逐项满足：只改了 `crates/rtx-ice/src/lib.rs` 的 doc comment 与 `docs/ice-turn-decision.md` 的 NB-1/NB-2 两处文字；无代码/签名/常量/行为/Cargo.toml/CI 改动；无新增文件；作者自查可复现。剩余 2 条非阻塞意见均落在 F1 授权范围之外，不要求本 PR 作者处理。

---

## 二、验收逐项表

| # | 验收项 | 结论 | 证据 |
|---|---|---|---|
| 1 | diff 范围：2 文件、无新增文件、lib.rs 纯注释 | **通过** | 见 2.1 |
| 2 | lib.rs 三处收敛到位 + 全文件残留检索 | **通过** | 见 2.2 |
| 3 | NB-1 / NB-2 独立核实 | **通过** | 见 2.3 |
| 4 | 未改动项（认证缺口 / no_std / 有界表 / pair 优先级 / 提名·重传·consent / 决策文档其余章节） | **通过** | 见 2.4 |
| 5 | 作者自查独立复核（test / fmt / clippy） | **通过** | 见 2.5 |
| 6 | PR 描述三项 (a)(b)(c) 齐全 | **通过** | 见 2.6 |

### 2.1 diff 范围（验收项 1）

```
$ git diff --numstat origin/main...origin/pr15
22	10	crates/rtx-ice/src/lib.rs
2	2	docs/ice-turn-decision.md

$ git diff --shortstat origin/main...origin/pr15
 2 files changed, 24 insertions(+), 12 deletions(-)

$ git diff --name-status --no-renames origin/main...origin/pr15
M	crates/rtx-ice/src/lib.rs
M	docs/ice-turn-decision.md

$ git diff --diff-filter=AD --name-status origin/main...origin/pr15
(空 —— 无 A/D 文件)
```

- 文件清单**恰为 2 个**，与任务书一致；**无新增文件**、无删除文件。
- `git ls-tree -r --name-only origin/pr15 | grep -iE 'screenshot|\.png$|\.jpg$|\.gif$|\.snap$'` → **无输出**，无越界二进制/截图文件；`docs/` 在 head 下仍是 11 个既有文件。
- lib.rs 全部 diff 行均为 `//!` 注释行：

```
$ git diff origin/main...origin/pr15 -- crates/rtx-ice/src/lib.rs \
  | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' | sed -E 's/^[+-]//' | grep -vE '^//!'
(无输出 —— 32 条变更行全部以 //! 开头)
```

- 更强的等价性证明（剥掉注释行后逐字节比对）：

```
$ diff <(git show origin/main:crates/rtx-ice/src/lib.rs | grep -vE '^//!') \
       <(git show origin/pr15:crates/rtx-ice/src/lib.rs | grep -vE '^//!')
(无差异 —— lib.rs 代码部分完全一致)

$ # 对 crates/rtx-ice/ 下全部 .rs 做同样比对
(无输出 —— rtx-ice 整个 crate 无任何代码改动)
```

结论：无代码行、无签名、无常量、无行为改动。

> 显示口径说明：`gh pr view 15 --json additions,deletions,changedFiles` 返回 `24 / 12 / 2`，与 git 一致；TRAE 会话页 widget 显示的「1 文件 +21/-9」是展示口径差异，**以 git 为准**，本报告不以 widget 数字作任何结论。

### 2.2 lib.rs 三处收敛（验收项 2）

**基线（main @ c545331）三处定位已独立复核**：原两 bullet 在 `:41-45`，责任表行在 `:179`，`# Split with R4-2` 节在 `:189-194`——与任务书给出的行号完全一致。

| 处 | 基线位置 | head 位置 | 状态 |
|---|---|---|---|
| bullet 1（gathering） | `:41-43` | `:41-45` | 已改写 |
| bullet 2（TURN） | `:44-45` | `:46-49` | 已改写 |
| 责任表行 | `:179` | `:183` | 已改写 |
| `# Split with R4-2` 节 | `:189-194` | `:193-206`（改标题为 `# Gathering and TURN (R4-2 decision)`） | 整节重写 |

**要求收敛的 8 个落点，逐项在位**（head 行号）：

| 要求落点 | 位置 | 原文（节选） |
|---|---|---|
| 收集执行归调用方 | `lib.rs:43-45` | "the caller enumerates sockets and discovers its STUN servers (`docs/ice-turn-decision.md` §4)" |
| 收集执行归调用方 | `lib.rs:183` | "caller; R4-2 (…) defines the gathering contract, **the caller executes it**" |
| TURN 全生命周期执行归调用方 | `lib.rs:197-199` | "the **caller** performs … the whole TURN lifecycle (allocation, refresh, authentication, permissions and channels)" |
| 树内无 TURN 客户端 | `lib.rs:49` | "**This tree contains no TURN client.**" |
| 树内无收集/TURN 代码 | `lib.rs:198-199` | "**no gathering or TURN code lives in this tree**" |
| relay 契约 address = base = relayed | `lib.rs:200-201` | "`address` and `base` are both the relayed transport address" |
| start 前入表 | `lib.rs:201-202` | "the candidate is added **before** [`Checklist::start`]" |
| 之后 AlreadyStarted | `lib.rs:202-203` | "(afterwards the add APIs return [`IceError::AlreadyStarted`])" |
| 分配丢失 → 检查失败 / consent stale | `lib.rs:203-204` | "a lost allocation shows up as failed pair checks or stale consent" |
| 会话级失败归调用方 | `lib.rs:204-205` | "session-level failure handling belongs to the caller" |

**lib.rs 新增表述与决策文档逐条对得上**（`docs/ice-turn-decision.md`）——不是凭空新增承诺：

- `:103` 「树内不做 TURN 客户端。relay 候选由调用方/信令侧提供：分配、刷新、认证、权限、通道绑定都在调用方」 ↔ `lib.rs:46-49, 197-199`
- `:105-115` 「`address` 与 `base` 都填 relayed 传输地址，两者相等」 ↔ `lib.rs:200-201`
- `:149` 「**调用方必须在 `start` 前**只加入已经分配成功的 relay 候选」「当前 API 在 `start` 之后不接受新增候选」 ↔ `lib.rs:201-203`
- `:152-158` 失败语义表（检查 `Failed` / `is_consent_stale` / 「按会话失败处理」） ↔ `lib.rs:203-205`
- `:232` §4「host 枚举、srflx 的 STUN 查询、relay 分配全部归调用方；树内不新增任何收集代码」 ↔ `lib.rs:43-45`
- `:257` §4.3「start 后 `add_*` 返回 `AlreadyStarted`」 ↔ `lib.rs:202-203`

**禁语/残留检索（命令与结果全列）**：

```
$ grep -rn "R4-2 owns" . --exclude-dir=.git
   No matches found

$ grep -rn "R4-2 owns the TURN client" . --exclude-dir=.git
   No matches found

$ grep -rn "R4-2 adds gathering" . --exclude-dir=.git
./docs/ice-turn-decision.md:273:…本决策把该行后半句 "R4-2 adds gathering" 解析为…（对旧措辞的引述）
./docs/ice-turn-decision.md:296:| `R4-2-F1` | … 把 … 责任表 `lib.rs:179` 的 "R4-2 adds gathering" 收敛到本决策的落点 …
   → 仅存于决策文档对**旧措辞的历史引述**，lib.rs 内已清零

$ grep -rn "Both belong to R4-2" . --exclude-dir=.git
./crates/rtx-ice/src/candidate.rs:98:    /// refresh logic. Both belong to R4-2.
   → 命中在 candidate.rs，不在 lib.rs（见问题清单 NB-A）

$ grep -rn "Split with R4-2" . --exclude-dir=.git
./docs/ice-turn-decision.md:22 / :175 / :296   → 均为决策文档对旧章节标题的历史引述
```

lib.rs 内 `R4-2` 剩余提及**恰为 3 处**：

```
$ grep -n "R4-2" crates/rtx-ice/src/lib.rs
183://! | Obtain local/remote candidates (sockets, STUN, TURN, signalling) | caller; R4-2 (`docs/ice-turn-decision.md`) defines the gathering contract, the caller executes it |
193://! # Gathering and TURN (R4-2 decision)
195://! R4-1 (this crate) stops at "tables filled by the caller". R4-2
```

与 PR 描述「剩余 `R4-2` 提及共 3 处（`:183`、`:193`、`:195`）」一致。三处均为指向决策文档/节标题，无「R4-2 将实现收集/TURN」含义。

lib.rs 其他方向性措辞复扫（`belongs to` 1、`owns` 2、`will be` 0、`future` 0、`later` 0、`out of scope` 0）：

```
$ grep -n "belongs to\|owns \|will be\|future\|later " crates/rtx-ice/src/lib.rs
6://! This crate is the R4-1 slice of the `rtx-ice` layer. It owns candidate
7://! bookkeeping and connectivity-check state; it owns no socket, reads no
204://! checks or stale consent, and session-level failure handling belongs to the
```

`:6-7` 是本 crate 自身边界（自述 owns 什么/不 owns 什么），`:204` 已收敛为「归调用方」。无残留指向性措辞。

`docs/` 路径写法（`docs/ice-turn-decision.md`）与仓库既有惯例一致（`crates/rtx-crypto-rustcrypto/src/lib.rs:19`、`crates/rtx-stun/src/integrity.rs:25` 等均为仓库根相对写法），非本次新引入的写法问题。

### 2.3 NB-1 / NB-2（验收项 3）

**NB-1 —— `docs/ice-turn-decision.md:33` 行号区间**

```
$ grep -n "mock_mac" crates/rtx-stun/tests/common/mod.rs
109:pub fn mock_mac(key: &[u8], input: &[&[u8]], output: &mut [u8]) -> Result<(), WireError> {
124:    MessageIntegrity::new_raw(b"password", mock_mac)
```

读 `105-119` 行：`:109` 为 `pub fn mock_mac` 定义行，函数体 `:110-118`，`:119` 为闭合 `}`。因此 **`109-119` 正确**；原 `109-117` 止于 `Ok(())` 行、漏掉闭合括号，属实。改后 `:33` 原文：

```
- 测试用的 `mock_mac` 是 XOR 假 MAC（`crates/rtx-stun/tests/common/mod.rs:109-119`），不是 HMAC-SHA1；
```

语义未变（仍是 XOR 假 MAC，不是 HMAC-SHA1）。✅

**NB-2 —— `docs/ice-turn-decision.md:52` 补澄清句**

```
$ sed -n '492,512p' ARCHITECTURE.md
496	### M2 — secure WebRTC transport
497
498	- crypto providers for Linux;
499	- SRTP;
500	- ICE subset/full ICE decision;
501	- DTLS integration experiment.
502
503	Exit criterion: RTP media can be exchanged with a browser through a minimal interoperable path or a clearly defined remaining gap.
504
505	### M3 — QUIC/WebTransport Linux path
```

澄清句中的三项断言全部核实为真：M2 节 = `496-503`；「ICE 子集/全 ICE 取舍」在 `:500`；浏览器互通出口判据在 `:503`。同句中未被本 PR 改动的既有引用 `§15（364-368 行）与 M3 节（505-510 行）` 亦准确（M3 确在 `505-510`）。

澄清句**追加在 P6 WebTransport 路线句之后**（`:52`），未删改原路线判断。**B 结论未动**：`:212` 仍为「**选 B：STUN + 直连 + relay 透传。**」，`:216-226`（理由 1-5、执行摘要、边界）逐字未动。**P6 路线判断未动**：`§1.4` 仍断言「P6 浏览器互通（计划 R6-3）走 WebTransport 路径…而不是 WebRTC ICE 路线」，本 PR 只在其后追加一句关于 M2 节归属的澄清（明确写「本决策对 P6 走 WebTransport 的路线判断不变」）。✅

### 2.4 未改动项（验收项 4）

`git diff -U0` 对决策文档只有两个单行 hunk，其余章节一字未动：

```
$ git diff -U0 origin/main...origin/pr15 -- docs/ice-turn-decision.md | grep -E '^@@'
@@ -33 +33 @@
@@ -52 +52 @@
```

§1.1 / §1.2 之外的 §1.3 / §1.5 / §2.A / §2.B / §2.C / §3 / §4 / §5 / §6 与结论原文均未动。`crates/rtx-ice` 代码部分与基线逐字节一致（见 2.1）。逐项锚点：

| 未改动项 | 位置（head） | 复核结果 |
|---|---|---|
| 认证缺口原文 | `lib.rs:58` | `**This crate does not claim an authenticated ICE agent.**` 与基线逐字一致（仅行号因前置注释 +4 行位移） |
| no_std | `lib.rs:1` | `#![cfg_attr(not(feature = "std"), no_std)]` 未动；rtx-ice 内无 `extern crate alloc` / `use alloc` |
| 有界表常量 | `checklist.rs:28/39/42/49` | `MAX_ICE_CANDIDATES=16`、`MAX_ICE_PAIRS=64`、`MAX_EVENTS=8`、`MAX_STUN_MESSAGE_SIZE=64` 未动 |
| pair 优先级 | `pair.rs:100-109` | `(min<<32) + (max<<1) + tie_break` 公式未动 |
| 提名 / 重传 / consent | `checklist.rs:59/69/78/446`、`USE-CANDIDATE` 路径 | `INITIAL_RTO=500ms`、`MAX_RTO=8s`、`MAX_RETRANSMISSIONS=7`、`is_consent_stale`、常规提名语义均未动 |

### 2.5 作者自查独立复核（验收项 5）

工具链：cargo 1.92.0 / rustc 1.92.0 / rustfmt 1.8.0-stable（workspace `rust-version = 1.85`）。

```
$ cargo test -p rtx-ice
test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out   (lib)
test result: ok.  2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out   (tests/resource_limits.rs)
test result: ok.  0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out   (Doc-tests rtx_ice)

$ cargo fmt --all --check
fmt_exit=0        (输出 0 字节)

$ cargo clippy -p rtx-ice --all-targets
clippy_exit=0     (warning 计数 = 0)
```

三项与 PR 描述「验收自查」块中的数字**完全一致**，未发现回归或新增警告。

补充一项本 PR 特有、作者自查未覆盖的检查（本 PR 是纯 doc-comment 改动，新文本引入 3 个 intra-doc 链接 `[`Checklist::start`]`、`[`IceError::AlreadyStarted`]`、`[`CandidateType::Relay`]`）：

```
$ RUSTDOCFLAGS="-D warnings" cargo doc -p rtx-ice --no-deps
doc_exit=0        (无 broken intra-doc link 警告)
```

即注释改动**未引入 rustdoc 警告或失效链接**。

**CI 口径**：`gh api …/commits/a92d1df…/check-runs --jq .total_count` = **0**。这是既往 CI-C1 模式（fuzz job 的步骤把 `uses` 与 `run` 合并）导致的既有现象，**不是本 PR 的缺陷，本报告不要求本 PR 修 CI**，也不以「无 CI 结果」判定不通过。门禁由协调者在 xc 上另跑 CI-exact。

### 2.6 PR 描述三项（验收项 6）

| 要求 | 位置 | 复核 |
|---|---|---|
| (a) 收敛前后逐处对照 | 「(a) 收敛前后对照（旧措辞 → 新措辞）」1/2/3 小节 + 4 全文件扫描 | 齐全。三处均给出**引号包裹的旧措辞原文 → 新措辞原文**与行号锚点（`:41-49`、`:183`、`:193-206`）；第 4 小节给出 pattern/file/result 三行检索块，**并显式标注作用域为 `crates/rtx-ice/src/lib.rs`**，与实际检索范围相符（非虚报） |
| (b) NB-1/NB-2 改法与核实方法 | 「(b) RV-PR14 NB-1 / NB-2」 | 齐全。NB-1 给出改法（`109-117`→`109-119`）与核实方法（先 `grep -n "mock_mac"`，再读 100-126 行确认 109 起 119 止）；NB-2 给出追加的澄清句原文与核实方法（读 `ARCHITECTURE.md:496-503`，确认 500 行 ICE 决策、503 行浏览器互通出口判据），并声明边界（未改 B 结论、未改 P6 路线、未宣称树内有 TURN 客户端） |
| (c) 未改动项清单 | 「(c) 未改动项」 | 齐全。列出无代码行改动、no_std/无 alloc、四个有界常量、pair 优先级公式、提名/重传/consent 语义、认证缺口原文、未改 `Cargo.toml`/CI/其他 crate 文档、无新增文件 |

附带「验收自查」块（含真实命令输出）与「明确不做」块，内容与本报告 2.4/2.5/2.6 复核结论吻合。

---

## 三、问题清单

### 阻塞项（blocking）

**0 项。**

### 非阻塞意见（non-blocking）

以下 2 项**均落在 F1 授权范围之外**（任务书：只改 `lib.rs` 的 doc comment + 决策文档 NB-1/NB-2 两处），**不要求本 PR 作者在本 PR 内处理**，建议由协调者另立跟进项。

**NB-A — `crates/rtx-ice/src/candidate.rs:91` 与 `:98`：同类指向性措辞残留在公开 rustdoc 中**

- 现状：

```
 91:    /// address. Server discovery belongs to R4-2.
 98:    /// refresh logic. Both belong to R4-2.
```

  位于 `pub enum CandidateType` 的 `ServerReflexive` / `Relay` 变体文档注释中，会出现在 `cargo doc` 公开文档里，是本 PR 想在 lib.rs 中清掉的**同一类**「R4-2 拥有该能力」措辞。
- 判定：`candidate.rs` 不在 F1 的授权文件范围内，且 `git diff` 显示该文件**未被本 PR 触碰**（`git diff origin/main...origin/pr15 -- crates/rtx-ice/src/candidate.rs` 为空）。因此**不构成本 PR 的缺陷**，不应据此要求作者扩范围。
- 建议改法（另立单）：把两处改为与 R4-2 结论 B 一致的表述——例如 `:91` 改为「the caller discovers its STUN servers; this tree contains no STUN client」，`:98` 改为「this crate contains no TURN allocation or refresh logic; the caller owns the whole TURN lifecycle」。可并入 `R4-2-F3`（调用方 relay 供给指南单）或由协调者开一条 F1 范围补充单。
- 附带更正：协调者背景中「禁语三组在 head 全文无命中」这一表述，**仅在 lib.rs 范围内成立**；仓库全量检索下 `Both belong to R4-2` 仍在 `candidate.rs:98` 命中。本报告已独立复核并如实记录。

**NB-B — `docs/ice-turn-decision.md:22 / :238 / :273 / :296`：对 lib.rs 的行号与旧措辞引用在本 PR 合并后变为陈旧**

- 现状：`:22` 引 `crates/rtx-ice/src/lib.rs:41-45` 与 `lib.rs:189-194`「Split with R4-2」；`:238` 引 `lib.rs:189-194`；`:273` 引 `lib.rs:175-187`、`lib.rs:179`、`lib.rs:189-194`；`:296` 引 `lib.rs:189-194` 与 `lib.rs:179` 的「R4-2 adds gathering」。
- 本 PR 合并后的实际位置：责任表行 `:183`、章节 `:193-206`（标题已改为 `# Gathering and TURN (R4-2 decision)`）。故上述历史引述的行号与旧措辞不再指向现状。
- 判定：任务书明确要求「决策文档其余章节一字未动」，作者**正确地**未触碰这些章节，因此不构成本 PR 的缺陷，不要求本 PR 修补。
- 建议改法（另立单）：做一次决策文档的引用刷新（行号 + 章节标题 + 旧措辞引述标注为「R4-1 时期原文」），可并入 `R4-2-F3` 或后续文档单。

---

## 四、评审结论

- **评审对象**：rtx-rs PR #15，head SHA `a92d1df015f2a4d7bccc36d246beace1dc0d51e3`（分支 `trae/p4-r4-2-f1-wording`）。
- **评审基线**：main 头 `c5453313ac16423886e8724686e5eb9e48db7268`（= PR #14 合并点，`git merge-base` 复核一致）；PR head 相对基线 1 个 commit、净 diff 2 文件 +24/-12（git 与 GitHub API 一致）。
- **阻塞项**：0。
- **非阻塞意见**：2 条（`candidate.rs:91/98` 残留措辞、决策文档对 lib.rs 的陈旧行号引用），均超出 F1 授权范围，建议另立跟进项，**不在本 PR 内要求修改**。
- **是否建议合并**：**建议合并**。本 PR 为纯文档措辞收敛，无代码/行为改动，测试、fmt、clippy、rustdoc 四项均独立复核通过；合并后树内不存在指向性措辞误导（lib.rs 内），NB-1/NB-2 收尾到位。CI 门禁仍由协调者在 xc 上另跑 CI-exact（head check-runs 总数为 0 属既往 CI-C1 模式，非本 PR 缺陷）。
