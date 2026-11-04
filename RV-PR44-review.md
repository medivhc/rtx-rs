# RV-PR44 独立评审报告 — rtx-rs PR #44

- 评审对象：PR #44 `docs(m4): GAP-M4-T-01 资源预算文档（只建 PR，不合入）`
- 评审所对头 SHA：`2e637c86bf7f2e3b873450ae06bae9c78bffe19b`（commit `docs(m4): clarify single-task and whole-profile heap assumptions`）
- base：`ea870b607aeb2db26f2096f686c9061612c04190`（main @ PR 创建时），PR API `base.sha` 一致
- mergeable：`mergeable=true`、`mergeable_state=clean`、`rebaseable=true`、`merged=false`、`draft=false`
- 评审方式：独立 `git clone` + `git merge-base`/`diff` 实测，自建 thumbv7em 构建复算对象级尺寸，自建探针 crate 复算类型尺寸，GitHub API 实测 check-runs
- 评审环境：rustc 1.92.0 (ded5c06cf 2025-12-08)，thumbv7em-none-eabihf，`CARGO_PROFILE_RELEASE_LTO=false`、`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`

## 结论

**要求修改**（阻塞项 3 条，均为小改；不涉及选型结论、不涉及 CI 结论、不需要重做预算推导）

内容方向可信：范围干净、结论诚实（M4-V4 仍为未核实、目标仍为未选定、无越权表述成 ELF 实测），`.text` 总数 135,378 B 精确复现，9 项类型尺寸逐项精确复现，数据手册页码与数值抽查全部对得上。阻塞项集中在"已核实"标记的数值/口径自洽性与基线时效性。

## 一、验收逐项表

| # | 验收项 | 判定 | 证据 |
|---|---|---|---|
| 1 | 范围：diff 仅任务书允许的 1 文件；无 firmware/代码/CI/其他文档改动；无新增二进制；未顺带处理无关缺口 | **通过** | `git merge-base 2e637c8 ea870b6` = `ea870b6`（等于 base，非错误祖先）；`git diff --numstat ea870b6..2e637c8` = `407 0 docs/m4-resource-budget.md`；`git log --oneline ea870b6..2e637c8` = 3 个 commit（f551afb / e0a8d35 / 2e637c8），`--stat` 仅该 1 文件；头树 `git ls-tree -r` 无 `firmware/`、无 `.rs`/`.yml` 变更、无二进制（40142 B 纯文本 .md）；全文 grep 无 RV-PR40-N2 / RV-PR42-NB1 / 语料 / B3-01 / PR #2 相关内容，PR #43 仅作"是否重复单"事实记录提及 |
| 2 | 预算口径与算术：静态+最小栈+最小堆的保守下界自洽；对象级/类型级无重复计算或漏项；RustCrypto 闭包进静态预算合理且未把动态分配算成静态；单任务 vs 整 profile 两种口径分清；候选 A/B 下界与手册上限逐项对应，无"把下界写成实测值"或"把上限写成下界" | **不通过** | 阻塞 B1、B2。已复现正确部分：`.text` 合计 **135,378 B 精确复现**（13 个 E0 crate 逐项 + 外部闭包 61,630 逐项全等）；9 项类型尺寸用独立探针逐项复现全等（Checklist 0x29d0=10704、RecordMachine 0x1370=4976、Sender 0x40=64、Receiver 0x58=88、SrtcpSender 0x40=64、SrtcpReceiver 0x50=80、Settings 0x208=520、Candidate 0x34=52、CandidatePair 0x78=120）；Flash/RAM 余量算术全对（902682 B / 86.1%、556944 B / 97.1%、1951258 B / 93.0%、524176 B / 96.9%）；确认唯一 alloc 路径属实（E0 crate 中仅 rtx-crypto-rustcrypto 有 `extern crate alloc`，其余 Vec 命中全在 `#[cfg(test)] mod tests` 内）。缺陷见 B1（单次分配 ≥48 与 §5.1 ≤48 互斥且方向标反）、B2（"上表求和"得 16668≠16496）、N2（闭包与 rtx-crypto-rustcrypto 单态化代码重复计入）、N4（DTLS 握手固定状态未登记且 E0 无 profile 内密钥来源） |
| 3 | V4 与选型诚实性：结论仍为"未选定"；M4-V4 仍"未核实"；无段落提前断言 V4 成立或提前选定 A/B；C 被 M4-V9 否决表述准确；A/B 的 T/V 状态与 ea870b6 选型文档一致、无状态漂移 | **通过** | §9 与首页均写"未选定"+"未核实"；全文 grep `V4 通过`/`选中目标` = 0 命中；§3.2/§4.2 标题自带"（不是 V4 判定）"；A/B 状态"2 通过/6 未核实"、"6 通过/4 未核实"与 `docs/m4-target-selection.md` §3.0 矩阵（A/B 均 2/6/0）、§4.0 矩阵（均 6/4/0）、§5.1 表逐字一致；C 的"M4-V9 否决"与 §4.3/§5.2 一致（EVKB/EVKC 不规避亦与原文一致）；缺口登记位置正确（选型文档 §6 有 GAP-M4-T-01，门禁 §5 只有 GAP-M3-B0-02/B3-01 → 文档"不在 docs/m3-m4-gates.md §5"属实） |
| 4 | 来源可追溯：S1–S19 修订版/页码/位置与所引内容相符；重点抽查 S1/S2 的 Flash/SRAM 上限、S5 选型章节、S6 门禁条款、S8–S17 代码行号；S19 的 cargo/size/nm 输出不得被写成 ELF 实测 | **通过**（含 N 级瑕疵） | S1：实抓 DS13313 Rev 5（"May 2025"）PDF，p1 "total 564 Kbytes…128 DTCM + 432 system + 4 backup"、"up to 1 Mbyte flash" ✓；p18 Table 1 "Flash memory (Kbytes) 1024/512" 对 ZGT/ZET ✓、SRAM 块 128/16/16/16/192/64/128/4 与文档"128 AXI+16 SRAM1+16 SRAM2+16 SRAM4+192 shared+64 ITCM+128 DTCM+4 backup=564" 逐项吻合 ✓；p14 Description 的 192/64/128/128/48/4 分解与文档"两处分法对账"（432 system = 128 AXI+48 AHB+192 shared+64 ITCM；564=432+128 DTCM+4 backup）✓。S2：实抓 DS11532 Rev 7（"February 2021"）PDF，p1 "512+16+4KB RAM"、"up to 2 Mbytes" ✓，p2 "Table 1. Device summary" 确含 STM32F767ZI ✓。S3/S4：UM2407 Rev 6（April 2026）Features 在 p7 ✓，UM1974 Rev 11（August 2025）Features 在 p6 ✓，两者 Features 页均无板载外部 RAM ✓，且 UM1974 表 1 确列 NUCLEO-F767ZI→STM32F767ZIT6 ✓。S5/S6/S7：所引 §2.2/§3/§4/§5.1/§5.4/§6 与 §2.0/§2.2/§2.2.1/§2.3/§2.6 均存在；ARCH §16 确为 11 个 MAX_* ✓。S8–S17 代码行号逐条实测全对（checklist.rs:28/39/42/1109-1133/1157-1178、resource_limits.rs:26/76、config.rs:46-57/50/51/54-55、endpoint.rs:75-78/89-93、event.rs:38/56/122、crypto-rustcrypto lib.rs:26-28/214-239、core lib.rs:177、dtls machine.rs:47/115-120、srtp lib.rs:270、h3 settings.rs:113 / qpack.rs:41 / connect.rs:52）。**关键项通过**：S19 明确标注"对象级/类型级数值"，§2.2 明写"不能替代 T-02 的 ELF/map"，§3.1/§4.1 的 ELF/map 行=未核实，§9 明写 M4-V4 未核实——**未发现把 cargo/size/nm 输出冒充 ELF/map 实测的越权表述**。瑕疵见 N1、N3、N5、N6 |
| 5 | PR 描述完整性：含 (a) 改了什么、(b) 数字来源与非作者重跑/非实测声明、(c) 复核基线 ea870b6、(d) 明确不做（不选型/不建 firmware/不改 CI）；成员状态与依据（头、合并提交、基线、报告路径）与 git/API 实测一致；未把未跑的门禁写成已跑，未把协调者核验写成作者自查 | **不通过**（仅因基线复核已过时；四要素与归属表述本身合规） | 四要素齐备：背景"只新增预算文档，不选型、不合入"、(a) 改了什么、(b) 每候选手册页码 + "对象级 .text…来自本单 cargo build…size -A"、".bss 16,496 来自类型尺寸探针（nm -S）"、(c) "基线：main @ ea870b6（Push 前 git ls-remote 与本地 HEAD 一致；无基线漂移）"、(d) 未改动项逐项（firmware/、ci.yml、选型文档、门禁文档、crates/*、Cargo.toml/lock、state.json 等）。归属正确：作者自查仅列本地命令（cargo test 2 passed、python3 表结构检查、grep -c、git status），**未声称任何门禁已跑**；§1.2 "额外任务列表"明确标为"协调者派前复核"，未冒称作者自查。实测复核：cargo test -p rtx-ice --test resource_limits → **2 passed**（与描述一致）；表结构检查 → table_blocks=12、column_mismatches=0（与描述一致）；grep -c '^|' → **183**（与描述一致）；base.sha=ea870b6、head.sha=2e637c8、mergeable=true（与描述一致）。**不一致点**：PR #43 于 2026-11-04T07:30:35Z 合并（main=33268ff），晚于本 PR 头提交 06:48:58Z——描述中"无基线漂移"在 push 时点为真，现已不成立；文档 §1.2:30 同样过时。见 B3 |
| 6 | CI 现状记录：头 check-runs 现状如实记录；内容结论与 CI 结论分开 | **通过** | 头 2e637c8：check-runs total_count=**7**，全部 conclusion=success（run 41788043987，2026-11-04T06:49:10Z–06:52:11Z 完成）：suite (stable)、coverage gate、suite (msrv)、fuzz smoke (nightly)、crypto vectors (published)、property tests (deep sweep)、build / lint (stable)；**无失败项、无 skipped 项**（全部 status=completed）。对照：main@ea870b6 → 7/7 success；当前 main@33268ff → 7/7 success。`refs/pull/44/merge`（a03ab17）check-runs=0，属 GitHub 合成 merge 提交未挂作业，非失败；PR `mergeable_state=clean`，本地实测把 2e637c8 合到 33268ff 无冲突。内容结论与 CI 结论已分列（内容见第 2、3 项，CI 见本项），未以 CI 绿替代内容判定，也未以内容问题混同为 CI 失败 |

## 二、file:line 问题清单

### 阻塞（须修改后方可合并）

**B1 — `docs/m4-resource-budget.md:120`（并 `:162`、`:211` 对 `:250`）单次分配下界方向标反且与 §5.1 互斥**
- `:120`："摘要长度最大为 SHA-384 的 48 B，因此已知单次分配下界为 **≥48 B**"；`:162`/`:211` 把 "≥48" 登记为 **已核实**；而 `:250` 对同一 `written` Vec 写 "是（**≤48 B**，摘要长度）"。
- 实测：`hmac_parts` 的 `written` 长度恰为 `digest_len(algorithm)`（crypto-rustcrypto lib.rs:52-58 → Sha1=20 / Sha256=32 / SHA-384=48）。E0 实际路径为 SRTP 的 HMAC-SHA1（rtx-srtp/src/cipher.rs:141-155）与 DTLS 密钥日程的 SHA-256（rtx-dtls/src/keyschedule.rs:128/145/160）；SHA-384 在 E0 crate 中无调用点（仅 rtx-crypto trait 定义与测试）。因此"单次分配 ≥48 B"按字面为假，实际单次分配为 20/32 B，48 B 只是算法上界。
- 修法：区分"单次分配上界（48 B，SHA-384）"与"堆预留下界（按最坏单次分配 48 B 预留）"，并使 §3.1/§4.1 与 §5.1 用同一口径，消除 ≥/≤ 互斥。

**B2 — `docs/m4-resource-budget.md:112` "E0 固定状态合计 16,496 | 上表求和" 与表内可见列之和不符**
- 表内 9 行相加 = **16,668**（10704+52+120+4976+64+88+64+80+520）；文档写 16,496 并标注"上表求和"。16,496 实为**排除** "ICE 候选 52"、"ICE pair 120" 两行后的和（这两行是 10,704 checklist 内含候选表 16×52×2 与 pair 表 64×120 的组件，`:103` 已注明"含两侧 16 候选表、64 pair 表"）。
- 风险：列名"对象（每个 profile 一份）"与两行"单个元素"口径混列，且表头声称"上表求和"，读者照做即得 16668 → 172 B 重复计入 ICE 候选/pair。
- 修法：改推导说明为"= 上表去除 ICE 候选/Ice pair 两行（已含于 checklist 10,704）后求和 = 16,496"，或把两行移出合计表另列。

**B3 — 基线复核结论已过时（`docs/m4-resource-budget.md:30`、`:37`；PR 描述"背景"段）**
- 实测：PR #43 于 2026-11-04T07:30:35Z 合并，main 头已由 ea870b6 变为 **33268ff**（`git ls-remote origin refs/heads/main`）；本 PR 头提交为 06:48:58Z，故 `:30`"主线头 ea870b6…无漂移"与 PR 描述"无基线漂移"在 push 时点为真、现已不成立；`:37`"PR refs 最大为 #43"亦已过期（现有 #44、#45）。
- 文档自身 §1.2 尾注与 §7.3:306 已规定该情形的处置："若 #43 先合并，作者须先 rebase 再复核 §1.2 的缺失项"——该前置条件现已触发而未执行。
- 影响：无内容冲突（本地实测 2e637c8 合入 33268ff 无冲突，GitHub `mergeable_state=clean`）。修法：rebase 到 33268ff，重核 §1.2 并更新 PR 描述基线陈述。

### 非阻塞（建议修，不挡合并）

**N1 — `docs/m4-resource-budget.md:56` "同族 `stm32f765ig.pdf` 的现行版本为 Rev 9" 与实测不符**
- 实测 2026-11-04 抓取 `https://www.st.com/resource/en/datasheet/stm32f765ig.pdf`：返回的是 **DS11532 Rev 7（February 2021，252 页）**，与 `stm32f767zi.pdf` 同一文件同一修订版。因此"现行版本为 Rev 9、本单未采用"不成立，且"避免混用两版"的理由已 moot（本单所用即现行版）。

**N2 — `docs/m4-resource-budget.md:94`/`:112` 对象级合计的重复计入机制未披露；`.rodata` 随构建路径漂移**
- 复核发现：rtx-crypto-rustcrypto 的 rlib 内已含 `aes_gcm::AesGcm::compute_tag`、`hmac::get_der_key`、`sha2::compress`、`ghash::GHashBackend::proc_block`、`generic_array`、`crypto_common`、`aes::soft::Aes128` 等**单态化副本**，同时外部闭包 crate 自身 rlib 也含同源代码 → 135,378 B 中同源函数被计两次。`:77` 已声明"链接期裁剪可能让它变小"，但未披露该重复机制；建议补一句，避免被读成"最小代码量下界"。
- `.rodata` 合计 10,516 B 非构建路径无关量：实测同 commit/同参数下，路径 `/tmp/rev44/base` 得 10,536、路径 `/tmp/rv_b` 得 10,484（panic location 字符串内嵌绝对路径）。`.text` 合计 135,378 B 则**与路径无关且精确复现**。建议把 `.rodata` 的"已核实"加上路径敏感性说明（或只对 `.text` 声明精确可复现）。

**N3 — `docs/m4-resource-budget.md:248`（及 `:249`、`:401`）容器清单字段名与行号错配、且有漏项**
- `Event::encoded` 字段不存在：`Event` 只有 `connection`/`kind`（event.rs:8-13）；`PeerTransportParameters::encoded` 在 event.rs:56；所引 event.rs:122 是 `CloseReason::Application::reason: Vec<u8>`。
- 漏登记的动态容器：`HandshakeInfo::alpn: Option<Vec<u8>>`（event.rs:38，S12 已列行号但 §5.1 表未列）、`EndpointConfig::private_key_pkcs8_der: Vec<u8>`（config.rs:63、:115）、`ServerIdentity`（config.rs:62-64）；`:249` 引 "config.rs:62-75" 未覆盖 114-115。

**N4 — `docs/m4-resource-budget.md:68`/`:101-112` E0 profile 未说明 DTLS 握手固定状态，且 E0 内无 profile 内 SRTP 密钥来源**
- `rtx_dtls::HandshakeMachine` 每会话固定状态含 `transcript: [u8; 1024]`（handshake.rs:52/238）、`Flight` = `[FlightItem; 4]`，每项 `payload: [u8; 512]`（handshake.rs:50/151/166）、外加 3 个 `RecordCipher`（cipher.rs:50-54），合计约 3.4 KB/会话——大于表中多行，却未进 §2.2 固定状态表，也未进 §6 未核实清单。
- 且 `RustCryptoProvider` **未实现** `rtx_crypto::CryptoProvider`（仓库内 CryptoProvider 的实现仅见于测试 mock：rtx-crypto/tests/common/mod.rs:530、rtx-crypto/src/lib.rs:1314、rtx-dtls/tests/common/handshake.rs:368），实测 `HandshakeMachine<RustCryptoProvider>` 编译失败（E0277）→ E0 profile 内无握手、无 SRTP 密钥导出路径。建议在 §2.1/§6 显式登记（属 T-05 provider adapter 缺口）。

**N5 — `docs/m4-resource-budget.md:55` DS13313 "第 14 页（Description）" 页锚定置信度较低**
- p1（Features）、p18（Table 1，ZGT/ZET 列 1024/512）已独立确证；p14 的 "564 Kbytes…192/64/128/128/48/4" 段落在 PDF 文本流中紧随 p14 页标记之后出现，但按"页脚标记"读法则落在 p15。建议复核并改为可唯一定位的锚点（如章节号 + 段落首句）。

**N6 — `docs/m4-resource-budget.md:406` S18 行号范围 "20-210" 偏窄**
- `.github/workflows/ci.yml` 实为 247 行，作业键在 20/74/112/152/184/207，`fuzz` 作业体延伸过 210 行。建议写 "16-247"；实质结论"无 embedded-* 作业"已实测成立。

**N7 — PR 描述未写头 SHA；提及仓库中不存在的文件**
- 描述未给头 SHA（实测 2e637c86bf7f2e3b873450ae06bae9c78bffe19b），建议补，便于评审/门禁对位。
- 描述"未改动项"列出 `state.json` / `PIPELINE-LOG.md` / `ERROR-LOG.md`，三者均不在仓库（`git ls-files` 无命中），陈述无害但易误导。

**N8 — `docs/m4-resource-budget.md:229` 候选 B SRAM 余量百分比舍入**
- 文档写 97.0%，精确值 524176/540672 = 96.948% → 96.9%。仅舍入，不影响结论。

## 三、评审依据快照（实测值）

- 头 SHA `2e637c86bf7f2e3b873450ae06bae9c78bffe19b`；base `ea870b607aeb2db26f2096f686c9061612c04190`；merge-base(head, base) = base（自包含）
- 净 diff：1 文件 +407/-0；3 commits；PR API：`additions=407, deletions=0, changed_files=1, commits=3, mergeable=true, mergeable_state=clean`
- 当前 main = `33268ff2c5721e31e3a115fe8469d7869cd60dbc`（PR #43 于 07:30:35Z 合并）；merge-base(head, 33268ff) = ea870b6；本地试合 2e637c8 → 33268ff 无冲突
- 对象级复算（自建，rustc 1.92.0 / thumbv7em-none-eabihf / LTO=false / cgu=16 / --no-default-features）：`.text` 合计 **135,378**（与文档全等，逐 crate 全等）；`.rodata` 合计 10,536（长路径）/ 10,484（短路径），文档 10,516 落在路径敏感性区间内；`.data`=0、`.bss`=0（全部 E0 crate rlib）
- 类型尺寸复算（自建仓库外探针 crate，`nm -S --size-sort`）：Checklist 0x29d0=10,704、RecordMachine<1200> 0x1370=4,976、Sender 0x40=64、Receiver 0x58=88、SrtcpSender 0x40=64、SrtcpReceiver 0x50=80、Settings 0x208=520、Candidate 0x34=52、CandidatePair 0x78=120（文档 §8.4 声称值逐项全等）
- 头 check-runs：7/7 success（run 41788043987），无失败、无 skipped
- 作者自查复现：`cargo test -p rtx-ice --test resource_limits` → 2 passed；表结构 → 12 blocks / 0 mismatches；`grep -c '^|'` → 183

## 四、边界声明

- 本报告只做评审，**未合并、未改动分支、未新建 PR**。
- 内容结论与 CI 结论分列：CI 7/7 绿不构成内容通过的依据；内容侧 B1/B2/B3 亦不构成 CI 失败的依据。
- 门禁阶段仍需按协调者流程以 xc CI-exact 重跑定性；本报告引用的是 2026-11-04 观察到的 head check-runs 现状。
