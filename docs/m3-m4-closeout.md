# M3 / M4 收尾一致性盘点（P9-1）

| 项 | 内容 |
|---|---|
| 文档编号 | P9-1 |
| 文档类型 | 收尾盘点（docs-only）；**不是**里程碑验收 PR |
| 基线 | `main` @ `4ba22ea`（P8 合并点，2026-10-30 复核） |
| 范围 | 版本 / CHANGELOG / 示例盘点 / 文档一致性；只建 PR，不合并 |
| 结论 | **FAIL**（依据见 §6） |
| 门禁文档 | 未改动 `docs/m3-m4-gates.md`；未勾选任何复选框、未填 §6 表格 |
| 自测清单 | 见 PR 描述 (a)–(e) |

> 本文件是收尾盘点，不是完成宣告。文中的“已合并”“已登记”只指 git 与文档事实，不指门禁条目通过。

---

## 1. 已合并阶段清单

核对方法：在 `main` @ `4ba22ea` 上执行 `git log --first-parent`、`git cat-file -p <merge>`，并用 `gh pr list --state all` 对照 PR 号与标题；短哈希为 7 位。阶段按 R/P 编号归组，**不按合并时间排序**（例如 R1-1 / PR #5 早于 R0-1 / PR #1 与 R0-2 / PR #4 合入）。

| 阶段 | PR | merge commit | 交付内容（一句话） |
|---|---|---|---|
| P0（R0 基线） | #1 | `43329cf` | 新增 MIT OR Apache-2.0 双许可 `LICENSE`，修正 `repository` 地址并在各 crate 继承（R0-1） |
| P0（R0 基线） | #4 | `4db963f` | 新增 `docs/m3-m4-gates.md` 可判定门禁清单（R0-2） |
| P1（R1 加密加固） | #5 | `8acc1a7` | 新增 `docs/ed25519-x25519-provider-design.md`：provider 设计、实现阶段 P0–P5 与常数时间审计清单（R1-1） |
| P1（R1 加密加固） | #3 | `b0a4ebf` | 把 `rtx-crypto` property 测试参数化到真实 RustCrypto 后端（branch `test/proptest-real-backend`；标题未标 R 编号，按内容归入 P1） |
| P2（R2 DTLS） | #6 | `dc0b27e` | 新增 `crates/rtx-dtls`：DTLS 1.2 record 层 sans-IO 状态机（R2-1） |
| P2（R2 DTLS） | #7 | `daa6b56` | DTLS 1.2 握手状态机与 DTLS-SRTP 密钥导出（R2-2） |
| P2（R2 DTLS） | #8 | `69597a8` | DTLS 真实 UDP 握手泵测试与互通缺口文档（R2-3，测试 + 文档） |
| P3（R3 SRTP） | #9 | `7c2b612` | 新增 `crates/rtx-srtp`：AES128_CM_HMAC_SHA1_80 保护与重放窗口（R3-1） |
| P3（R3 SRTP） | #10 | `dbaeba5` | SRTP 加密区改回 RFC 3711 §3.1 布局（R3-1b） |
| P3（R3 SRTP） | #11 | `88823ab` | DTLS-SRTP KDF 接线：RFC 3711 §4.3 + RFC 5764 §4.2 方向映射（R3-2） |
| P3（R3 SRTP） | #12 | `a095f06` | SRTCP 会话密钥派生与包保护（R3-3） |
| P4（R4 ICE / relay） | #13 | `f6d0cc5` | 新增 `crates/rtx-ice`：有界候选表、pair 表与 sans-IO 检查表状态机（R4-1） |
| P4（R4 ICE / relay） | #14 | `c545331` | 新增 `docs/ice-turn-decision.md`：TURN 复用决策（选项 B：relay 透传，R4-2） |
| P4（R4 ICE / relay） | #15 | `6e4bcd9` | `rtx-ice` 文档措辞收敛到 R4-2 决策（R4-2-F1） |
| P4（R4 ICE / relay） | #16 | `4bce6f1` | relay 透传一致性测试（R4-2-F2，test-only） |
| P4（R4 ICE / relay） | #17 | `7647f4f` | 新增 `docs/ice-relay-caller-guide.md`（R4-2-F3，docs-only） |
| P4（R4 ICE / relay） | #18 | `581f326` | 调用方 relay 指南措辞修正（RV-PR17-NB，docs-only） |
| P5（SCTP 决策） | #19 | `4641cd5` | 新增 `docs/sctp-datachannel-decision.md`：M3 跳过 SCTP 实现的 interim 决策 |
| P6（R6 QUIC / WebTransport） | #20 | `3983ed6` | 新增 `crates/rtx-quic`：`quinn-proto` 窄外观（M3-Q） |
| P6（R6 QUIC / WebTransport） | #21 | `d9663e1` | 最小 H3/WebTransport 编解码层（M3-H1/H2/H6/H7/H8） |
| P6（R6 QUIC / WebTransport） | #22 | `9940499` | Chrome SETTINGS / CONNECT 真实帧抓包 harness（M3-H3/H4 证据，不含互通结论） |
| P6（R6 QUIC / WebTransport） | #23 | `c6c4897` | 新增 `crates/rtx-h3`：SETTINGS / QPACK / CONNECT（M3-H3–H5） |
| P6（R6 QUIC / WebTransport） | #24 | `edca8ea` | `interop/m3/rtx-server/`：rtx WebTransport 服务端 harness + 回环证据（M3-B 前置片） |
| P6（R6 QUIC / WebTransport） | #25 | `ddc43e4` | Chrome WebTransport 两阶段实测（B0 阻塞，登记 `GAP-M3-B0-02`） |
| P7（M3-P harness） | #26 | `37a2a8a` | `crates/rtx-testkit` + `benchmarks/m3/`（独立 crate + `run.sh`）+ `docs/m3-benchmarks.md` 报告骨架；不含任何基线数字 |
| P8（M4-0-1） | #27 | `4ba22ea` | 新增 `docs/m4-target-selection.md`：结论“未选定”，登记 `GAP-M4-T-01`…`GAP-M4-T-08` |

计数：P0–P8 共 **26 个已合并 PR**（P0 2 + P1 2 + P2 3 + P3 4 + P4 6 + P5 1 + P6 6 + P7 1 + P8 1）。P6 另有 1 个直接提交到 `main` 的 commit `6c69657`（`docs(gates): register GAP-M3-B0-02 (blocking) and GAP-M3-B3-01 (conditional) from R6-4 PR #25`），无 PR、无 merge commit，故不计入 PR 计数。

### 仍 open 的 PR（不属已合并清单）

| PR | 分支 | 头 | 状态 | 说明 |
|---|---|---|---|---|
| #2 | `test/fuzz-regression-corpus` | `74640b8` | OPEN | fuzz 回归语料库单（任务书编号 R1-3）；CI `build / lint (stable)` 失败，其余 5 个 job skipped；不在 P0–P8 已合并清单内，本单不处理、不修复 |

---

## 2. 版本与发布状态

- **workspace 版本**：`Cargo.toml:22` 为 `version = "0.1.0"`；本单未改动 `Cargo.toml`（diff 不含该文件）。edition 2024、license `MIT OR Apache-2.0`、`repository = "https://github.com/medivhc/rtx-rs"`（`Cargo.toml:23–26`）同样未动。
- **CHANGELOG 历史状态**：`4ba22ea` 上没有任何层级的 `CHANGELOG` 文件（`find . -iname 'changelog*'` 无输出）。本单新建根 `CHANGELOG.md`，只设 `Unreleased` 一节，见该文件。
- **发布状态**：本单未执行任何发布动作；仓库无发布工作流（`.github/workflows/ci.yml` 无 publish 作业）、无 git tag（`git tag -l` 为空）、版本号未动。未发布到 crates.io；crates.io registry 侧的独立核对因沙箱访问返回 403 未做，本文件不把“未检索”写成已核实结论，只记录“无发布动作、无发布流水线、无 tag”。
- **发布范围**：只发 wire/crypto 层还是整 workspace，待用户收尾时一句话定；本单不决策、不预设。与本单绑定的流水线默认是：不发布到 crates.io、不改 workspace 版本号。

---

## 3. 示例状态

`4ba22ea` 实测：

- 无 workspace 级 `examples/` 目录：`find . -maxdepth 3 -type d -name examples` 无输出。
- 无任何 `crates/*/examples/` 目录。
- `interop/m3/` 下只有测试 / 互通 harness：
  - `interop/m3/chrome/`：Chrome 侧页面、启动脚本（`run.sh`）与抓包证据目录 `2026-10-29-chrome-156.0.8078.4/`（R6-2c）。
  - `interop/m3/chrome-rtx/`：服务端 + Chrome 互通 harness 与两阶段证据 `2026-10-29-chrome-155.0.8059.39/`、`2026-10-29-chrome-155.0.8059.39-baseline/`、`blocker-analysis.md`（R6-4）。
  - `interop/m3/rtx-server/`：rtx WebTransport 服务端 harness（`src/`、`tests/`、`run-loopback.sh`、`evidence/`，R6-3）。

**结论**：以上均为测试 / 互通 harness，**不是示例**；仓库没有最小浏览器媒体交换路径示例。本单不新建示例代码，该缺口按门禁 §4 字段登记如下。

| 字段 | 内容 |
|---|---|
| ID | `GAP-M3-E-01` |
| 类型 | 非阻塞（示例缺口；不在门禁条目表内，不改变 §6 结论） |
| 场景与复现 | 在 `4ba22ea` 上执行 `find . -maxdepth 3 -type d -name examples` → 无输出；`ls interop/m3/` → `chrome`、`chrome-rtx`、`rtx-server`（均为 harness） |
| 期望依据 | 任务书 P9-1 §3 的示例盘点要求；ARCH §20 M3 的 browser DATAGRAM and stream interoperability 工作项所对应的可运行示例 |
| 实际证据 | 无 `examples/` 目录；`interop/m3/chrome/`、`interop/m3/chrome-rtx/`、`interop/m3/rtx-server/` 是测试 harness 与证据，不可替代“最小浏览器媒体交换示例” |
| 影响 | 交付缺少最小可运行示例；不阻塞任何 M3 门禁条目，但构成交付完整性缺口 |
| 处置 | `defer`；重测日期 2026-11-30（暂定，协调者确认）；另起示例代码单，不在本单范围 |
| 责任与复核 | owner：后续示例代码单作者（待协调者指派）；复核：架构评审；issue：本 PR 讨论 |
| 状态 | `OPEN` |

---

## 4. 文档一致性发现清单

| # | 文件与位置 | 实际证据（`4ba22ea` 实测） | 本单处置 / 归属 |
|---|---|---|---|
| 1 | `README.md:5–10`（修正前） | 第 5 行称 “only four foundation crates”，只列 `rtx-core` / `rtx-buffer` / `rtx-wire` / `rtx-crypto`；`Cargo.toml:3–19` 列出 15 个成员 | **已修**：本单只重写该段为 15 成员清单；README 其余段落、标题与链接未动 |
| 2 | `docs/m3-m4-gates.md:8` | “引用基线”仍为 `caab165a…`（2026-10-26 核对），当前 `main` 为 `4ba22ea` | 未修：门禁文档本单不可改；交协调者裁决 |
| 3 | `docs/m3-m4-gates.md:11` | “当前状态 \| M3/M4 均未开工；下表复选框全部为未满足”，与 R6 / P7 / P8 已合并事实不符 | 未修：同上 |
| 4 | `docs/m3-m4-gates.md:452` | §5 前言称“本文件创建时 M3/M4 尚未开工，因此没有已登记缺口”，同节 `:456–457` 已登记 `GAP-M3-B0-02` 与 `GAP-M3-B3-01` 两行 | 未修：同上 |
| 5 | `docs/m3-m4-gates.md:463–509` | §6.1 / §6.2 / §6.3 表格全为空白：分组结论无数字与签署、附件表无链接、签署表无内容 | 未填：`docs/m3-m4-gates.md:38`（§0.2 规则 5）规定复选框只能由里程碑验收 PR 勾选；本单不是验收 PR |
| 6 | `docs/m3-m4-gates.md:493–496`；`docs/`、`measurements/` | §6.2 必填附件缺失：`docs/m4-quic-decision.md`、`docs/m4-resource-budget.md`、`docs/m4-memory-report.md`、`measurements/m4/`、`measurements/m4/ci/protection.json` 均不存在（`ls docs` 仅 `m4-target-selection.md` 一个 `m4-*` 文件；`measurements/` 仅 `m3/deps/*.txt`） | 未补齐：归属 M4-Q / M4-R / M4-M / M4-C 后续单或协调者 |
| 7 | `benchmarks/m3/results/README.md:1–6`；`docs/m3-benchmarks.md:3–9` | `benchmarks/m3/results/` 仅 `README.md`，无任何场景 JSON；`docs/m3-benchmarks.md` 自述 “contains no measured numbers”，全表为“待 xc 基线” | 未修：首份 xc 基线为协调者后续工作；本单未跑正式模式、未产基线数字 |
| 8 | `docs/progress-report.md:1–5, 26` | 标题 “M0 → M2”、HEAD `da34ad6`、“crates：8 个”，与 `main` `4ba22ea`、15 个成员不符 | 未修：归属后续文档单；本单不重写已有文档正文 |

---

## 5. 阻塞缺口总表

以下逐项复述任务书 §0 的阻塞清单，不删项、不改口径。未登记 GAP ID 的门禁前置缺失照实标注，不新增 ID。

| 缺口 | 类型 | 状态 | 证据 | 影响 |
|---|---|---|---|---|
| `GAP-M3-B0-02` | 阻塞 | `OPEN` | `docs/m3-m4-gates.md:456`；`interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md` 与同目录 `-baseline/report.md` | Chrome 建立 WebTransport 会话失败：服务端 SETTINGS 不含 legacy `ENABLE_WEBTRANSPORT`（`0x2b603742`），Chrome 以 `net::ERR_METHOD_NOT_SUPPORTED` 拒绝；B1/B2 因此 `not_run` |
| `GAP-M4-T-01` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:284`（§6） | 无 `docs/m4-resource-budget.md`、无 `firmware/`、无 ELF/map；V4 无法判定 |
| `GAP-M4-T-02` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:285`（§6） | 无 `firmware/m4-smoke`、无 `embedded-build` CI、未做链接实验；V5 无法判定 |
| `GAP-M4-T-03` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:286`（§6） | 无 `rtx-smoltcp`、无 MAC/PHY 驱动与缓冲区所有权文档；T4/V6 未核实 |
| `GAP-M4-T-04` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:287`（§6） | 无 `docs/m4-quic-decision.md`；M4-Q 的 QC1–QC10 矩阵与结论未做；V3 无法判定 |
| `GAP-M4-T-05` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:288`（§6） | 无目标 crypto provider 与 AES-GCM/SHA 吞吐、栈占用记录；T5 未核实 |
| `GAP-M4-T-06` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:289`（§6） | 无定时器驱动与溢出扩展测试、分频值未定；T6 未核实 |
| `GAP-M4-T-07` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:290`（§6） | 无板卡资产编号 / runner 标签，CI 仅 `ubuntu-latest`；T7 的 CI 板卡子项未核实 |
| `GAP-M4-T-08` | 阻塞 | `OPEN` | `docs/m4-target-selection.md:291`（§6） | 两款 NUCLEO 板卡的 Longevity Commitment 均为 `-`、项目周期未定义、SDK 集成评审未做；T8 未核实 |
| M3-P 基线缺失 | 阻塞（门禁前置缺失，未登记 GAP ID） | `OPEN` | `benchmarks/m3/results/` 仅 `README.md`，无场景 JSON；`docs/m3-benchmarks.md` 全表“待 xc 基线” | P7 合并的只是 harness + 报告骨架，不等于 M3 基线成立，也不等于 M3-P 门禁成立；`M3-PT4` 无基线时不得声称“无回归” |
| §6.2 附件缺失 | 阻塞（门禁前置缺失，未登记 GAP ID） | `OPEN` | `docs/m4-quic-decision.md`、`docs/m4-resource-budget.md`、`docs/m4-memory-report.md`、`measurements/m4/`、`measurements/m4/ci/protection.json` 均不存在 | `docs/m3-m4-gates.md` §6.2 必填附件不全，§6.3 无法签署 PASS |

非阻塞项（单列以示区分）：

| 缺口 | 类型 | 状态 | 证据 | 说明 |
|---|---|---|---|---|
| `GAP-M3-B3-01` | 非阻塞（条件适用） | `OPEN` | `docs/m3-m4-gates.md:457`；`interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md` 状态表 B3 行 | Firefox 互通未判定：未找到可用 Firefox 二进制，B3 记 `NOT DETERMINED`，待有二进制后重测 |

附注（并行未关闭项，只列存在，不在本单处理、未关闭）：PR #2（`test/fuzz-regression-corpus`，OPEN，CI `build / lint (stable)` 失败）；CI-C1（`.github/workflows/ci.yml:212–218`，fuzz job 的 `uses` + `run` 非法 step）；P8 评审非阻塞 N-1…N-8 跟进项；RV-PR15/16/18/23-NB 跟进项。§3 登记的 `GAP-M3-E-01` 是示例缺口，不在本表混列，也不改变本单 FAIL 结论。

---

## 6. 结论

**FAIL。**

依据：`docs/m3-m4-gates.md:442`（§4 规则 1）规定存在任一阻塞 GAP 时 §6 结论必须是 FAIL；`docs/m3-m4-gates.md:509`（§6.3）规定结论只能是 PASS 或 FAIL，空白、`TBD` 与含糊措辞均视为 FAIL。当前清单：

- 已登记阻塞 GAP **9 个**：`GAP-M3-B0-02`（门禁 §5，1 个）+ `GAP-M4-T-01`…`GAP-M4-T-08`（选型文档 §6，8 个），均为 `OPEN`。
- 另有 2 项未登记 GAP ID 的门禁前置缺失：M3-P 基线缺失、`docs/m3-m4-gates.md` §6.2 必填附件缺失（清单见 §5）。

因此本单结论为 FAIL；本单不填写 `docs/m3-m4-gates.md` §6.1/§6.2/§6.3（`docs/m3-m4-gates.md:38`：复选框只能由里程碑验收 PR 勾选）。

本收尾文档合并 ≠ M3/M4 完成；M3/M4 完成定义达成前不得发最终完成汇报。最终是否算完成、缺口如何处置，由协调者与用户在收尾时另行定夺，不由本单作者定夺。

---

## 7. 未做项复述

- 发布到 crates.io：**未做**。
- 版本号改动：**未做**（`0.1.0` 未动）。
- 门禁文档改动（复选框、条文、§5 缺口行）与 §6 表格填写：**未做**。
- 基线正式模式运行：**未做**（未产任何基线数字，未动 `benchmarks/m3/results/`）。
- 固件 / 移植 / 板上实测：**未做**（未新建 `firmware/`）。
- 示例代码：**未做**（未新建任何 `examples/`）。
- CI 修复：**未做**（未改 `.github/workflows/ci.yml`）。
- PR #2 修复：**未做**。
- P8 评审 N-1…N-8 与 RV-PR15/16/18/23-NB 跟进：**未做**。
