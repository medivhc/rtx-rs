# Changelog

> 本文件只记录已合并的 P0–P8 PR，集中放在 `Unreleased` 一节；未合入的 PR（见 `docs/m3-m4-closeout.md` §1 末节）不在本文件。
> 每条 bullet 附 PR 号 + merge commit（7 位短哈希），与 `docs/m3-m4-closeout.md` §1 清单一致。
> workspace 版本保持 `0.1.0`；本文件不含发布记录、日期与版本标题。

## Unreleased

### P0 — 基线（R0）

- PR #1（merge `43329cf`）：新增 MIT OR Apache-2.0 双许可 `LICENSE`，修正 `repository` 地址并在各 crate 继承（R0-1）。
- PR #4（merge `4db963f`）：新增 `docs/m3-m4-gates.md` 可判定门禁清单（R0-2）。

### P1 — 加密加固（R1）

- PR #5（merge `8acc1a7`）：新增 `docs/ed25519-x25519-provider-design.md`，含 provider 设计、实现阶段 P0–P5 与常数时间审计清单（R1-1）。
- PR #3（merge `b0a4ebf`）：把 `rtx-crypto` property 测试参数化到真实 RustCrypto 后端。

### P2 — DTLS（R2）

- PR #6（merge `dc0b27e`）：新增 `crates/rtx-dtls`，DTLS 1.2 record 层 sans-IO 状态机（R2-1）。
- PR #7（merge `daa6b56`）：DTLS 1.2 握手状态机与 DTLS-SRTP 密钥导出（R2-2）。
- PR #8（merge `69597a8`）：DTLS 真实 UDP 握手泵测试与互通缺口文档（R2-3，测试 + 文档）。

### P3 — SRTP（R3）

- PR #9（merge `7c2b612`）：新增 `crates/rtx-srtp`，AES128_CM_HMAC_SHA1_80 保护与重放窗口（R3-1）。
- PR #10（merge `dbaeba5`）：SRTP 加密区改回 RFC 3711 §3.1 布局（R3-1b）。
- PR #11（merge `88823ab`）：DTLS-SRTP KDF 接线（RFC 3711 §4.3 + RFC 5764 §4.2 方向映射，R3-2）。
- PR #12（merge `a095f06`）：SRTCP 会话密钥派生与包保护（R3-3）。

### P4 — ICE / relay（R4）

- PR #13（merge `f6d0cc5`）：新增 `crates/rtx-ice`，有界候选表、pair 表与 sans-IO 检查表状态机（R4-1）。
- PR #14（merge `c545331`）：新增 `docs/ice-turn-decision.md`，TURN 复用决策（选项 B：relay 透传，R4-2）。
- PR #15（merge `6e4bcd9`）：`rtx-ice` 文档措辞收敛到 R4-2 决策（R4-2-F1）。
- PR #16（merge `4bce6f1`）：relay 透传一致性测试（R4-2-F2，test-only）。
- PR #17（merge `7647f4f`）：新增 `docs/ice-relay-caller-guide.md`（R4-2-F3，docs-only）。
- PR #18（merge `581f326`）：调用方 relay 指南措辞修正（RV-PR17-NB，docs-only）。

### P5 — SCTP 决策

- PR #19（merge `4641cd5`）：新增 `docs/sctp-datachannel-decision.md`，M3 跳过 SCTP 实现的 interim 决策。

### P6 — QUIC / WebTransport（R6）

- PR #20（merge `3983ed6`）：新增 `crates/rtx-quic`，`quinn-proto` 窄外观（M3-Q）。
- PR #21（merge `d9663e1`）：最小 H3/WebTransport 编解码层（M3-H1/H2/H6/H7/H8）。
- PR #22（merge `9940499`）：Chrome SETTINGS / CONNECT 真实帧抓包 harness（M3-H3/H4 证据，不含互通结论）。
- PR #23（merge `c6c4897`）：新增 `crates/rtx-h3`，SETTINGS / QPACK / CONNECT（M3-H3–H5）。
- PR #24（merge `edca8ea`）：`interop/m3/rtx-server/` 服务端 harness + 回环证据（M3-B 前置片）。
- PR #25（merge `ddc43e4`）：Chrome WebTransport 两阶段实测；B0 阻塞，登记 `GAP-M3-B0-02`，B1/B2 `not_run`。

> 说明：`6c69657` 为直接提交到 `main` 的门禁 §5 缺口登记（`GAP-M3-B0-02` / `GAP-M3-B3-01`，无 PR、无 merge commit），不计入上方 bullet。

### P7 — M3-P harness

- PR #26（merge `37a2a8a`）：`crates/rtx-testkit` + `benchmarks/m3/`（独立 crate + `run.sh`）+ `docs/m3-benchmarks.md` 报告骨架；不含任何基线数字。

### P8 — M4-0-1 目标选择

- PR #27（merge `4ba22ea`）：新增 `docs/m4-target-selection.md`，结论“未选定”，登记 `GAP-M4-T-01`…`GAP-M4-T-08`。
