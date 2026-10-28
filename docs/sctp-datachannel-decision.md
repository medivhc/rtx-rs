# P5：SCTP / DataChannel 决策（interim）

| 项 | 内容 |
|---|---|
| 决策编号 | P5（计划 P5 节“SCTP / DataChannel 决策门”；决策文档单） |
| 基线 | `main` @ `581f326`（2026-10-28，RV-PR17-NB / PR #18 合并点；本文所有仓库内引用均按此 commit 复核） |
| 决策对象 | M3 阶段是否需要 SCTP/DataChannel 实现；M3 浏览器互通采用哪条数据路径 |
| 交付形态 | 只新增本文档；不写代码、不改 API、不新增 crate、不改 CI、不改已有文档 |
| 结论（interim） | M3 跳过 SCTP 实现；M3 浏览器互通走 WebTransport DATAGRAM / 流，不依赖 DataChannel；满足 §5 触发条件时重估，不是最终关闭 |
| 依据 | `ARCHITECTURE.md` §3、§5、§6、§13、§15、§16、§20；`DEPENDENCY_AUDIT.md` §1、§3、§4；`docs/m3-m4-gates.md` §0.1、§0.3、§1.1–§1.3、§1.6、§2.1.2、§2.5、§3；`docs/ice-turn-decision.md` §1.4、§6；`docs/ice-relay-caller-guide.md`；RTX-COMPLETION-PLAN.md P5 节、PIPELINE.md §5 |

> 说明：RTX-COMPLETION-PLAN.md 与 PIPELINE.md 是协调者文档，不在本仓库内。本文只引用其节名与原文句子，不引用行号。仓库内文件的行号以 `581f326` 实测为准。

## 1. 决策结论（interim，不是最终关闭）

本决策是 **interim 决策**，不是“永不做 SCTP”的最终关闭。具体结论：

1. **M3 阶段不排 SCTP 实现。** 不新建 `rtx-sctp` crate，不写 SCTP 关联/chunk/重传/拥塞控制状态机，也不写 DataChannel / DCEP 通道状态。M3 的 QUIC/WebTransport 路径不因本决策增加任何协议实现。
2. **M3 浏览器互通只走 WebTransport DATAGRAM / 流。** Chrome 互通按 `docs/m3-m4-gates.md` §1.3 的 M3-B0–B2 执行：会话建立、DATAGRAM 双向收发、流双向收发。这三项均以 WebTransport 为路径，不要求 DataChannel。
3. **本结论可重估。** 满足 §5 任一触发条件时，本决策重新排进队列重新评估。重估是决策动作，不是自动开工实现；若重估结论为“要做”，仍需单独立项、单独任务书与门禁证据。
4. **本决策不预判 M4-Q3。** M4 的替代性分析（`docs/m3-m4-gates.md` M4-Q3）仍按门禁原文在 M4 阶段完成；本文只回答“M3 是否需要 SCTP/DataChannel”，不替 M4 的 required/optional/absent 矩阵下结论。
5. **与 PIPELINE.md §5 的默认决策一致。** PIPELINE.md §5 的默认决策是：P5 默认跳过 SCTP 实现；M3 浏览器互通先走 WebTransport DATAGRAM / 流，不依赖 DataChannel；若后续互通证据证明 DataChannel 是必需的，流水线把 P5 决策文档单重新排进队列，而不是擅自开工实现。本文是该默认决策的书面化与证据化，不扩大其范围。

**本单不做什么**（与结论绑定）：不写 SCTP 实现、不新增 `rtx-sctp` crate、不定 SCTP API、不改 `rtx-quic` / `rtx-webrtc`（两者在 `581f326` 尚未建树）、不改门禁、不写 P6 QUIC/WebTransport 实现、不合并。本文不声称“SCTP 已实现”“将在本单实现”“DataChannel 已覆盖”或“将覆盖”。

## 2. 需求证据盘点

### 2.1 “需要 DataChannel”的证据：无

逐项核查（`581f326`）：

| # | 证据来源 | 核查结果 | 判定 |
|---|---|---|---|
| 1 | 树内实现与调用方 | `crates/` 下大小写不敏感检索 `sctp` / `datachannel` / `data_channel` 零命中；`Cargo.toml:3-15` 的 workspace members 只有 11 个 crate，不含 `rtx-sctp` / `rtx-quic` / `rtx-webrtc` / `rtx-webtransport` | 无 DataChannel 调用方，无实现 |
| 2 | 互通测试要求 | 树内无 `interop/` 目录；`docs/m3-m4-gates.md` §1.3 的 M3-B0–B4 均为 WebTransport/QUIC 互通条目（B0–B2 为会话/DATAGRAM/流，B3 Firefox 条件适用，B4 Quinn/WebTransport 参考实现）；M3 出口判定（§1.6，`:203-216`）不列 DataChannel 条目 | 无互通测试要求 DataChannel |
| 3 | 部署证据 | 树内无 `measurements/`、`deployments/` 或归档部署报告；计划 R6-3 的浏览器互通尚未执行 | 无部署证据（**无证据**） |
| 4 | 门禁必做项 | `docs/m3-m4-gates.md` 中 SCTP 只有三处（见下），均不是“必须实现 SCTP” | 无必做项 |

第 4 项的三处 SCTP 及边界（不得读成实现义务）：

- **§0.3 的 crate 名清单**（`docs/m3-m4-gates.md:43`）：来自 ARCH §5 的规划名，只约束文档用语。`rtx-sctp` 是名字占位，不是实现承诺；`581f326` 的 workspace 也不含该 crate。
- **M4-Q3**（`docs/m3-m4-gates.md:295`）：门禁原文（逐字）：

  > 对每个 required 能力做替代性分析：WebRTC DataChannel/SCTP、纯 RTP、UDP/TCP 自定义协议能否替代；替代结论要有协议对比或原型/抓包证据。缩减的 QUIC profile 不算“替代 QUIC”，只影响 M4-S 的移植范围。

  SCTP 在这里是被分析的替代项，不是 required 能力；本条不构成 M3 或 P5 的实现要求。
- **§3 非目标**（`docs/m3-m4-gates.md:413`）：原文是“M4 不要求 SDP/完整 ICE/DTLS/SCTP 全套；只移植目标真正需要的模块”。它排除“全套”，不产生 SCTP 必做项。

补充边界：

- **ARCH 侧没有实现承诺。** ARCH §13 的原文是“SCTP/DataChannel if the target actually requires them.”；ARCH §5 的 `rtx-sctp` 位于 “Planned expansion” 的 crate 名清单中。二者都是条件性/规划性表述。ARCH §3 把“complete browser-compatible PeerConnection implementation from scratch”列为非目标；门禁 §3（`docs/m3-m4-gates.md:413`）沿用该边界，并写明 M4 不要求 SDP/完整 ICE/DTLS/SCTP 全套。
- **依赖审计不是需求来源。** `DEPENDENCY_AUDIT.md:39` 对 webrtc-rs SCTP/DataChannel 的定位是“Linux direct; embedded only if required”，`:201-203` 进一步写明 SCTP 天然含 hash map、deque、slab 与多队列，Full DataChannel 不应进入最小嵌入式 profile。这是复用/选型建议，不是需求证据。
- **复用顺序不是时间表。** `DEPENDENCY_AUDIT.md:223-227` 的 `RTCP -> RTP -> STUN/SRTP -> ICE -> DTLS -> SCTP/DataChannel` 是“preferred reuse sequence”，不构成“SCTP 已排期”或“在 M3 做”的证据。

### 2.2 “不需要 / 不依赖 DataChannel”的证据

1. **P6 浏览器互通走 WebTransport 路径。** `docs/ice-turn-decision.md:52` 写明：“P6 浏览器互通（计划 R6-3）走 WebTransport 路径：QUIC/H3 的客户端-服务器模型，不跑 ICE，不存在候选配对，也就不需要 TURN。”同文 §6 末节（`docs/ice-turn-decision.md:305-309`）再次写明 R6-3 不接 relay，并声明 P5 SCTP 决策不在该单范围。`docs/ice-relay-caller-guide.md:31-32` 同样把 P6 的 WebTransport 路径与“P5 SCTP 决策不在本指南范围”并列。
2. **P6 的 QUIC/WebTransport 组件面不含 SCTP。** ARCH §15 的 H3/WebTransport 初始子集（varint、H3 frame header、WebTransport 所需 SETTINGS、CONNECT 的最小 QPACK 形式、extended CONNECT、流/会话标识、capsules、DATAGRAM 映射）不含 SCTP；ARCH §20 的 M3 工作项（`quinn-proto` backend facade、minimal H3/WebTransport handshake、browser DATAGRAM and stream interoperability、allocation and batching benchmarks）也不含 SCTP。计划 R6-1 / R6-2 的 `quinn-proto` 窄外观与 H3/WebTransport 层按此范围规划；对应门禁条目是 `docs/m3-m4-gates.md` §1.1 的 M3-Q0–Q8 与 §1.2 的 M3-H1–H8。`581f326` 尚未建 `rtx-quic` / `rtx-h3` / `rtx-webtransport`，因此这是**计划范围陈述**，不是“已实现”陈述。
3. **门禁的替代性分析框架把 SCTP 放在“可替代方案”一侧。** M4-Q3 要求对每个 required 能力分析 WebRTC DataChannel/SCTP、纯 RTP、UDP/TCP 自定义协议能否替代，并要求协议对比或原型/抓包证据；M4-QC1–QC10 能力矩阵（`docs/m3-m4-gates.md` §2.1.1）也不含 DataChannel 行。即：M4 需要证明“目标到底需要什么”，而不是默认需要 SCTP。
4. **M2 出口判据不强制 DataChannel。** ARCH §20 M2 的出口判据是“RTP media can be exchanged with a browser through a minimal interoperable path or a clearly defined remaining gap”；它允许“明确登记的剩余缺口”，没有把 DataChannel 写成必做项。

### 2.3 判定

- “需要 DataChannel”的证据条目数为 **0**；其中 2.1 节第 3 项属**无证据**，不得写成“可能有需求”。
- 按 PIPELINE.md §5 与计划 P5 节，P5 默认跳过 SCTP 实现；本单据此给出 interim 结论，不为“将来可能需要”编造需求。
- 本盘点不把 `rtx-sctp` 规划名、M4-Q3 的替代项列表、依赖审计的复用顺序读成实现义务或时间表。

## 3. 替代路径分析（按 M4-Q3 框架）

M4-Q3 的框架是：对每个 required 能力，逐项回答“WebRTC DataChannel/SCTP、纯 RTP、UDP/TCP 自定义协议能否替代”，结论要有协议对比或原型/抓包证据。以下把该框架用于 **M3 浏览器互通**场景（Chrome 建 WebTransport 会话、DATAGRAM、流；`docs/m3-m4-gates.md` §1.3），不用于 M4 的 required 能力判定。

| 路径 | 在 M3 浏览器互通下的能力 | 覆盖 M3-B0–B2 吗 | 主要代价 / 缺口 |
|---|---|---|---|
| WebRTC DataChannel / SCTP | 依赖 ICE + DTLS + SCTP + DCEP 全栈；浏览器侧需要 `RTCPeerConnection` 与 SDP 交换 | 否（且与 P6 路径冲突） | 树内没有 ICE 全栈（R4-2 结论是 STUN + 直连 + relay 透传，不做 TURN 客户端、不做 SDP）；ARCH §3 明确不做浏览器级 PeerConnection；门禁 §3 也写明 M4 不要求 SDP 全套 |
| 纯 RTP | 只承载媒体载荷；浏览器不能在没有 WebRTC 信令/ICE/DTLS-SRTP 的情况下直接接收裸 RTP | 否 | 不提供服务端-浏览器会话建立，也不承载 M3 的 DATAGRAM/流语义；M3 的路径是 QUIC/WebTransport，不是媒体传输 |
| UDP / TCP 自定义协议 | 可自定义可靠/不可靠语义，但浏览器没有对应 API，需自建封装、NAT 穿透与安全层 | 否 | 浏览器不可直接调用；要另做一套与 WebTransport 平行的会话/安全层，且没有门禁条目支撑 |
| WebTransport DATAGRAM / 流 | 浏览器原生 API；QUIC 提供加密、拥塞控制、流控；DATAGRAM 提供不可靠消息，流提供可靠有序字节流 | 是（M3-B0–B2 即按此定义） | 需要按 M3-Q / M3-H 建 `rtx-quic` / `rtx-h3` / `rtx-webtransport` 窄外观与最小子集；这是 M3 的计划内工作，不是本决策新增的实现 |

**论证**：

1. M3 的互通对象是浏览器；浏览器侧能直接使用的数据路径是 WebTransport（DATAGRAM/流）或 WebRTC（DataChannel/媒体）。后者的前置是 ICE/DTLS/SCTP/SDP；ARCH §3 已把浏览器级 PeerConnection 列为非目标，R4-2 又明确树内不做 TURN 客户端、不做 SDP，因此 DataChannel 路径在 M3 没有可落地的前置。
2. WebTransport 路径的每个能力都有门禁条目与证据形式：会话（M3-B0）、DATAGRAM（M3-B1 / M3-Q4 / M3-H8 / M3-PS8）、流（M3-B2 / M3-Q3 / M3-PS9）。因此“WebTransport 路径已覆盖 M3 互通需求”是可验收的陈述，不是主观偏好。
3. 纯 RTP 解决的是媒体载荷，不解决浏览器会话建立与 DATAGRAM/流语义；UDP/TCP 自定义协议浏览器不可直接调用。两者都不能覆盖 M3-B0–B2。
4. 结论：**M3 浏览器互通由 WebTransport DATAGRAM/流覆盖，不需要 DataChannel**。本结论不外推到“DataChannel 永远无用”；范围与重估见 §5。

**门禁原文边界（不得改写）**（`docs/m3-m4-gates.md:295`，M4-Q3，逐字）：

> 缩减的 QUIC profile 不算“替代 QUIC”，只影响 M4-S 的移植范围。

因此：

- 本文不把“嵌入式只移植 QUIC 子集”说成“用别的协议替代 QUIC”；
- QUIC profile 的缩减属于 M4-S 的移植范围问题（M4-S1 的“模块 → 能力”映射、M4-S2 的上游差分测试；`docs/m3-m4-gates.md:384-392`），不是 P5 的替代路径；
- M3 仍以 QUIC/WebTransport 为路径，`quinn-proto` 窄外观（M3-Q0–Q8）与最小 H3/WebTransport 子集（M3-H1–H8）不因本决策改变。

## 4. footprint 评估（定性，不写实现）

本节只描述“若将来做 SCTP”时的范围边界与定性成本，**不写实现代码、不定 API 签名、不排实现工期**。

### 4.1 新 crate 与规划名

- 新 crate 只可能是 ARCH §5 规划名 `rtx-sctp`（`ARCHITECTURE.md` §5 的 planned expansion；`docs/m3-m4-gates.md:43` 的 crate 名清单）。`581f326` 的 workspace（`Cargo.toml:3-15`）不含该 crate，本单不创建它。
- 依赖方向按 ARCH §6：`rtx-sctp` 只能向内依赖 `rtx-core` / `rtx-buffer` / `rtx-wire` / `rtx-crypto` 一类的可移植层，不得反向依赖平台 crate。DataChannel 的浏览器语义与通道生命周期属于 WebRTC 层（`rtx-webrtc`）的职责边界，不应塞进 `rtx-sctp`。
- 上游参考是 webrtc-rs 的 `rtc-sctp` / `rtc-datachannel`（`DEPENDENCY_AUDIT.md:130-146` 的 crate 清单）与 str0m 的 `sctp-proto`（`DEPENDENCY_AUDIT.md:52-58` 的依赖树）。这些只是参考/复用候选，不是树内已有实现。

### 4.2 no_std 约束与有界表模式

若 `rtx-sctp` 要进入可移植层，必须复刻现有可移植 crate 的约束模式，而不是 `std` 风格：

- `rtx-ice`：`#![cfg_attr(not(feature = "std"), no_std)]` 与 `#![forbid(unsafe_code)]`（`crates/rtx-ice/src/lib.rs:1-2`）；“allocates nothing and never blocks”（`crates/rtx-ice/src/lib.rs:3-11`）；有界表 `MAX_ICE_CANDIDATES = 16`、`MAX_ICE_PAIRS = 64`、`MAX_EVENTS = 8`、`MAX_STUN_MESSAGE_SIZE = 64`（`crates/rtx-ice/src/checklist.rs:28`、`:39`、`:42`、`:49`）。
- `rtx-dtls`：同样的 no_std 与 forbid unsafe（`crates/rtx-dtls/src/lib.rs:1-2`），allocation-free（`crates/rtx-dtls/src/lib.rs:4`），`ReplayWindow` 是 64 条记录的滑动位图（`crates/rtx-dtls/src/lib.rs:16`）。
- SCTP 天然包含 hash map、deque、slab 与多队列（`DEPENDENCY_AUDIT.md:201-203`），与上述“固定上限 + 无分配”模式直接冲突。若要做，必须先把 association、stream、reassembly、retransmission、chunk 队列逐项映射到 ARCH §16 的显式上限，并为每个上限定义超限行为（拒绝或显式丢弃，不静默增长）。这属于未来实现单的预算工作，本文不代做。

### 4.3 与 `rtx-quic` / `rtx-webrtc` 的接口面（只描述边界）

- **`rtx-quic`：无接口面。** QUIC 不承载 SCTP；WebTransport 用 QUIC 的 DATAGRAM 与流，不经 DataChannel/SCTP。因此无论 M3 还是 P6 的 WebTransport 路径，`rtx-quic` 都不需要 SCTP 接口。把 SCTP 接到 QUIC 上不是本计划中的路径。
- **`rtx-webrtc`：可能的上层归属。** DataChannel 是 WebRTC 的 API 概念；若将来做，`rtx-webrtc` 负责通道生命周期与对外 API，`rtx-sctp` 只做 SCTP 关联/流/chunk 状态机。传输绑定需要 DTLS 提供的数据报通道（`rtx-dtls` 已有 record layer，但没有 SCTP 适配）。此外 DataChannel 还需要 DCEP（RFC 8832）通道协商与 SDP 侧 `m=` 协商，而 ARCH §3 把完整浏览器级 PeerConnection 列为非目标（门禁 §3 沿用该边界，并写明 M4 不要求 SDP 全套）——这两项是比 SCTP 状态机更大的前置缺口。
- **`rtx-linux` / `rtx-embassy` / `rtx-smoltcp`：只提供传输。** SCTP 状态机保持 sans-I/O，socket/定时器/任务由平台层提供；这沿用 `rtx-core::ProtocolMachine` 的既有模式，不新增 runtime 抽象。
- 以上只界定范围与依赖方向；具体 API 签名、事件类型、缓冲所有权留给未来实现单的决策文档，本文不定义。

### 4.4 定性成本结论

- 直接成本：新协议状态机 + 有界队列 + 定时器/重传 + 多流调度 + 通道生命周期 + DCEP；按 `DEPENDENCY_AUDIT.md:39` 的评级是“high footprint”。
- 间接成本：需要 DTLS 数据报绑定与 SDP/通道协商前置；这两项当前都不在树内，也不在本计划的 M3/M4 必做项里。
- 因此 footprint 评估的结论是：在没有 §5 触发证据前，SCTP/DataChannel 的成本不会由 M3 或 P6 的 WebTransport 路径分摊，提前做只会增加未评审面。该结论支持 §1 的 interim 决策。

## 5. 重估触发条件（可判定）

本决策在满足以下**任一**条件时重新评估。触发条件是**归档证据事件**，不是“以后再说”或主观判断；无证据时维持本决策。

### 5.1 触发条件 A：R6-3 浏览器互通实测证据

- **证据形态**：按 `docs/m3-m4-gates.md` §0.1 “记录”类证据归档的浏览器互通报告——含被测 commit、日期、环境、脚本与原始日志，可复跑。
- **必须回答的三件事**：
  1. 哪个具名互通场景（浏览器版本、API、操作序列）无法由 WebTransport DATAGRAM/流覆盖；
  2. 该场景的失败记录（抓包/qlog/服务端日志/浏览器控制台）证明失败不是实现缺陷，而是路径能力缺失；
  3. 为什么 DataChannel 是**唯一**覆盖路径（其他三条路径为何不可行）。
- **判定**：三件事都有归档证据 → 触发重估；缺任一项 → 不触发。

### 5.2 触发条件 B：真实部署证据

- **证据形态**：归档的部署证据文档（不是口头说明、聊天记录或未提交的本地结果），含部署方/场景、时间、环境、浏览器或对端能力清单，以及“为什么不能用 WebTransport”的说明。
- **必须回答的三件事**：
  1. 哪个部署必须使用 DataChannel（对端只暴露 WebRTC DataChannel API，或网络策略禁止 WebTransport）；
  2. 该限制的原始依据（对端能力清单、抓包、厂商文档）；
  3. 该部署是否在项目交付范围内（有计划条目或验收要求指向它）。
- **判定**：三项齐全且部署在范围内 → 触发重估；否则登记为观察项，不触发。

### 5.3 触发后的动作（重估，不是自动开工）

1. 按 PIPELINE.md §5，把 P5 决策文档单重新排进队列，重新评估本决策；
2. 重估产出新的决策结论（可以是“仍跳过”“改做子集”“做完整 DataChannel”），并更新本文档或新增决策文档；
3. 若重估结论是“要做”，仍需单独立项、单独任务书与门禁证据；本文不授权任何实现。

### 5.4 不构成触发的项（避免含糊）

- “WebRTC 通常都有 DataChannel”“其他栈都有 SCTP”一类的类比；
- `rtx-sctp` 规划名出现在 ARCH §5 / 门禁 §0.3；
- M4-Q3 把 DataChannel/SCTP 列为待分析的替代项；
- 依赖审计的复用顺序把 SCTP/DataChannel 排在最后（`DEPENDENCY_AUDIT.md:223-227`）；
- 任何没有归档证据的“将来可能需要”。

---

## 附：与计划、流水线和门禁的对应

| 来源 | 原文 / 节名 | 本文落点 |
|---|---|---|
| RTX-COMPLETION-PLAN.md P5 节 | “SCTP / DataChannel 决策门”；决策问题“Linux 直接复用 vs 嵌入式仅在必需时做”；交付是决策文档（需求证据 + footprint 评估 + 推荐），不先写实现 | §1–§4；结论为 M3 跳过、嵌入式范围留给 M4-Q3 / M4-S |
| PIPELINE.md §5 | P5 默认跳过 SCTP 实现；M3 浏览器互通先走 WebTransport DATAGRAM/流；若互通证据证明 DataChannel 必需，把 P5 决策文档单重新排进队列 | §1 结论第 5 条；§5 触发与动作 |
| `ARCHITECTURE.md` §13 | “SCTP/DataChannel if the target actually requires them.” | §2.1 补充边界；§1 结论 |
| `DEPENDENCY_AUDIT.md` §1 | “Linux direct; embedded only if required” | §2.1 补充边界；§4.4 |
| `docs/m3-m4-gates.md` M4-Q3 | 替代性分析要求；缩减的 QUIC profile 不算“替代 QUIC”，只影响 M4-S 的移植范围 | §3 全节 |
