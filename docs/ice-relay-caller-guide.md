# R4-2-F3：调用方 relay 供给指南

| 项 | 内容 |
|---|---|
| 单号 | R4-2-F3（P4 跟进；文档单） |
| 基线 | `main` @ `4bce6f1`（R4-2-F2 / PR #16 合并点） |
| 唯一依据 | [`docs/ice-turn-decision.md`](ice-turn-decision.md) 的 §2.B、§3、§4（下称“决策”） |
| 适用代码 | `crates/rtx-ice` 的 `Candidate` / `Checklist` / `Event`（入表、配对、检查、提名、consent） |
| 交付形态 | 只新增本文档；不写代码、不改 API、不改常量、不改 CI、不改已有文档 |
| 结论 | relay 候选由调用方自备 TURN 供给；`rtx-ice` 只做入表、配对、检查、提名与 consent 时间戳 |

> **片段声明**：本文中的代码片段均为说明性伪代码 / 流程描述，**非可编译示例**，不对应任何新增 API、类型、crate 或测试；树内也不新增 TURN 客户端。片段只用于解释调用方职责与事件映射。
>
> **锚点说明**：本文引用的源码行号按当前基线 `main` @ `7647f4f`（R4-2-F3 / PR #17 合并点）实测复核；初稿“按 `c545331` 实测、`4bce6f1` 复核无变”的说法与 git 事实不符（`lib.rs` 在两者之间因 F1 措辞收敛有变更），已作废。决策条款只引用节号。

---

## 1. 适用范围与非目标

### 1.1 适用

- 调用方已经自备 TURN 基础设施：有可用的 TURN 服务器，并在树外实现了自己的 TURN 客户端（Allocate / Refresh / 认证 / 权限 / 通道）。
- 调用方希望把该 TURN 分配得到的 relayed 传输地址作为 relay 候选交给 `rtx-ice`，让它参与配对、检查与提名。
- 本指南描述“调用方如何把外部 TURN 供给给 `rtx-ice`”的契约与流程，不描述 TURN 协议本身的实现。

### 1.2 非目标

- **树内没有 TURN 客户端。** Allocate、Refresh、长期凭证认证、CreatePermission、ChannelBind、ChannelData 全部归调用方（决策 §2.B、§3 执行摘要；`crates/rtx-ice/src/lib.rs:46-49`）。本指南不教如何实现 TURN 服务器 / 客户端，也不把引入 TURN 客户端作为路径；完整 TURN 客户端评估（决策 §6 的 `R4-2-F4`）只在出现真实部署证据时条件触发，目前未排期、不属本指南承诺。
- **不声称树内认证。** `rtx-ice` 不校验 ICE 检查的 `USERNAME` / `MESSAGE-INTEGRITY`，明写不宣称 authenticated ICE agent（`lib.rs:55-58`）；TURN 的长期凭证认证归调用方。本文不宣称树内已认证 ICE 或 TURN。
- **不改 `rtx-ice`。** relay 候选只走既有 `add_local_candidate` / `add_remote_candidate`；不新增 API、事件、常量，不改有界表（决策 §2.B“对 `rtx-ice` API 的影响：零”、§5）。
- **P6 不把 relay 写成必选项。** P6 的浏览器互通走 WebTransport 路径时不跑 ICE、没有候选配对，不接 relay（决策 §1.4、§6 末节）；只有 P6 选择 ICE/WebRTC 且部署确有 relay 需求时，才由调用方 / 运行时按本指南自备 TURN。
- 不涉及 SDP 实现、P5 SCTP 决策、P6 QUIC/WebTransport 决策。

---

## 2. 外部 TURN 分配供给流程

relay 候选在 `rtx-ice` 眼里没有特殊分支：它只是一个 `address` 与 `base` 都等于 relayed 传输地址的普通候选。差别全在调用方——发送要经 TURN 封装，接收要先解封装（§4）。

### 2.1 供给时序（全部在 `start` 前完成）

1. **Allocate。** 调用方的 TURN 客户端向自己的 TURN 服务器执行 Allocate（RFC 5766 §5），得到 relayed 传输地址。该地址是 TURN 服务器替该分配收发数据的传输地址；它不是本地 socket 地址，也不是 STUN/TURN 的 mapped address。
2. **本地 relay 候选入表。**

```text
Candidate::new(Relay, COMPONENT_RTP, Transport::Udp,
               relayed_transport_address,
               Some(relayed_transport_address))
    -> Checklist::add_local_candidate(...)
```

3. **远端 relay 候选入表。** 对端的 relayed 传输地址来自信令，`address` 与 `base` 都填它，经 `add_remote_candidate` 入表。
4. **TURN 侧权限。** 调用方在自己的 TURN 会话上为对端准备权限（RFC 5766 §8），使用 ChannelData 时再做 ChannelBind（§11）。`rtx-ice` 不感知 CreatePermission / ChannelBind；权限或通道缺失会让检查在 TURN 侧被丢弃，表现见 §5。
5. **配对与启动。** `generate_pairs()` 之后 `start(now)`。

### 2.2 时机与生命周期约束

- **所有 `add_*` 必须在 `start` 前完成。** `start` 之后两个 add API 都返回 `IceError::AlreadyStarted`（`checklist.rs:317-335`；决策 §4.3）。
- **没有 remove / replace API。** 入表后不能在会话中途撤下、替换或补充 relay 候选；因此分配必须在 `start` 前成功，失败就不入表（决策 §2.B“生命周期归属”）。
- **中途重新分配不支持。** 新的 relayed 传输地址意味着新的信令 / 新的 ICE 会话，不能原地替换（决策 §2.B）。
- **名额。** relay 候选占用既有的 `MAX_ICE_CANDIDATES`（每侧 16）与 `MAX_ICE_PAIRS`（64）预算；表满返回 `IceError::CandidateTableFull` / `IceError::PairTableFull`，拒绝且不驱逐（`lib.rs:99-110`）。调用方须在 `start` 前为 relay 预留名额。

### 2.3 start 前分配失败

Allocate 失败就没有 relayed 传输地址：不要构造 relay 候选，只加 host / srflx。这是调用方的失败处理，不是 ICE 错误（决策 §2.B 失败语义表首行）。是否继续一个不含 relay 的会话由调用方决定。

---

## 3. base 填法（含反例）

### 3.1 正确填法

`address = base = relayed 传输地址`，两者严格相等：

```text
Candidate::new(Relay, COMPONENT_RTP, Transport::Udp,
               relayed_transport_address,
               Some(relayed_transport_address))
```

依据 RFC 8445 定义节与 §5.1.1.2（“The base of a relayed candidate is that candidate itself.”），决策 §2.B 已钉住。本地与远端 relay 候选适用同一规则。

### 3.2 机制：为什么必须是 relayed 地址

以下四处必须同时成立：

1. `Candidate::base` 的文档语义是“检查发送时所使用的本地基地址”（`candidate.rs:129-135`）。
2. `send_check` 把 `Event::SendCheck.source` 设为 `pair.local().base()`（`checklist.rs:807`）。relay 场景下 `source` 就等于 relayed 地址，调用方据此找到对应分配并做 TURN 封装。
3. 成功响应匹配要求 `pair.local().base() == meta.destination`（`checklist.rs:646`）。TURN 服务器把内层响应投递到 relayed 地址；调用方解封装后以 `destination = relayed 地址` 交给 checklist，正好匹配。
4. 入站检查的本地候选查找以 `meta.destination` 为键、由 `position()` 与 `candidate.address()` 逐项比对（`checklist.rs:541-544`、`:975-980`），同样要求调用方给出 `destination = relayed 地址`。

补充：consent indication 的刷新也要求 `pair.remote().address() == meta.source` 且 `pair.local().base() == meta.destination`（`checklist.rs:688-700`），即 §4 的 `destination = relayed 地址` 规则对 consent 同样适用。

### 3.3 反例 A：base 填本地 TURN socket 地址

设本地 TURN 客户端 socket 为 `local_socket`；候选仍 `address = relayed`，但 `base = local_socket`。代码会接受这个构造——`Candidate::new` 对 Relay 只要求 `base = Some`，不校验它与 `address` 的关系（`candidate.rs:172-181`）——但契约被破坏：

- `Event::SendCheck.source` 变成 `local_socket`，不再是 RFC 8445 定义的 base，也不再是定位分配的键；调用方按 `source` 找分配会找不到，只能额外维护一张偏离契约的映射。
- 响应匹配要求 `pair.local().base() == meta.destination`（§3.2 第 3 条），按 `base = local_socket` 即要求 `meta.destination = local_socket`，而 TURN 服务器实际把内层响应投递到 relayed 地址。调用方只有把 `meta.destination` 填成 `local_socket`（“伪造”一个与实际到达地址不符的值）才能让这条 `base` 比对通过；这等于绕过 §3.2 第 3 条。
- 入站检查的本地候选查找以 `meta.destination` 为键、由 `position()` 与 `candidate.address()` 比对（§3.2 第 4 条）；`destination` 只是查找键，代码不对它做独立的字段校验。`address` 仍是 relayed 地址，按实际到达地址填 `destination = relayed` 时查找正常；若为凑 `base` 比对而把 `destination` “伪造”成 `local_socket`，查找反而会落空并返回 `IceError::UnknownLocalCandidate`。consent 刷新同样要求 `pair.local().base() == meta.destination`（§3.2 补充），会因 `base = local_socket` 失配。

结论：`base = 本地 TURN socket 地址` 不是合法配置。它只能靠在喂入数据时把 `meta.destination` “伪造”成 `local_socket`（与实际到达地址不符）去凑 `base` 比对，属于自欺，不得使用（决策 §2.B 对同一反例的论证）。

### 3.4 反例 B：base 留空

`Candidate::new(Relay, ..., base = None)` 直接返回 `IceError::MissingBaseAddress`（`candidate.rs:172-181`），候选无法入表。没有 base 的 relay 候选在 `rtx-ice` 中不存在可用形态。

### 3.5 易错点：SDP 的 `raddr/rport` 不是 base

SDP 的 `raddr/rport` 是 Allocate 响应的 mapped address（RFC 8839 §5.1），即 TURN 服务器看到的调用方映射地址，用于诊断 / 展示；它**不是** base（决策 §2.B 末段、§4.3）。

- 本地 relay 候选：把 `raddr/rport` 当 `base` 会直接落入 §3.3 同类错误——`SendCheck.source` 与响应匹配所要求的 `meta.destination` 都偏离 relayed 地址，只能把 `meta.destination` “伪造”成该非 relayed 地址去凑 `base` 比对。
- 远端 relay 候选：`base` 不参与本实现的检查发送与响应匹配（发送用 `source = local.base()`，匹配用 `remote.address()` 与 `local.base()`），但它是 `Candidate` 的契约字段，foundation 由 `(type, transport, base)` 派生（`candidate.rs:233-241`、`:259-274`），`base()` 对调用方可见。填 mapped address 会让远端候选在语义与 foundation 上偏离 relay 候选的契约；决策 §2.B 明确禁止。

从信令构造远端 relay 候选时，`address` 与 `base` 都填对端的 relayed 传输地址，不要填 `raddr/rport`。

---

## 4. `SendCheck` 封装与 Data indication 解封装

树内只产出、只接收内层的 STUN 字节与事件；TURN 封装 / 解封装全部是调用方的职责。

### 4.1 出站：`Event::SendCheck`

`Event::SendCheck` 携带 `source`（= `pair.local().base()` = relayed 地址）、`destination`（= `pair.remote().address()` = 对端传输地址）、`pair` 索引、`transaction_id`、`nominated` 与已编码的内层 Binding request（`checklist.rs:104-121`、`:806-814`）。

流程：

1. 以 `source` 为键查“relayed 地址 → 分配”映射。
2. 把 `message[..message_len]` 作为 TURN 载荷：未绑通道用 Send indication（RFC 5766 §10.1，形成 Send indication，peer = `destination`）；已 ChannelBind 可用 ChannelData（§11）。
3. 从该分配对应的 TURN 客户端 socket 发往 TURN 服务器。

```text
on Event::SendCheck { source, destination, message }
    alloc = allocations_by_relayed[source]     # source == pair.local().base()
    if alloc is none: session_failure(...)     # 供给不完整，见 §6
    turn_send(alloc, peer = destination, payload = message)
```

### 4.2 响应：`Event::SendResponse`

入站检查会产出 `Event::SendResponse { destination, pair, ... }`（`checklist.rs:122-137`）。`destination` 是请求来源（对端），事件没有 `source` 字段；调用方必须用 `pair` 索引查 `pair(index)`（`checklist.rs:418-420`）拿到本地候选的 `base()`（= relayed 地址），据此找到分配并封装响应：

```text
on Event::SendResponse { destination, pair, message }
    local = checklist.pair(pair).local()
    alloc = allocations_by_relayed[local.base()]
    turn_send(alloc, peer = destination, payload = message)
```

不要把响应直接发往 `destination`：那会绕过 TURN，且源地址不再是 relayed 地址，对端与 TURN 服务器的匹配都会失败。

### 4.3 入站：Data indication / ChannelData 解封装

TURN 服务器把对端数据以 Data indication（RFC 5766 §10.4，接收 Data indication）或 ChannelData（§11）投递到 TURN 客户端的 socket。调用方解封装后：

1. 取内层载荷（应为 STUN 消息；非 STUN 会得到 `IceError::NotStunMessage`，`checklist.rs:487-490`）。
2. 取对端传输地址：Data indication 的 `XOR-PEER-ADDRESS`，或 ChannelData 通道绑定的对端地址。
3. 构造 `DatagramMeta` 并交给 checklist：

```text
meta.source      = 对端传输地址             # 不是 TURN 服务器地址
meta.destination = 该分配对应的 relayed 地址  # 不是本地 socket 地址
meta.now         = 当前时间
checklist.handle_input(Input::Datagram { meta, payload: 内层 STUN })
```

机制对照：

- 入站 Binding request 的本地候选查找用 `meta.destination`（`checklist.rs:541-544`）；填成本地 socket 地址会返回 `IceError::UnknownLocalCandidate`。
- Binding response 匹配要求 `pair.remote().address() == meta.source` 且 `pair.local().base() == meta.destination`（`checklist.rs:646`）；`source` 填成 TURN 服务器地址、或 `destination` 不填 relayed 地址，响应都会被静默忽略。
- consent indication 同样按 `source` / `destination` 匹配（`checklist.rs:688-700`），不匹配就不会刷新 consent 时间戳。

### 4.4 多分配与远端 relay

- 多个本地 relay 候选就是多个分配：一律以 relayed 地址为键保存映射，不要以本地 socket 或 TURN 服务器地址为键。
- 远端是 relay、本地不是 relay：`destination` 就是对端的 relayed 地址，是公网可达的中继地址，调用方可直接按 `destination` 发送，不经本地 TURN 封装（决策 §2.B）。
- 本地与远端都是 relay：双向都按 §4.1–§4.3 封装 / 解封装。

---

## 5. 刷新失败与会话失败处理

### 5.1 谁负责刷新

Refresh（RFC 5766 §7.1，发送 Refresh 请求）、权限续期（§8）、通道续期（§11）全部归调用方的 TURN 客户端；`rtx-ice` 没有参与其中的定时器、状态或 API。刷新节奏与重试策略不在本指南的契约内；本指南只规定失败表现与调用方处理边界。

### 5.2 失败表现

| 触发 | 树内表现 | 调用方动作 |
|---|---|---|
| `start` 前 Allocate 失败 | 无 relayed 地址，无影响 | 不入表；只用 host / srflx（§2.3） |
| 会话中 Refresh 失败 / 分配过期 | 经该分配发出的检查无响应：该 pair 按 `MAX_RETRANSMISSIONS`（7 次）重传后 `Failed`；全部 pair 失败 → `ChecklistFailed`（`lib.rs:129-135`、`checklist.rs:709-755`；`all_failed` → `fail()` → 推 `ChecklistFailed` 见 `checklist.rs:785-787`、`:875-882`） | 停止使用该分配；按会话级失败处理 |
| 已提名 relay pair 的分配丢失 | pair 不被清除；consent 无刷新，`is_consent_stale` 超时后返回 `true`（`checklist.rs:446-454`、`lib.rs:148-154`） | 停媒体；走信令重协商 / 新 ICE 会话；不要原地换候选 |
| 权限 / 通道失效但分配仍有效 | TURN 侧丢弃转发；检查无响应，表现同上 | 转发恢复仅当对应 pair 尚未 `Failed` 时成立：此时在 TURN 侧重新安装权限 / 通道即可恢复（relayed 地址未变，`rtx-ice` 无需动作）；已 `Failed` 的 pair 不会重启，仍按 §5.3 走会话级处理；分配已过期则按会话级处理 |
| 表满 | `CandidateTableFull` / `PairTableFull`，拒绝且不驱逐 | `start` 前预留名额（§2.2） |

### 5.3 会话级失败处理

API 无 remove，`start` 后不能补充候选，已 `Failed` 的 pair 不会重启。因此进行中会话的 relay 丢失只能会话级处理：

1. **重建会话。** 新建 `Checklist`，重新走信令；在新会话 `start` 前重新 Allocate 并供给候选（新的 relayed 地址只属于新会话）。
2. **回落 host / srflx。** 新会话可只带 host / srflx 候选，前提是这些 pair 在新会话条件下确实可连通；这不是自动降级，而是调用方的新会话决策。
3. **停媒体。** consent stale 后不应继续使用原 nominated pair；`rtx-ice` 不发 keepalive、不切换；consent 是否过期由调用方用 `is_consent_stale` 查询（`checklist.rs:446` 起），该查询本身不是自动检测与切换（`lib.rs:148-154`）。

**明确否定**：树内不会自动更换 relay 候选、不会自动重分配，也不会把失败 pair 重开到新 relay；这些都不在 `rtx-ice` 的职责内，调用方也不得依赖。

---

## 6. 检查清单（调用方自查表）

逐项可勾选；缺一项即视为供给未完成。

- [ ] `start` 前完成 Allocate，拿到 relayed 传输地址（失败则不入表，见 §2.3）。
- [ ] 本地 relay 候选 `address = base = relayed 传输地址`（§3.1）。
- [ ] 远端 relay 候选 `address = base = 对端 relayed 传输地址`；SDP `raddr/rport` 未用作 `base`（§3.5）。
- [ ] 全部 `add_local_candidate` / `add_remote_candidate` 在 `start` 前完成；接受 `start` 后返回 `AlreadyStarted`、无 remove API 的事实（§2.2）。
- [ ] 持有“relayed 地址 → 分配”映射；`Event::SendCheck.source` 能命中该映射并做 TURN 封装（§4.1）。
- [ ] `Event::SendResponse` 通过 `pair(index)` 找到本地 `base()` 后再封装，未直接发往 `destination`（§4.2）。
- [ ] 解封装后 `meta.destination = relayed 地址`、`meta.source = 对端传输地址`；入站检查与 consent 都按此规则喂入（§4.3）。
- [ ] 多个分配以 relayed 地址为键区分；本地非 relay、远端 relay 时按直发处理（§4.4）。
- [ ] TURN 侧权限 / 通道由调用方维护；未假设 `rtx-ice` 感知 CreatePermission / ChannelBind（§2.1、§5.1）。
- [ ] 刷新失败 / 分配过期按会话级处理：停媒体、重建会话或回落 host / srflx；未假设树内自动更换 relay 候选或自动重分配（§5.3）。
- [ ] 未假设树内认证 ICE 检查或 TURN 长期凭证（§1.2、`lib.rs:55-58`）。
- [ ] 候选 / 配对预算：relay 占用每侧 16 个候选与 64 个 pair 名额，`start` 前已预留（§2.2）。
