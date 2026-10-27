# R4-2：TURN 复用决策

| 项 | 内容 |
|---|---|
| 决策编号 | R4-2（P4 第二单；决策文档单） |
| 基线 | `main` @ `f6d0cc5`（R4-1 / PR #13 合并点） |
| 决策对象 | f6d0cc5 的 `rtx-ice` API（`Candidate` / `CandidateType` / `Checklist` / `Event`） |
| 交付形态 | 只新增本文档；不写代码、不改 API、不改常量、不改 CI、不改已有文档 |
| 结论 | 选项 B：STUN + 直连 + relay 透传；树内不做 TURN 客户端 |
| 依据 | RFC 8445、RFC 5389、RFC 5766、RFC 8839；`docs/m3-m4-gates.md`、`docs/m1-3-implementation-notes.md`、R4-1 源码；RTX-COMPLETION-PLAN.md P4/P6 节、PIPELINE.md §5 |

> 说明：RTX-COMPLETION-PLAN.md 与 PIPELINE.md 是协调者文档，不在本仓库内。本文只引用其节名与原文句子，不引用行号。RFC 行号不进入本文，统一使用节号。

---

## 1. 需求证据

### 1.1 已合入文档与代码的现状

- **门禁没有 TURN 必做项。** `docs/m3-m4-gates.md` 全文大小写不敏感检索 `turn` 只有 1 处命中：第 80 行 M3-Q5 的测试名 `m3_q5_idle_poll_returns_none` 中的子串（`returns` 含 `turn`），与 TURN 无关。M3/M4 门禁中没有“必须实现 TURN 客户端 / relay 分配”的条目。
- **TURN 客户端语义被明确留到后续里程碑。** `docs/m1-3-implementation-notes.md:96` 把“TURN 客户端语义（Allocate/ChannelData 生命周期）”列为“后续里程碑”；同表第 94 行把“长期密钥 MD5 派生 / `MessageIntegrity::new_long_term` 构造函数”列为未完成项，第 93 行把 RFC 5389 §10.2 的真实 HMAC-SHA1 向量列为未完成项。
- **R4-1 把收集与 TURN 划给了 R4-2。** `crates/rtx-ice/src/lib.rs:41-45` 明写：socket 候选收集、接口枚举、STUN 服务器发现不在 R4-1；TURN 分配/刷新/权限也不在；`CandidateType::Relay` 只是类型值，TURN 客户端由 R4-2 拥有。`crates/rtx-ice/src/lib.rs:189-194` 的“Split with R4-2”重复了同一划分，并说明 relay 类型存在的目的只是让 R4-2 能插入 relay 候选而不改 API。
- **计划原文只有一句话。** RTX-COMPLETION-PLAN.md P4 节对本单写的是：“R4-2 TURN 复用决策：先定子集（是否做完整 TURN，还是只做 STUN + 直连 + relay 透传），不要默认做全。”

### 1.2 消息层证据的边界（不得当作客户端）

`crates/rtx-stun/tests/turn_scenarios.rs` 在 f6d0cc5 有 **16** 个消息级场景测试（`STUN-TURN-001` … `STUN-TURN-016`，文件内 `#[test]` 计数为 16）：

- 001 分配成功响应、002 长期凭证两步对话、003 CreatePermission、004 ChannelBind、005 Send/Data indication、006 Refresh LIFETIME=0、007 437、008 438 stale nonce、009 441、010 完整认证栈、011 401 线上字节级、012 XOR-PEER-ADDRESS 掩码字节级、013 REQUESTED-TRANSPORT 非 UDP 编号、014 重试时 transaction id 语义、015 大 DATA indication、016 错误响应上的 SOFTWARE 属性。

这些测试验证的是 `rtx-stun` 对 TURN 相关属性与消息形状的编解码能力：

- 测试用的 `mock_mac` 是 XOR 假 MAC（`crates/rtx-stun/tests/common/mod.rs:109-119`），不是 HMAC-SHA1；
- 没有 socket、没有分配状态、没有刷新定时器、没有权限/通道生命周期、没有 ChannelData 帧（`docs/m1-3-implementation-notes.md:96` 明确说 `DATA`/`CHANNEL-NUMBER` 无专门 typed 模块）；
- 每个场景都是构造字节、解码、断言属性，没有与真实 TURN 服务器交互。

因此**不得**把这些场景说成“已有 TURN 客户端”或“可复用的现成实现”。它们只证明消息层可用，是选项 A 的原料，不是 A 的已完成部分。

### 1.3 什么部署必须走 relay

relay 的必要条件不是“用了 WebRTC”，而是 **host 与 srflx 候选的所有组合都无法建立连通性**。具体形态：

1. 双方都在端点相关（endpoint-dependent）/对称 NAT 之后，且端口映射不可预测；双方的 srflx 地址互不可达，host 地址也不可达。
2. 网络策略只允许出站 UDP 到少数已知中继（企业防火墙、运营商策略），直连被阻断。
3. 需要隐藏自身 IP（隐私部署），只暴露中继地址。

RFC 8445 本身把 relay 定义为可选项：§5.1.1.2 说 agent SHOULD gather server-reflexive 和 relayed candidates，但“某些网络不需要 STUN/TURN，TURN 可能昂贵，部分部署可以选择不用”；建议实现后用配置关闭，条件变化时再启用。§5.1.2.2 把 relay 的 type preference 定为 0（最低），即只在最后兜底。

### 1.4 什么部署不需要 relay

- 实验室 / 局域网 / 已知可直连的部署：host 候选（必要时加 srflx）即可完成检查与提名。
- P6 浏览器互通（计划 R6-3）走 WebTransport 路径：QUIC/H3 的客户端-服务器模型，不跑 ICE，不存在候选配对，也就不需要 TURN。`ARCHITECTURE.md` §15（364-368 行）与 M3 节（505-510 行）把浏览器互通定义为 QUIC/WebTransport 路线，而不是 WebRTC ICE 路线。补充澄清：`ARCHITECTURE.md` 的 M2 节（496-503 行）另含 ICE 子集/全 ICE 取舍与浏览器互通的出口判据，那是 M2 阶段的路线措辞；本决策对 P6 走 WebTransport 的路线判断不变。

### 1.5 需求判定

**目前没有任何一条已合入门禁强制要求 TURN**，也没有任何已合入文档把“公网 P2P、双方 NAT 不可穿透”登记为当前交付目标。因此：

- 不能用“WebRTC 就必须有 TURN”或“将来可能需要”作为选项 A 的证据；
- 但 R4-1 已经把 `Relay` 放进 `CandidateType` 并允许它经 `add_*_candidate` 入表，本单必须给出它的完整使用契约，不能留成无契约的悬空值。

这个判定直接支撑第 3 节选 B：relay 是“调用方有 TURN 基础设施时应当可用”的能力，不是门禁强制的交付项。

---

## 2. 选项比较

三个选项都以“`rtx-ice` API 不变”为目标；差别在树内新增多少生产代码、依赖谁、P6 怎么接线。

### A. 完整 TURN 客户端进树

**范围**：Allocate / Refresh / CreatePermission / ChannelBind / Send-Data（含 ChannelData 帧）全套；长期凭证认证（401/438 重试、realm/nonce 状态）；分配生命周期与刷新；权限与通道过期管理。

**依赖**：

- **认证缺口是硬前置。** `crates/rtx-ice/src/lib.rs:51-54` 明写 `USERNAME` 与 `MESSAGE-INTEGRITY` 校验不在 R4-1，“There is no shared credential context in this order... **This crate does not claim an authenticated ICE agent.**”
- `rtx-stun` 只有 `MessageIntegrity::new_raw`（`crates/rtx-stun/src/integrity.rs:74`）与 `check`（`:123`），没有 `new_long_term`；TURN 场景测试用 XOR 假 MAC（`crates/rtx-stun/tests/common/mod.rs:109`），不是真实 HMAC-SHA1。
- `rtx-crypto` 的 `HashAlgorithm` 只有 `Sha1` / `Sha256` / `Sha384`，没有 MD5（`crates/rtx-crypto/src/lib.rs:15-19`）；而 RFC 5389 §15.4 的长期凭证密钥需要 `MD5(username ":" realm ":" password)`。`docs/m1-3-implementation-notes.md:93-94` 把真实 HMAC-SHA1 向量与 MD5 派生都列为遗留项。
- 因此完整 TURN 客户端之前必须先有一个“认证/凭证故事”决策：凭证从哪来（信令？配置？）、realm/nonce 如何存、MD5 是否实现、是否改用其他长期凭证方案。这个决策尚未存在，A 不能先于它开工。
- 还要依赖 TURN 服务器基础设施（分配、中继）与公网部署证据；当前两者都没有登记。

**footprint**：

- 现有 `rtx-ice` 是 no_std、无 alloc、固定数组：候选表 `[Option<Candidate>; MAX_ICE_CANDIDATES]` × 2（`crates/rtx-ice/src/checklist.rs:942`），pair 表 `[Option<CandidatePair>; MAX_ICE_PAIRS]` + `[u16; MAX_ICE_PAIRS]`（`:985-986`），事件队列 `[Option<Event>; MAX_EVENTS]`（`:1158`），事件内消息缓冲 `MAX_STUN_MESSAGE_SIZE = 64`（`:49`）。
- TURN 客户端要新增：每个分配的 relayed 地址/生命周期/刷新 deadline、realm 与 nonce（RFC 5389 §15.7 / §15.8 规定两者均小于 128 字符）、长期凭证密钥、权限表（按 peer IP，RFC 5766 §8 权限寿命 5 分钟）、通道绑定表（通道号 0x4000–0x7FFF，RFC 5766 §11 寿命 10 分钟）、事务状态。Send/Data indication 与 ChannelData 要携带媒体，64 字节的事件缓冲不够，需要 MTU 级静态缓冲或新的借用式事件形状。这些都要在 no_std 下用固定数组定界，等于给 Tier B 增加一份新的静态预算，M4 需要重新定界。
- 定时器模型冲突：R4-1 明确“at most one transaction is outstanding, which keeps the Tier B timer state to one deadline”（`lib.rs:120-122`）。TURN 分配刷新（RFC 5766 §5 默认分配寿命 600 秒，§7.2 规定 Refresh 处理）与事务重传是另一套 deadline；若并入 `Checklist`，会破坏单 deadline 模型；若独立成机器，运行时必须同时驱动两个 sans-IO 机器。

**对 `rtx-ice` API 的影响**：

- 若 TURN 客户端作为独立 crate（例如 `rtx-turn`）且分配在 `Checklist::start` 之前完成，`rtx-ice` API 可以零改动：relay 候选仍走 `add_*_candidate`。
- 但“完整生命周期”包含刷新失败后的重新分配/换 relayed 地址；`add_local_candidate` 在 start 后返回 `AlreadyStarted`（`checklist.rs:310-321`），且没有 remove API。中途更换 relay 候选必须新增 API（remove/replace，或允许 start 后补充）。因此 A 的“零 API 影响”只在“分配只发生一次且必须先于 start”的子集成立，不是完整 TURN 客户端的自然结果。这是 A 的额外成本。

**对 P6 接线的影响**：P6 运行时需要同时驱动 TURN 与 ICE 两个 sans-IO 机器（或一个多定时器机器），在同一 UDP socket 上解复用 STUN / TURN / ChannelData / DTLS / SRTP；ChannelData 要直接进入媒体路径。接线复杂度明显高于 B。

**需要新增的后续单（具名，不实现）**：

1. `AUTH-1`（认证/凭证故事决策单，暂定名）——必须先于 TURN 客户端；
2. `R4-2-A1` TURN sans-IO 客户端单（分配/刷新/权限/通道/凭证状态）；
3. `R4-2-A2` socket 复用与解复用接线单；
4. `R4-2-A3` TURN 互通与一致性测试单。

### B. STUN + 直连 + relay 透传

**范围**：树内不做 TURN 客户端。relay 候选由调用方/信令侧提供：分配、刷新、认证、权限、通道绑定都在调用方；`rtx-ice` 只负责 relay 候选的入表、配对、检查、提名与 consent 时间戳——这些能力 R4-1 已经具备。

**relay 候选的 base 取值（本决策钉住）**：

RFC 8445 定义节写明：“For relayed candidates, the base is the same as the relayed candidate (i.e., the transport address used by the TURN server to send from)”；§5.1.1.2 再次写明：“The base of a relayed candidate is that candidate itself.” 因此：

```text
Candidate::new(Relay, COMPONENT_RTP, Transport::Udp,
               relayed_transport_address,
               Some(relayed_transport_address))   // base == address
```

即 `address` 与 `base` 都填 relayed 传输地址，两者相等。论证不是“代码允许这么填”，而是以下四处必须同时成立：

1. `Candidate::base` 的文档语义是“检查发送时所使用的本地基地址”（`crates/rtx-ice/src/candidate.rs:129-135`）。
2. `send_check` 把 `Event::SendCheck.source` 设为 `pair.local().base()`（`checklist.rs:807`）；按 RFC 8445 §7.2.4，检查从 base 发出。relay 本地候选的 base 是 relayed 地址，所以事件里的 `source` 就是 relayed 地址，调用方据此找到对应分配并做 TURN 封装。
3. 成功响应匹配要求 `pair.local().base() == meta.destination`（`checklist.rs:646`）。TURN 服务器把内层响应投递到 relayed 地址，调用方解封装后以 `destination = relayed 地址` 交给 checklist，正好匹配。
4. 入站检查的本地候选查找使用 `meta.destination`（`checklist.rs:543`），同样要求调用方给出 `destination = relayed 地址`。

如果改为“base 填本地 TURN socket 地址”，则 (3) 会要求 `meta.destination = 本地 socket`，与 TURN 实际投递地址（relayed）冲突，调用方只能伪造 `meta.destination`；同时 (2) 的 `source` 也不再是 RFC 8445 定义的 base。因此 base 必须等于 relayed 地址，不能是本地 TURN socket 地址。

另外：SDP 的 `raddr/rport` 是 Allocate 响应的 mapped address（RFC 8839 §5.1），用于诊断，**不是** base；从信令构造远端 relay 候选时，不能把 `raddr/rport` 填进 `Candidate::base`，仍应填 relayed 地址本身。`Candidate::new` 对 Relay 只强制 `Some`，不校验它与 `address` 的关系（`candidate.rs:172-181`）；本决策用契约收窄，代码不动。

**调用方 TURN 职责与事件映射**：

```text
调用方 TURN 客户端（树外）                      rtx-ice（树内）
  Allocate / Refresh / 长期凭证认证
  -> relayed transport address
  Candidate::new(Relay, addr, Some(addr))  -->  add_local_candidate
                                               generate_pairs / start
  Event::SendCheck{source=relayed addr, destination=peer}
  -> 调用方按 source 找到分配，封装 Send indication / ChannelData
  TURN Data indication / ChannelData        -->  解出内层 Binding，
     meta{source=peer, destination=relayed addr} 交给 checklist
  Event::SendResponse{destination=peer}
  -> 调用方按 pair 索引（pair(index)，checklist.rs:418）找到分配并封装
```

- 本地 relay 候选：所有发给对端的检查/响应都要经该分配转发；调用方以 `source`（relayed 地址）为键保存“relayed 地址 → 分配/控制 socket/TURN 服务器”的映射。
- 远端 relay 候选：对端 relayed 地址是公网可达的中继地址，本地直接按 `destination` 发送即可；若本地也是 relay，则按上面的封装路径走。
- 权限/通道：由调用方在 TURN 侧维护；`rtx-ice` 不感知 CreatePermission/ChannelBind。

**生命周期归属（谁负责刷新失败后撤表）**：

- 刷新、权限续期、通道续期全部归调用方。
- 当前 API 在 `start` 之后不接受新增候选，也没有 remove API（`checklist.rs:310-335`）。因此“撤表”在树内不可执行：**调用方必须在 `start` 前只加入已经分配成功的 relay 候选**；分配过期后，候选和 pair 留在有界表内，靠检查失败/consent 过期自然失效。
- 中途重新分配（新的 relayed 地址）在 B 下不支持；需要重新走信令/新的 ICE 会话。这是 B 的明确边界，不是隐含行为。

**失败语义（分配丢了以后检查表如何表现）**：

| 阶段 | 现象 | `rtx-ice` 行为 | 调用方动作 |
|---|---|---|---|
| `start` 前分配失败 | 没有 relayed 地址 | 无影响 | 不加入 relay 候选；只加 host/srflx |
| `start` 后分配过期 | 发往/来自 relayed 地址的检查无响应 | 该 pair 按 7 次重传后 `Failed`；其他 pair 继续；全部失败 → `ChecklistFailed` | 停止刷新；按会话失败处理 |
| 已提名的 relay pair 失效 | 无响应 / consent 超时 | 提名不变；`is_consent_stale` 在超时后返回 true（`lib.rs:143-150`） | 停媒体，走信令重协商/新 ICE 会话；不要原地换候选 |
| 表满 | `CandidateTableFull` / `PairTableFull` | 拒绝、不驱逐 | 预分配候选预算；relay 占用 16/64 名额中的一部分 |

**footprint**：树内零新增生产代码、零新增状态、零新增定时器；只增加本文档。relay 候选仍占用既有 `MAX_ICE_CANDIDATES` / `MAX_ICE_PAIRS` 名额。TURN 客户端的内存由调用方承担。

**对 `rtx-ice` API 的影响**：**零**。论证：

- `CandidateType::Relay` 与 `Candidate` 的 `base` 字段已存在（`candidate.rs:95-99`、`:139-147`）；
- `add_local_candidate` / `add_remote_candidate` 接受任意类型的 `Candidate`（`checklist.rs:317-335`）；
- 配对、检查、提名、consent 全部只读 `Candidate` 的 type/address/base/priority，没有按类型分支（`checklist.rs:791-827`、`:543-551`、`:646`）；
- 事件已经携带 `source`（base）与 `destination`（remote address），足以让调用方完成 TURN 封装/解封装；`pair(index)` 可把 `SendResponse` 映射回本地候选。
- 因此不需要新增字段、事件变体或输入类型；唯一新增的是“`source` 为 relayed 地址时按 TURN 路径发送”的解释，这个解释由调用方实现，不需要 API 变化。

**对 P6 接线的影响**：若 P6 走 WebTransport 路径（R6-3），不接 relay，B 不产生接线工作；若 P6 选择 ICE/WebRTC 且需要 relay，P6 单必须包含调用方/运行时的 TURN 客户端与 socket 解复用，`rtx-ice` 保持零改动。

**需要新增的后续单（具名，不实现）**：

1. `R4-2-F1` 文档措辞跟进单（只改 `rtx-ice` 的 doc comment，把 R4-1 的 “Split with R4-2” 与责任表措辞收敛到本决策）；
2. `R4-2-F2` relay 透传一致性测试单（test-only）；
3. `R4-2-F3` 调用方 relay 供给指南/示例单（文档/示例，树内不新增 TURN 客户端）。

### C. 整体推迟 TURN

**范围**：保留 `CandidateType::Relay` 类型值；不写分配故事、不定义透传契约。调用方拿到 relay 需求时，明确回答“不支持”，而不是含糊其辞。

**调用方处理**：能力查询返回“不支持”；不得把 relay 候选经 `add_*_candidate` 塞进表里（否则检查会按直连语义发往 relayed 地址，本地 relay 路径必然失败，且没有文档化的失败语义）。这是明确的产品边界，不是静默忽略。

**footprint**：零。

**对 `rtx-ice` API 的影响**：零。

**对 P6 接线的影响**：没有 relay 路径；若 P6 的部署需要 relay，只能在信令层判定失败，或重新开决策。

**需要新增的后续单**：无。将来出现真实部署证据时，需要重新开一个决策单，不能在 C 之上直接派实现单。

**相对 B 的缺点**：C 与 B 的树内成本相同（都是零代码），但 C 让 R4-1 预留的 relay 类型变成无契约的死值（`candidate.rs:95-99`、`lib.rs:189-194` 的存在目的落空），且对有 relay 需求的调用方只给出“不支持”，没有可用路径。B 在同一成本下给出了可执行的契约。

### 汇总比较

| 维度 | A. 完整 TURN 客户端 | B. relay 透传 | C. 整体推迟 |
|---|---|---|---|
| 树内新增生产代码 | 高（客户端 + ChannelData + 凭证状态） | 无（只加文档） | 无 |
| 认证依赖 | 硬依赖未决策的认证故事 + MD5/HMAC-SHA1 | 无（认证在调用方；树内缺口不变） | 无 |
| 定时器/状态模型 | 新增刷新 deadline，冲突 R4-1 单 deadline | 无 | 无 |
| `rtx-ice` API | 条件零影响（中途换候选需新 API） | 零影响 | 零影响 |
| P6 接线 | 最重（双机器 + 解复用） | 中等（仅在有 relay 部署时由调用方提供） | 无 relay |
| 有 relay 部署时可用 | 是 | 是（调用方自备 TURN） | 否（明确不支持） |
| 与计划“不要默认做全” | 冲突 | 一致 | 一致 |
| 与 R4-1 relay 类型的存在目的 | 一致 | 一致 | 冲突（类型无契约） |

---

## 3. 推荐结论

**选 B：STUN + 直连 + relay 透传。**

理由：

1. **需求证据不支持 A。** 第 1 节已核实：没有已合入门禁强制 TURN，也没有已登记的公网 P2P 部署目标；唯一与浏览器相关的 P6 互通走 WebTransport，不依赖 ICE/relay。选项 A 的收益（树内自带 TURN 客户端）没有对应的需求证据，违反计划“不要默认做全”。
2. **A 的依赖链尚未就绪。** A 必须先解决一个尚未决策的认证故事（`USERNAME`/`MESSAGE-INTEGRITY`、长期凭证 MD5、realm/nonce），而 R4-1 明确不声称 authenticated ICE agent（`lib.rs:51-54`），`rtx-stun` 也没有长期凭证构造函数。在认证故事缺位时开工 A 会违反 PIPELINE.md §5“没有设计结论就不派实现单”。
3. **A 的 footprint 与定时器成本是真实的。** 新增分配/权限/通道状态与 MTU 级缓冲；若并入 `Checklist` 会破坏“单事务 / 单 deadline”模型（`lib.rs:120-122`）；若独立成 crate，P6 仍要解复用并驱动两个机器。A 的“API 零影响”也不是无条件成立——中途更换 relay 候选需要新 API。
4. **B 在零成本下给出完整契约。** relay 类型、base 字段、有界表、配对/检查/提名都已存在；本决策只钉住 base = relayed 地址、调用方职责与失败语义。C 与 B 的树内成本相同，却把 R4-1 预留的 relay 类型变成无契约的死值，并让有 relay 需求的调用方得不到明确行为；B 严格优于 C。
5. **B 不掩盖认证缺口。** 树内仍不认证 ICE 检查，TURN 的长期凭证认证由调用方负责；本文不声称任何 TURN 功能已实现。

**执行摘要（后续单照此执行，不需再开决策会）**：

> 树内不做 TURN 客户端；socket/STUN 收集与 TURN 分配/刷新/认证/权限/通道全部归调用方；本地 relay 候选以 relayed 传输地址同时作为 `address` 与 `base`，经 `add_local_candidate` 入表（远端 relay 候选同样 address = base，经 `add_remote_candidate`）；`rtx-ice` 只做入表、配对、检查、提名与 consent 时间戳；分配丢失表现为相关 pair 检查失败 / consent stale，调用方负责会话级失败处理。

与结论绑定的边界：本单不写 TURN 客户端、不实现 `USERNAME`/`MESSAGE-INTEGRITY` 认证、不改 `rtx-ice` API、不做 SDP、不做 P5 SCTP 决策、不做 P6 QUIC/WebTransport 决策。

---

## 4. 收集归属决策

**结论：host 枚举、srflx 的 STUN 查询、relay 分配全部归调用方；树内不新增任何收集代码。**

理由：

- `crates/rtx-ice/src/lib.rs:6-8` 定义该 crate 不持有 socket、不读时钟、不分配、不阻塞；收集需要接口枚举、socket 绑定、STUN 事务与重传定时器（RFC 8445 §5.1.1.2 的 Ta 规则），这些都不属于该 crate 的模型。
- 收集天然平台相关：`docs/m3-m4-gates.md:43` 把 `rtx-linux`、`rtx-embassy`、`rtx-smoltcp` 列为规划中的平台 crate；把接口枚举塞进 `rtx-ice` 会让 no_std 核心绑定平台细节。
- 归调用方可以保持 R4-1 的边界：“tables filled by the caller”（`lib.rs:189-194`），树内只通过填表 API 接收候选。

### 4.1 host 候选

调用方枚举接口并绑定 UDP socket；构造 `Candidate::new(Host, COMPONENT_RTP, Transport::Udp, bound_addr, None)`（base 可省略或等于 address，`candidate.rs:172-177`），经 `add_local_candidate` 入表。

### 4.2 srflx 候选

调用方配置/发现 STUN 服务器（RFC 8445 §5.1.1.2 建议用 DNS SRV 发现；发现方式由调用方决定），从某个 host 候选的 socket 发 Binding 请求，并自行负责重传（RFC 5389 §7.2.1）。成功后：

- `address` = XOR-MAPPED-ADDRESS；
- `base` = 发出该 Binding 请求的本地 host 候选地址（RFC 8445 §5.1.1.2：“The base of the server-reflexive candidate is the host candidate from which the ... Binding request was sent.”）；
- 构造 `Candidate::new(ServerReflexive, ..., Some(host_addr))`，经 `add_local_candidate` 入表。

查询失败就不加该候选；这是调用方的失败处理，不是 ICE 错误。

### 4.3 结果以什么形式入表、在什么时机入表

- 本地候选：`Candidate` 值经 `add_local_candidate`；远端候选：信令得到的 `Candidate` 值经 `add_remote_candidate`。
- 都必须在 `generate_pairs` / `start` 之前完成；start 后 `add_*` 返回 `AlreadyStarted`（`checklist.rs:310-335`）。relay 候选同理，所以分配必须在 start 前完成。
- 从 SDP/signalling 构造远端 relay 候选时，`address` 与 `base` 都填 relayed 传输地址；SDP 的 `raddr/rport` 是 Allocate 响应的 mapped address（RFC 8839 §5.1），不是 base，不能用来填 `base`。

### 4.4 调用方责任表（与 R4-1 责任表衔接）

| 责任 | 归属 | 说明 |
|---|---|---|
| 枚举接口、绑定 socket | 调用方 | 平台相关；`rtx-ice` 无 socket |
| STUN 服务器配置/发现、Binding 查询与重传 | 调用方 | 结果以 srflx `Candidate` 入表 |
| 构造 host/srflx/relay `Candidate` 并填 base | 调用方 | 规则见 4.1、4.2 与 2.B |
| `start` 前调用 `add_local_candidate` / `add_remote_candidate` | 调用方 | start 后拒绝（`AlreadyStarted`） |
| TURN Allocate / Refresh / 权限 / ChannelBind / 长期凭证认证 | 调用方 | 树内无 TURN 客户端 |
| 本地 relay 候选的 TURN 封装/解封装 | 调用方 | 见 2.B 的事件映射 |
| 分配失败后的撤表/更换 | **不支持** | API 无 remove；只能 start 前预置，或会话级重建 |
| ICE 检查的 `USERNAME` / `MESSAGE-INTEGRITY` | 无人（R4-1 明确缺口） | 本决策不改变 |

与 `crates/rtx-ice/src/lib.rs:175-187` 的责任表不矛盾：该表已把“获取本地/远端候选（socket、STUN、TURN、信令）”的 owner 写成“caller”（`lib.rs:179`）。本决策把该行后半句 “R4-2 adds gathering” 解析为“R4-2 定义收集契约，执行归调用方”，而不是“R4-2 在树内实现收集”。该行措辞与 `lib.rs:189-194` 已过时，其更新由第 6 节的 `R4-2-F1` 单处理；本单按验收不改 `lib.rs`。

---

## 5. 一致性声明

逐条核对 f6d0cc5，本决策不改变以下任何一项：

1. **relay 类型偏好 0 不变。** `CandidateType::type_preference` 中 `Relay => 0`（`crates/rtx-ice/src/candidate.rs:109-116`），与 RFC 8445 §5.1.2.2 及 `lib.rs:71-73` 一致；本决策不引入新的 type preference，也不改优先级公式。
2. **pair 优先级公式不变。** `pair_priority` 仍是 RFC 8445 §6.1.2.3 的 `2^32 * MIN + 2 * MAX + (G > D)`（`crates/rtx-ice/src/pair.rs:100-109`；`lib.rs:85-93`）。relay 候选只通过自己的 priority 字段参与，公式不变。
3. **`MAX_ICE_CANDIDATES` / `MAX_ICE_PAIRS` 不变。** 仍是每侧 16 个候选、64 个 pair（`crates/rtx-ice/src/checklist.rs:28`、`:39`；`lib.rs:99-100`）；relay 候选照常占用名额，本决策不扩容、不驱逐。
4. **常规提名、重传、consent 语义不变。** 常规提名仍是 controlling 侧对 `Succeeded` pair 发 `USE-CANDIDATE`，controlled 侧只接受 `Succeeded` pair（`lib.rs:137-141`）；`INITIAL_RTO = 500 ms`、`MAX_RTO = 8 s`、`MAX_RETRANSMISSIONS = 7` 不变（`checklist.rs:59`、`:69`、`:78`；`lib.rs:125-131`）；consent 时间戳语义不变（`lib.rs:143-150`；`Checklist::is_consent_stale`）。relay 路径只复用这些机制，不新增提名规则或定时器。
5. **`Candidate::new` 的 base 规则不变。** 代码仍只强制“非 host 必须有 base”（Relay 缺 base 返回 `IceError::MissingBaseAddress`，`candidate.rs:178-181`）；本单不修改该校验，只钉住取值语义：Relay 的 base 必须等于 relayed 传输地址（即与 `address` 相同），依据 RFC 8445 定义节（base for relayed = the relayed candidate）与 §5.1.1.2。
6. **API、事件与其它常量不变。** 不新增 `Event` / `Input` 变体；`MAX_EVENTS = 8`、`MAX_STUN_MESSAGE_SIZE = 64`、no_std / 无 alloc 均不变（`checklist.rs:42`、`:49`；`lib.rs:1`）；`add_local_candidate` / `add_remote_candidate` 的签名与错误契约不变；本单 PR 不触碰 `crates/**`。

---

## 6. 后续单清单

按推荐结论 B，后续单如下（本单只列名与前置条件，不实现）：

| 单号（暂定） | 类型 | 内容 | 前置条件 |
|---|---|---|---|
| `R4-2-F1` | 文档措辞（只改 `rtx-ice` doc comment） | 把 `lib.rs:189-194` “Split with R4-2” 与责任表 `lib.rs:179` 的 “R4-2 adds gathering” 收敛到本决策的落点（调用方执行、树内无收集/TURN）；不改 API、不改行为 | 本 PR merged |
| `R4-2-F2` | 测试单（test-only） | relay 透传一致性测试：构造 `address = base = relayed` 的本地/远端候选 → 入表 → 配对 → 检查/提名；断言无需新 API；不实现 TURN | 本 PR merged |
| `R4-2-F3` | 文档/示例单 | 调用方 relay 供给指南：外部 TURN 分配、base 填法、`SendCheck` 封装、Data indication 解封装、刷新失败与会话失败处理；示例可落在平台 crate 或 testkit，但树内不新增 TURN 客户端 | 本 PR merged；可与 F1 并行 |
| `R4-2-F4`（条件触发，未排期） | 决策/实现评估 | 完整 TURN 客户端评估，仅在出现真实部署证据时立项（门禁新增 TURN 必做项，或归档的部署报告）；若立项，先拆 `AUTH-1`，再 `A1/A2/A3` | `AUTH-1`（认证/凭证故事决策单，暂定名）先 merged；部署证据先入档 |

**本单之后 P4 是否还有未决项**：

按 RTX-COMPLETION-PLAN.md P4 节现有条目与派单前提，P4 的具名决策项为 R4-1（已合 f6d0cc5）与本单 R4-2。本单合并后，这两个决策项均已关闭，P4 不再因 TURN 保留未决项；计划若在 P4 节另有条目，以计划原文为准，本单不凭空假定。`R4-2-F1` / `F2` / `F3` 是 P4 之后的文档/测试/示例跟进，不是新的 P4 决策；`R4-2-F4` 仅在证据出现时另行开单。

**P6 接线时 relay 部分怎么办**：

- 若 P6 走 WebTransport 路径（R6-3），不接 relay，本决策不产生接线工作；
- 若 P6 选择 ICE/WebRTC 且需要 relay，按 B 的契约由调用方/运行时提供 TURN 客户端，`rtx-ice` 保持零改动；不得假设树内有 TURN 客户端；
- P5 SCTP 决策与 P6 QUIC/WebTransport 决策不在本单范围。
