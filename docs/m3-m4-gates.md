# M3 / M4 可判定门禁（rtx-rs）

| 项 | 内容 |
|---|---|
| 文档类型 | 门禁清单：只定义“什么算通过”，不含实现 |
| 里程碑 | M3（QUIC/WebTransport Linux 路径）、M4（嵌入式 profile） |
| 权威依据 | `ARCHITECTURE.md` §3、§4、§5、§7、§8、§11、§12、§13、§14、§15、§16、§17、§18、§19、§20；`DEPENDENCY_AUDIT.md` §1、§5、§9、§11 |
| 引用基线 | `main` @ `caab165a1273a19b63f7506c4a2dacfd2dd7b9b7`（2026-10-26 核对） |
| 用途 | P6（M3）/ P8（M4）任务书按条目 ID 引用；里程碑验收 PR 逐条填写证据 |
| 本单边界 | 仅新增本文件；不改代码、不改 `ARCHITECTURE.md`、不合并 |
| 当前状态 | M3/M4 均未开工；下表复选框全部为未满足 |

`ARCHITECTURE.md` §20 对 M3/M4 只列出了工作项，没有逐项出口标准。本文件把 §14、§15、§16、§19、§20 展开成可逐项打勾的清单。凡是本文自行设定的阈值、流程或路径，均在行内标注“本文件”，不冒充 ARCH 原文。

---

## 0. 判定规则

### 0.1 证据的四种合法形式

每一项的“通过证据”只能是以下四类之一，且必须绑定被测 commit：

| 类型 | 形式 | 复核方式 |
|---|---|---|
| 命令 | 命令 + 退出码 0 + CI 日志链接 | 在干净 checkout 中重跑同一命令 |
| 测试 | 仓库文件路径 + 测试函数名 | `cargo test` 能按名定位并通过 |
| 记录 | 归档报告（互通/基准/内存），含 commit、日期、环境、原始日志路径 | 按报告中的脚本与原始日志复现 |
| 评审 | 仅用于“没有暴露某 API / 没有实现某功能”这类否定性判定 | PR 评审链接 + 被评审的 diff |

以下不算证据：口头说明、聊天记录、未提交的本地结果、没有原始日志的截图、`#[ignore]` 的测试、只跑过一次且无法复现的手工操作。

### 0.2 通过规则

1. 一个 Gate 组的全部条目为 `[x]` 才算该组通过。
2. `N/A` 只允许出现在本文明确标注“条件适用”的条目（Firefox、目标不具备某硬件等）；`N/A` 必须给出依据文件或版本证据，不能空白。
3. 未通过项若不影响 M3/M4 出口，必须按 §4 格式登记为 GAP；未登记即视为门禁失败。
4. 存在阻塞性 GAP 时，整组失败；不允许用“基本通过”“已知问题”代替 PASS/FAIL。
5. 本文的复选框只能由里程碑验收 PR 勾选；实现 PR 不勾选。

### 0.3 引用约定

- “ARCH §x”指 `ARCHITECTURE.md` 的章节号。本文不引用 ARCH 行号，避免编辑后漂移。
- crate 名一律使用 ARCH §5 的规划名：`rtx-core`、`rtx-buffer`、`rtx-wire`、`rtx-crypto`、`rtx-stun`、`rtx-ice`、`rtx-rtp`、`rtx-rtcp`、`rtx-srtp`、`rtx-dtls`、`rtx-sctp`、`rtx-webrtc`、`rtx-quic`、`rtx-h3`、`rtx-webtransport`、`rtx-media`、`rtx-linux`、`rtx-embassy`、`rtx-smoltcp`、`rtx-testkit`。
- 本文出现的 `crates/...`、`interop/...`、`measurements/...`、`benchmarks/...`、`firmware/...`、`scripts/...` 是 M3/M4 需要产出的证据位置；本单不创建它们。
- 条目 ID 稳定，不随文档重排而改变；新增条目只能追加新 ID。

### 0.4 两种“通过”不能混用

- **功能通过**：某场景能跑通。
- **门禁通过**：该条目的证据齐全、可复现、且没有未登记缺口。

“功能通过”不等于“门禁通过”。例如 Chrome 能连上但 DATAGRAM 丢包未记录，对应条目仍未通过。

---

## 1. M3 — QUIC / WebTransport Linux 路径

ARCH §20 M3 的工作项是：`quinn-proto` backend facade；minimal H3/WebTransport handshake；browser DATAGRAM and stream interoperability；allocation and batching benchmarks。以下四组分别展开。

### 1.0 M3-0 入口条件

| 完成 | ID | 要求 | 通过证据 |
|---|---|---|---|
| [ ] | M3-0-1 | `crates/rtx-quic` 存在并被 workspace 收录；`quinn-proto` 版本在 `Cargo.lock` 固定，且与 DEPENDENCY_AUDIT §1 审计基线 `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` 的差异有书面记录 | `cargo tree -p rtx-quic -i quinn-proto` 输出归档到 `measurements/m3/deps/quinn-tree.txt`；`Cargo.lock` diff 评审记录 |
| [ ] | M3-0-2 | `rtx-quic` 公共 API 不依赖 Tokio（ARCH §7：协议引擎必须可在无 socket、无 task 的情况下驱动） | `cargo tree -p rtx-quic -e normal` 输出中无 `tokio`；输出归档到 `measurements/m3/deps/normal-tree.txt` |
| [ ] | M3-0-3 | 不把 `quinn-proto` 类型直接暴露到 facade 公共 API（ARCH §14：Do not mirror the entire Quinn public API） | `crates/rtx-quic/src/lib.rs` 的 `# 公共外观` 清单；`cargo doc -p rtx-quic` 链接；PR 评审记录确认公开签名中没有 `quinn_proto::{Endpoint, Connection, Event, Transmit}` |
| [ ] | M3-0-4 | M3 测试可在无真实 socket、无 sleep 的条件下运行（ARCH §18：Deterministic protocol tests） | `grep -R "thread::sleep" crates/rtx-quic/tests` 无匹配；CI 日志中 `cargo test -p rtx-quic --all-features` 通过 |

### 1.1 M3-Q：`quinn-proto` 窄外观接口清单

对齐 ARCH §14 Linux backend 的 8 项能力。每项既要证明“有”，也要证明“没有把 Quinn 整体搬出来”。

| 完成 | ID | ARCH §14 能力 | 规范操作名（facade 文档必须使用同名或给出映射） | 外观最小契约 | 通过证据（命令 / 文件 / 测试名） |
|---|---|---|---|---|---|
| [ ] | M3-Q0 | 不镜像整个 Quinn 公共 API | — | 公共外观只包含 Q1–Q8 所需操作；每个公开项都能在 `# 公共外观` 表中找到唯一消费者；不提供通用 passthrough | `crates/rtx-quic/tests/api_surface.rs` 编译通过且不 `use quinn_proto`；`cargo doc -p rtx-quic` 页面链接；PR 评审记录 |
| [ ] | M3-Q1 | endpoint/connection creation | `endpoint_new`、`endpoint_connect`、`endpoint_accept` | 可创建 client/server endpoint；client 发起连接并得到连接句柄；server 收到 incoming 事件并可 accept/refuse；endpoint 不拥有 socket，调用方负责喂入/取出 datagram；配置至少覆盖 ALPN、transport parameters、证书/私钥或 crypto provider | `cargo test -p rtx-quic --test facade_lifecycle`；`m3_q1_client_server_handshake_completes`、`m3_q1_server_accepts_and_refuses_incoming` 通过 |
| [ ] | M3-Q2 | handshake events | `poll_event`（握手子集） | 至少产生 `HandshakeComplete`（含协商 ALPN、peer transport parameters、DATAGRAM 支持标志）与 `HandshakeFailed`（区分证书、ALPN、transport parameter、超时）；事件顺序确定，重复输入不产生重复事件 | `cargo test -p rtx-quic --test facade_handshake`；`m3_q2_handshake_event_sequence`、`m3_q2_alpn_mismatch_fails`、`m3_q2_peer_datagram_support_is_visible` 通过 |
| [ ] | M3-Q3 | uni/bi streams | `open_uni`、`open_bi`、`accept_uni`、`accept_bi` | 支持单/双向流的打开与接受；发送/接收遵守流控；支持 finish、reset、stop_sending；流 ID 的方向与递增规则被校验；流控阻塞后能恢复；不静默丢数据 | `cargo test -p rtx-quic --test facade_streams`；`m3_q3_uni_round_trip`、`m3_q3_bi_round_trip`、`m3_q3_flow_control_blocks_then_resumes`、`m3_q3_reset_and_stop_sending_are_reported` 通过 |
| [ ] | M3-Q4 | QUIC DATAGRAM | `send_datagram`、`poll_datagram` | 按协商的 `max_datagram_frame_size` 发送与接收；超限返回显式错误且不截断；对端不支持 DATAGRAM 时返回显式错误；不可靠语义（不重传）在 facade 文档中写明 | `cargo test -p rtx-quic --test facade_datagram`；`m3_q4_round_trip`、`m3_q4_oversize_rejected`、`m3_q4_unsupported_peer_rejected` 通过 |
| [ ] | M3-Q5 | transmit polling | `poll_transmit` | 每次调用返回一个可直接由调用方发送的 transmit（含目的地址、长度、可发送性）；连续轮询可排空发送队列；空闲轮询返回 `None` 而不是忙等；支持调用方批量发送 | `cargo test -p rtx-quic --test facade_transmit`；`m3_q5_transmit_batch_drain`、`m3_q5_idle_poll_returns_none` 通过；`benchmarks/m3/` 中 batch 结果 |
| [ ] | M3-Q6 | timeout polling/handling | `poll_timeout`、`handle_timeout` | `poll_timeout` 返回绝对 `rtx_core::Timestamp` 截止时间；`handle_timeout(now)` 驱动 idle timeout、PTO/重传与丢包检测；只用注入时钟，不用 wall clock；同一截止时间只触发一次；关闭后的过期 timer 被忽略 | `cargo test -p rtx-quic --test facade_timeout`；`m3_q6_idle_timeout`、`m3_q6_pto_retransmits_without_sleep`、`m3_q6_timer_after_close_is_ignored` 通过；`cargo doc -p rtx-quic` 公开签名评审记录显示时间参数为 `Timestamp` |
| [ ] | M3-Q7 | connection close | `close`、`poll_event`（关闭子集） | 支持应用错误码+原因关闭、立即关闭、本地/远端关闭事件、draining 期；关闭幂等；关闭后调用 open/send 返回显式错误而不是 panic | `cargo test -p rtx-quic --test facade_close`；`m3_q7_application_close_round_trip`、`m3_q7_remote_close_event`、`m3_q7_operations_after_close_fail_explicitly` 通过 |
| [ ] | M3-Q8 | transport metrics needed by pacing/observability | `metrics` | 快照至少包含：平滑 RTT、最新 RTT、cwnd、in-flight bytes、lost packets、DATAGRAM 发送/接收计数、流字节数。若上游可提供 pacing 速率/令牌桶状态则必须一并暴露；不可得时必须在 facade 文档中给出上游 API 源码位置作为依据。快照的分配次数必须记录（0 或明确值） | `cargo test -p rtx-quic --test facade_metrics`；`m3_q8_metrics_after_handshake`、`m3_q8_metrics_reflect_loss_and_rtt`、`m3_q8_snapshot_allocations` 通过；facade 文档中的 pacing 说明 |

**M3-Q 的否定性边界**：以下内容不是门禁要求，除非 H3/互通条目明确需要——完整 Quinn 运行时、socket 所有权、异步 `AsyncRead`/`AsyncWrite`、连接池、自动重连、qlog 全量输出。把这些做进 M3 不构成“更完整”，只构成额外的未评审面。

**批量 syscall 的归属**：`recvmmsg`/`sendmmsg` 等 Linux 批量 I/O 属于 `rtx-linux`（ARCH §17），`rtx-quic` 只暴露 transmit 轮询与批量排空接口，不拥有 socket。M3-Q5/PB1 的批量对比必须说明测的是 `rtx-linux` 的 syscall 批处理还是纯协议处理，二者不能混为一张表。

### 1.2 M3-H：最小 H3 / WebTransport 子集清单

对齐 ARCH §15 的 8 个子集项。ARCH §15 最后一句限定：“The exact subset must be driven by browser interop tests, not by trying to implement all of HTTP/3.” 因此本组只要求下列子集，不要求完整 HTTP/3。

| 完成 | ID | ARCH §15 子集 | 所属 crate / 文件 | 最小契约 | 通过证据（命令 / 文件 / 测试名） |
|---|---|---|---|---|---|
| [ ] | M3-H1 | QUIC varint | `rtx-wire` / `crates/rtx-wire/src/varint.rs` | 支持 1/2/4/8 字节编码长度；边界值 `0`、`63`、`64`、`16383`、`16384`、`2^30-1`、`2^62-1` 往返一致；截断输入与超过 `2^62-1` 的值被拒绝；解码不分配 | `cargo test -p rtx-wire --test varint`；`m3_h1_boundary_round_trip`、`m3_h1_truncated_rejected`、`m3_h1_overflow_rejected`、`m3_h1_no_alloc` 通过 |
| [ ] | M3-H2 | H3 frame header | `rtx-wire` / `crates/rtx-wire/src/h3_frame.rs` | 帧头 = type varint + length varint；payload 以借用切片暴露；声明长度大于输入时拒绝；空 payload 合法；未知帧类型可保留并跳过 | `cargo test -p rtx-wire --test h3_frame`；`m3_h2_frame_header_round_trip`、`m3_h2_truncated_payload_rejected`、`m3_h2_unknown_frame_preserved` 通过 |
| [ ] | M3-H3 | SETTINGS required by WebTransport（WebTransport 所需 SETTINGS） | `rtx-h3` / `crates/rtx-h3/src/settings.rs` | 至少编码/解码 `SETTINGS_H3_DATAGRAM`、`SETTINGS_ENABLE_CONNECT_PROTOCOL`、所选 WebTransport over HTTP/3 版本要求的 max-sessions 设置；重复设置按 H3 错误处理；未知设置忽略；常量值必须与 Chrome 实测 SETTINGS 帧 fixture 对应 | `cargo test -p rtx-h3 --test settings`；`m3_h3_settings_round_trip`、`m3_h3_duplicate_setting_rejected`、`m3_h3_chrome_settings_fixture_parsed` 通过；fixture 存放在 `crates/rtx-h3/tests/fixtures/chrome-settings.bin` |
| [ ] | M3-H4 | CONNECT 最小 QPACK 形式 | `rtx-h3` / `crates/rtx-h3/src/qpack.rs`、`connect.rs` | 支持 CONNECT 所需静态表项与字面量形式（name reference、literal name）；动态表关闭（capacity 0、blocked streams 0）；能解码 Chrome 实际发送的 Huffman 编码字段，编码侧可输出非 Huffman 形式但必须被 Chrome 接受；伪头顺序与重复校验 | `cargo test -p rtx-h3 --test connect`；`m3_h4_connect_request_decode_chrome_fixture`、`m3_h4_connect_request_encode_round_trip`、`m3_h4_qpack_dynamic_table_disabled` 通过；fixture 存放在 `crates/rtx-h3/tests/fixtures/chrome-connect.bin` |
| [ ] | M3-H5 | extended CONNECT 请求/响应表示（core 不含 `url::Url`） | `rtx-h3` / `crates/rtx-h3/src/connect.rs` | 以字段表示 scheme、authority、path、protocol；支持 2xx 成功与错误状态；core 不依赖 `url::Url` | `cargo test -p rtx-h3 --test connect`；`m3_h5_extended_connect_round_trip`、`m3_h5_error_status_preserved` 通过；`cargo tree -p rtx-h3 -e normal` 输出无 `url`，归档到 `measurements/m3/deps/rtx-h3-tree.txt` |
| [ ] | M3-H6 | WebTransport 流/会话标识 | `rtx-webtransport` / `crates/rtx-webtransport/src/ids.rs` | 表示并校验 CONNECT 会话标识、WebTransport 流 ID、HTTP Datagram 的 quarter stream ID；ID 往返不变；非法/越界 ID 被拒绝；32 位目标上不发生 `usize` 截断 | `cargo test -p rtx-webtransport --test ids`；`m3_h6_session_and_stream_id_round_trip`、`m3_h6_invalid_id_rejected`、`m3_h6_no_usize_truncation` 通过 |
| [ ] | M3-H7 | 所选协议版本要求的 capsule | `rtx-webtransport` / `crates/rtx-webtransport/src/capsules.rs` | 至少覆盖会话关闭、会话 drain、流映射（stream ID 关联）三类语义所需的 capsule；类型值以所选 draft 与 Chrome 抓包为准并在代码常量中登记；按长度分帧；未知 capsule 忽略；超限拒绝 | `cargo test -p rtx-webtransport --test capsules`；`m3_h7_capsule_round_trip`、`m3_h7_unknown_capsule_ignored`、`m3_h7_oversize_rejected` 通过；draft 版本与常量表在文件头注释中 |
| [ ] | M3-H8 | DATAGRAM 映射 | `rtx-webtransport` / `crates/rtx-webtransport/src/datagram.rs` | 将 HTTP Datagram 载荷（quarter stream ID + payload）映射到 WebTransport 会话；校验会话归属；畸形载荷拒绝；大小上限与 QUIC DATAGRAM 协商一致 | `cargo test -p rtx-webtransport --test datagram_mapping`；`m3_h8_datagram_mapping_round_trip`、`m3_h8_wrong_session_rejected`、`m3_h8_malformed_rejected` 通过；Chrome DATAGRAM 互通记录（见 M3-B1） |

**子集边界的判定方法**：任何 H3 功能要进入门禁，必须先在 Chrome 抓包中证明浏览器实际使用它，并在 `crates/rtx-h3/tests/fixtures/` 留下 fixture。没有抓包证据的功能不得以“协议完整性”为由扩项；完整 HTTP/3 不是 M3 门禁项（ARCH §15）。

### 1.3 M3-B：浏览器互通清单

| 完成 | ID | 场景 | 通过证据 | 失败时 |
|---|---|---|---|---|
| [ ] | M3-B0 | Chrome 建立 WebTransport 会话 | `interop/m3/chrome/run.sh` 可重复执行；`interop/m3/<date>-chrome-<version>/report.md` 记录 commit、Chrome 版本、OS、启动参数、证书设置、服务端日志；extended CONNECT 返回 200 且服务端观察到会话 | 记为阻塞 GAP-M3-B0-01，M3 失败 |
| [ ] | M3-B1 | Chrome DATAGRAM | 同一报告中的 DATAGRAM 小节：Chrome→服务端与方向相反的 echo 各 1000 个 datagram；载荷取 1 字节、1000 字节、协商的 `max_datagram_frame_size`（若该值小于 1200 则用协商上限，并记录数值）；记录发送数、接收数、丢失数、顺序；服务端不崩溃 | 记为阻塞 GAP-M3-B1-01；只修不跳过 |
| [ ] | M3-B2 | Chrome 流 | 同一报告中的流小节：Chrome 发起的单向流、服务端发起的单向流、双向流各至少 1 条；每条 1 MiB，报告 SHA-256 与字节数；至少 10 条并发流；覆盖 half-close 与 reset | 记为阻塞 GAP-M3-B2-01；只修不跳过 |
| [ ] | M3-B3 | Firefox（条件适用，ARCH §18 “where applicable”） | 若被测 Firefox 版本支持 WebTransport over HTTP/3：复用 B0–B2 的报告格式；若不支持：`report.md` 中给出 Firefox 版本、平台、相关 pref/功能开关状态，判为 N/A | N/A 缺依据视为未通过；支持但失败按 B1/B2 处理 |
| [ ] | M3-B4 | Quinn/WebTransport 参考实现 | `interop/m3/quinn/` 中双向互通记录：QUIC 层用 `quinn` client ↔ `rtx-quic` server、`rtx-quic` client ↔ `quinn` server，覆盖握手、DATAGRAM、单向流、双向流；H3/WebTransport 层用 moq-dev/web-transport 参考实现（DEPENDENCY_AUDIT §1 的 `d4e4e458da556ac3033c9b63f6db5110d3ab5adc`）做握手/帧级对比；两层证据分开记录，并记录 quinn upstream revision（`9d729c1b6b7ad30d45d40265037eeeb9d98a7420`） | 记为阻塞 GAP-M3-B4-01；这是协议 oracle（ARCH §18） |
| [ ] | M3-B5 | 失败项缺口声明 | 每个 FAIL 行都有 GAP ID；GAP 按 §4 填写；无空白、无“已知问题”式跳过；阻塞 GAP 数量在报告首页汇总 | 缺 GAP 即未通过 |

**ARCH §18 的其余 peer**：`str0m` 与 `webrtc-rs/rtc` 是 WebRTC 互通对端，属于 M2 范围，M3 不重复跑。M3 验收 PR 必须链接 M2 的 `str0m` / `webrtc-rs/rtc` 互通记录；缺失时分别登记 GAP-M3-PS1-01 / GAP-M3-PS2-01。Firefox 按 §18 “where applicable” 处理（M3-B3）。

**`quinn` 的依赖边界**：M3-B4 的 `quinn` 只作为互通测试对端，不进入 `rtx-quic` 的运行时依赖；`rtx-quic` 仍直接驱动 `quinn-proto`（ARCH §14：the higher-level `quinn` runtime is optional）。

**互通记录必须包含的原始材料**（缺一不可）：

| 材料 | 路径示例 | 用途 |
|---|---|---|
| 可重跑脚本 | `interop/m3/chrome/run.sh` | 复现浏览器版本、参数、证书 |
| 浏览器版本 | `.../chrome-version.txt`（`chrome://version` 输出） | 证明版本，不写“最新版” |
| 服务端日志 | `.../server.log` | 证明会话、流、DATAGRAM 计数 |
| 载荷校验 | `.../hashes.txt` | 证明字节内容，不只是“收到” |
| 抓包/qlog | `.../capture.pcap` 或 `.../qlog/` | 失败项必须提供；通过项建议提供 |
| 测试页面/客户端 | `.../client.js` 或 `.../index.html` | 证明调用了哪些 WebTransport API |

**“通过”的最低含义**：会话建立、DATAGRAM 双向收发、流双向收发都有数字和哈希；不是“页面能打开”。

### 1.4 M3-P：分配与批量基准清单

#### 1.4.1 维度（逐项对齐 ARCH §19）

| 完成 | ID | ARCH §19 维度 | 单位与定义 | 采集方式 | 通过证据 |
|---|---|---|---|---|---|
| [ ] | M3-P1 | throughput | 字节/秒；线速字节与有效载荷字节分开报告 | 固定时长、固定载荷的收发循环 | `benchmarks/m3/results/*.json` 中 `throughput` 字段；`docs/m3-benchmarks.md` 汇总表 |
| [ ] | M3-P2 | packet rate | 包/秒（pps），饱和输入下测量 | 以最大可持续发送速率运行 | `packet_rate` 字段与原始日志 |
| [ ] | M3-P3 | p50/p95/p99 latency | 微秒；必须写明测量点（端到端、单向、或处理时延） | 时间戳打点或 RTT/2；不得把不同测量点混在一张表 | `latency.p50/p95/p99` 与测量点说明 |
| [ ] | M3-P4 | CPU cycles or CPU% | cycles/packet 或 CPU 时间占墙钟百分比；二者至少一种 | `perf stat` cycles 或 `getrusage` CPU 时间；记录命令 | `cpu` 字段 + 采集命令 |
| [ ] | M3-P5 | peak resident/live memory | 进程 RSS 峰值（`VmHWM`）与分配器 `peak_live_bytes` 分开报告 | `/proc/self/status` + 计数分配器 | `memory.rss_peak`、`memory.heap_peak` |
| [ ] | M3-P6 | allocation count and bytes | `alloc_count`、`free_count`、`allocated_bytes`、`peak_live_bytes` | `rtx-testkit` 计数分配器，按场景打标签 | `allocations` 对象；原始计数器日志 |
| [ ] | M3-P7 | allocations per packet/frame/connection | 每包、每帧、每连接、每握手的分配数 | 由 P6 计数器除以场景计数；握手单独统计 | `alloc_per_packet`、`alloc_per_frame`、`alloc_per_connection`、`alloc_per_handshake` |
| [ ] | M3-P8 | queue depth and backpressure behavior | 最大队列深度、丢弃/背压次数、饱和时行为 | 1.2 倍配置容量输入，记录深度与丢弃/拒绝计数 | `queue.max_depth`、`backpressure.events`；超限必须显式丢弃/拒绝 |

#### 1.4.2 场景（逐项对齐 ARCH §19）

“责任”列区分 M3 自己执行与引用 M2 产出。M3 只对 QUIC/WebTransport 行负责；引用行缺失时登记项目级 GAP，不能把 M3 标成已覆盖全部 §19。

| 完成 | ID | ARCH §19 场景 | 参数 | 责任 | 通过证据 |
|---|---|---|---|---|---|
| [ ] | M3-PS1 | WebRTC handshake | 1/10/100 并发握手；0/1/5/10% 丢包 | M2 产出，M3 引用 | M3 验收 PR 链接 M2 基准报告；缺失则 GAP-M3-PS1-01 |
| [ ] | M3-PS2 | RTP TX/RX | 固定码率与突发两种输入 | M2 产出，M3 引用 | 同上 |
| [ ] | M3-PS3 | 1080p30 media payload path | 预编码载荷；不实现编解码器 | M2 产出，M3 引用 | 同上 |
| [ ] | M3-PS4 | 4K media payload path | 预编码载荷；不实现编解码器 | M2 产出，M3 引用 | 同上 |
| [ ] | M3-PS5 | TWCC/NACK under 0/1/5/10% loss | 0/1/5/10% 丢包 | M2 产出，M3 引用 | 同上 |
| [ ] | M3-PS6 | 10/50/200 ms RTT | 三档 RTT，QUIC 与 WebTransport 各跑 | M3 执行 | `benchmarks/m3/results/rtt-*.json` |
| [ ] | M3-PS7 | QUIC handshake | 冷启动；1/10/100 并发；0/1/5/10% 丢包 | M3 执行 | `handshake-*.json`；`m3_p7_handshake_under_loss` 等测试 |
| [ ] | M3-PS8 | WebTransport DATAGRAM | 载荷取协商的 `max_datagram_frame_size`（记录数值）；1000 pps 起步，饱和点另测（P2）；60 秒；0/1/5/10% 丢包；10/50/200 ms RTT 组合 | M3 执行 | `datagram-*.json`；与 M3-B1 互通的指标交叉引用 |
| [ ] | M3-PS9 | uni/bi stream throughput | 1 MiB 与 16 MiB；1/10/100 并发流 | M3 执行 | `stream-*.json`；与 M3-B2 交叉引用 |
| [ ] | M3-PS10 | many concurrent idle and active sessions | 1/100/1000/10000 idle（DEPENDENCY_AUDIT §9，where practical；不可行时记录实际上限与原因）；活跃会话按宿主容量取最大可运行值 | M3 执行 | `sessions-*.json`；记录每连接内存与 CPU |
| [ ] | M3-PB1 | 批量发送/接收（ARCH §20 M3 “batching benchmarks”） | batch = 1/8/32/64 | M3 执行 | `batch-*.json`；pps 与 cycles/packet 对照表 |

**如果 M3 路径实际承载 RTP**（例如用 WebTransport 传媒体），PS1–PS5 从“引用”转为 M3 执行，不能再用 M2 报告替代。

**引用行的 GAP ID**：PS2–PS5 缺失时分别登记 GAP-M3-PS2-01、GAP-M3-PS3-01、GAP-M3-PS4-01、GAP-M3-PS5-01，不能复用 PS1 的 GAP。

#### 1.4.3 基准方法与复现要求

| 完成 | ID | 要求 | 通过证据 |
|---|---|---|---|
| [ ] | M3-PM1 | 计数分配器位于 `rtx-testkit`，可按场景标签输出 `alloc_count`、`free_count`、`allocated_bytes`、`peak_live_bytes`；不得在热路径打印日志 | `cargo test -p rtx-testkit` 中分配器自测通过；`crates/rtx-testkit/src/alloc.rs` |
| [ ] | M3-PM2 | 丢包/RTT 由确定性网络模拟器注入，测试不依赖真实 `tc netem` 或外网；模拟器有单元测试 | `crates/rtx-testkit/src/netem.rs`；`m3_pm2_netem_deterministic` 通过；场景日志含 seed |
| [ ] | M3-PM3 | 每次结果记录：commit、rustc、target、feature 集、CPU 型号、内核、batch、loss、RTT、seed；缺字段的结果无效 | `benchmarks/m3/results/*.json` 的元数据块；`docs/m3-benchmarks.md` 表头 |
| [ ] | M3-PM4 | 每场景至少 5 次运行、报告 5 次的中位数与离散度；含预热；固定 CPU 亲和性 | 原始运行日志；汇总表标注运行次数 |
| [ ] | M3-PM5 | 结果可复跑：`benchmarks/m3/run.sh` 一条命令重建全部 M3-owned 场景 | 脚本 + CI/手工运行日志；脚本在干净 checkout 可执行 |
| [ ] | M3-PM6 | 基准报告提交到 `docs/m3-benchmarks.md`，原始 JSON 提交到 `benchmarks/m3/results/` | 文件路径 + 评审链接 |

#### 1.4.4 通过阈值（“本文件”设定，非 ARCH 原文）

| 完成 | ID | 阈值 | 通过证据 |
|---|---|---|---|
| [ ] | M3-PT1 | 完整性：M3-owned 的每个“维度 × 场景”单元都有数字；缺一格即失败 | 汇总表无空单元格；`run.sh` 输出的场景清单与 §1.4.2 一一对应 |
| [ ] | M3-PT2 | `rtx-wire`/`rtx-h3` 的稳态帧编解码为 0 次强制分配/帧（DEPENDENCY_AUDIT §9 的 WebTransport frame codec 目标） | `m3_pt2_frame_codec_zero_alloc` 中计数分配器 delta 为 0 |
| [ ] | M3-PT3 | QUIC DATAGRAM 稳态的 allocations/packet 必须实测并记录；不得承诺 0（DEPENDENCY_AUDIT §9：minimize and measure; do not promise before profiling） | `datagram-*.json` 中的 `alloc_per_packet` + 说明 |
| [ ] | M3-PT4 | 任一维度相对上一份基线恶化超过 10%，必须附 waiver 说明；否则失败。首轮 M3 结果即基线；没有基线文件时不得声称“无回归” | 基线文件 + diff 表 + waiver 链接 |
| [ ] | M3-PT5 | P8 的队列最大深度不得超过配置上限；超限必须是显式丢弃/拒绝/背压，不能静默增长 | 饱和场景日志中的 `max_depth` 与 `drop/backpressure` 计数；计数分配器峰值不随输入线性增长 |
| [ ] | M3-PT6 | 批量对比必须给出 batch=1/8/32/64 的 pps 与 cycles/packet；若批量无改善，记录瓶颈（syscall/加密/拷贝） | `batch-*.json` + 报告中的瓶颈说明 |

### 1.5 M3-F：新解码器的 fuzz 门禁

ARCH §18 要求 “Fuzz all untrusted wire decoders before optimizing them”。M3-H 新增的 varint、H3 帧头、SETTINGS、QPACK、capsule、DATAGRAM 映射都是不可信输入解码器，因此 fuzz 是优化和基准之前的门禁，不是可选项。

| 完成 | ID | 要求 | 通过证据 |
|---|---|---|---|
| [ ] | M3-F1 | 每个新解码器至少有一个 `cargo-fuzz` target；target 名与解码器一一对应；`cargo fuzz build` 全量通过 | `fuzz/fuzz_targets/` 中的 target 清单；`cargo fuzz build` 日志；target ↔ 解码器映射表在 `fuzz/README` 或 PR 描述中 |
| [ ] | M3-F2 | 每个 target 在 CI 中至少 smoke 运行 20 秒；历史 crash 输入固化为 regression corpus，修复后不得复现 | CI `fuzz` 作业日志；`fuzz/corpus/<target>/` 中的 regression 输入；修复 commit 链接 |
| [ ] | M3-F3 | fuzz 必须在 M3-PT2（零分配优化）之前完成；未完成 fuzz 时不得宣称解码器“优化完成” | PR 顺序/时间线；M3 验收 PR 中的 fuzz 链接早于基准报告 |

### 1.6 M3 出口判定

| 完成 | 条件 | 证据 |
|---|---|---|
| [ ] | M3-0 全部通过 | M3-0 表全部 `[x]`；§6.2 附件 |
| [ ] | M3-Q0–Q8 全部通过 | M3-Q 表全部 `[x]`；`cargo doc -p rtx-quic` 链接 |
| [ ] | M3-H1–H8 全部通过 | M3-H 表全部 `[x]`；fixture 路径 |
| [ ] | M3-B0、B1、B2、B4 通过；B3 通过或 N/A 有依据；B5 无阻塞缺口 | `interop/m3/.../report.md` 与 GAP 表 |
| [ ] | M3-F1–F3 全部通过，且早于 M3-PT2 的优化声明 | fuzz CI 日志、corpus 路径、PR 时间线 |
| [ ] | M3-P1–P8、PS1–PS10、PB1、PM1–PM6、PT1–PT6 全部通过（PS1–PS5 可引用 M2 报告或登记项目级 GAP） | `docs/m3-benchmarks.md` + `benchmarks/m3/results/` |
| [ ] | 不存在阻塞性 GAP | §5 已登记缺口表（无阻塞行） |
| [ ] | 互通报告、基准报告、原始日志均已归档并可复跑 | §6.2 必填附件全部有链接 |

**M3 不要求**：完整 HTTP/3、QPACK 动态表、Firefox 在未支持版本上的通过、0-RTT、连接迁移、多会话复用，除非 Chrome 互通或 M4-Q 决策明确要求。未要求项不得写成“已完成”。

---

## 2. M4 — 嵌入式 profile

ARCH §20 M4 的工作项是：choose a real MCU-L/RTOS target；prove or reject full QUIC requirement；port only the required WebRTC/QUIC components；enforce resource budgets and measure worst-case memory。下面按“目标 → QUIC 决策 → 预算 → 内存 → CI → 移植范围”展开。

### 2.0 M4-0：目标前置门（硬前置）

**规则**：M4-0 未通过前，不得开始任何 `quinn-proto` 移植、裁剪、协议栈板级适配或最坏内存测试代码。允许的前置工作只有：候选调研、数据手册核对、最小启动固件，以及为验证目标可用性所必需的最小 build/link/smoke CI。违反此顺序即 M4 失败，不论后续测试多绿。

#### 2.0.1 候选列出标准

| 完成 | ID | 标准 | 通过证据 |
|---|---|---|---|
| [ ] | M4-T1 | 具体型号：MCU 型号、核心、主频、封装、开发板型号齐全，不接受“某 Cortex-M”式描述 | `docs/m4-target-selection.md` 的候选表；数据手册 URL 与页码 |
| [ ] | M4-T2 | 类别：属于 ARCH §4 的 MCU/RTOS 目标（Tier B 或 Tier C），不是 Tier D 的 Linux/应用处理器目标；M4 要证明的是 MCU-L 约束（ARCH §20 M4） | 候选表“capability tier”列 + ARCH §4 对应关系 |
| [ ] | M4-T3 | 内存/Flash：数据手册给出的 SRAM、Flash、可用外部 RAM（若有）与启动/RTOS 占用估算 | 候选表数值 + 数据手册页码 |
| [ ] | M4-T4 | 网络：MAC/PHY 或板载网口；链路 MTU；网络栈（`rtx-smoltcp` 或厂商栈）的缓冲区所有权；若需 QUIC，必须能满足 RFC 9000 的最小 1200 字节 UDP 负载 | 候选表 + DEPENDENCY_AUDIT §11 E6 的第 3 项回答 |
| [ ] | M4-T5 | 密码学：硬件加速器或可测的软件性能；能通过 `rtx-crypto` 的 provider 边界；不要求新增原语（ARCH §12） | 候选表 + 加速器型号/驱动；`rtx-crypto` trait 映射说明 |
| [ ] | M4-T6 | 时间：单调时钟/定时器存在，分辨率、位宽、溢出行为明确，能映射到 `rtx_core::Timestamp`（ARCH §8） | 候选表 + 定时器驱动/数据手册章节 |
| [ ] | M4-T7 | 工具链与 CI：稳定版 Rust 有对应 target triple；可链接 ELF；有调试探针；至少一块开发板可长期用于 CI（或可远程访问的 runner） | `rustup target list` 输出；CI runner 标签；板卡资产编号 |
| [ ] | M4-T8 | 可获得性：开发板可购买、供应商 SDK/RTOS 可用、生命周期满足项目周期 | 采购链接/订单号；供应商文档链接 |

候选数量：至少 2 个候选，或对至少 1 个落选候选给出逐条否决理由。只列 1 个候选且无落选记录，视为未做目标选择。

#### 2.0.2 否决条件

| 完成 | ID | 否决条件 | 证据 |
|---|---|---|---|
| [ ] | M4-V1 | 没有具体型号/开发板，目标无法复现 | 候选表缺失即否决 |
| [ ] | M4-V2 | 目标是 Linux/应用处理器且不体现 MCU-L 约束：不能作为 M4 的证明目标；嵌入式 Linux 只能作为后续独立 profile，不得替代 M4 的 MCU-L 验证 | 候选表类别列 + 目标用途说明 |
| [ ] | M4-V3 | 若 M4-Q 结论需要 QUIC，而链路 MTU < 1200 或无路径满足 RFC 9000 最小 UDP 负载 | MTU 实测/数据手册 + M4-Q 决策 |
| [ ] | M4-V4 | 数据手册资源上限低于“静态占用 + 最小堆栈 + 最小堆”的保守下界；M4-M 实测超预算同样触发否决 | 预算表 + M4-M 报告 |
| [ ] | M4-V5 | 无稳定 Rust target/toolchain，或无法在 CI 中完成链接 | `cargo build --target ...` 失败记录 |
| [ ] | M4-V6 | 网络栈/驱动只提供 `std`/OS 接口且无适配路径（违反 ARCH §7 的 Sans-I/O 边界） | 依赖树/驱动文档评审 |
| [ ] | M4-V7 | 密码学只能通过新增原语或非 provider-neutral 接口接入（违反 ARCH §3、§12） | 密码学接口评审记录 |
| [ ] | M4-V8 | 无可用单调时钟/定时器，或分辨率/位宽不满足 ARCH §8 的时间模型 | 数据手册 + 驱动评审 |
| [ ] | M4-V9 | 开发板不可购买/无 CI 实物，无法完成 M4-M 的板上实测 | 采购/资产记录 |
| [ ] | M4-V10 | 目标需要不兼容的运行时（例如只能跑非 Rust 异常模型/动态链接的 SDK），且无隔离适配方案 | SDK 文档评审 |

任一 V 条件命中且无书面豁免，目标即被否决；豁免必须由架构评审签署，并登记 GAP-M4-T-01。

#### 2.0.3 M4-0 通过证据

| 完成 | ID | 证据 |
|---|---|---|
| [ ] | M4-0-1 | `docs/m4-target-selection.md` 已合并；含候选表、T1–T8 逐项证据、V1–V10 逐项结论、选中目标、落选理由 |
| [ ] | M4-0-2 | 选中目标的最小启动固件（`firmware/m4-smoke`）执行 `cargo build --no-default-features --release --target <triple>` 能链接出 ELF（不是只有 `cargo check`） |
| [ ] | M4-0-3 | CI 中存在 `embedded-build` 作业并在该 target triple 上为绿；作业链接归档到目标文档 |
| [ ] | M4-0-4 | 至少一块板上运行的最小固件能启动并通过串口/探针输出（证明板子、工具链、烧录链路可用） |
| [ ] | M4-0-5 | 目标文档的合并 commit 早于任何 M4 移植 PR；`git log`/PR 时间线作为证据 |

### 2.1 M4-Q：完整 QUIC 需求的证明/否定

#### 2.1.1 能力矩阵（必须逐行回答，不能留空）

| 完成 | ID | QUIC 能力 | 需要？ | 证据来源 | 缺失后果 | 可替代方案 |
|---|---|---|---|---|---|---|
| [ ] | M4-QC1 | QUIC handshake + TLS 1.3 | 必须填 required/optional/absent | 产品需求或数据流文档 | 必须写具体后果 | 必须写或写“无” |
| [ ] | M4-QC2 | 单向流 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC3 | 双向流 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC4 | QUIC DATAGRAM | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC5 | 丢包恢复/重传 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC6 | 拥塞控制 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC7 | 流控/窗口更新 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC8 | 连接迁移/CID 变更 | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC9 | 0-RTT | 同上 | 同上 | 同上 | 同上 |
| [ ] | M4-QC10 | key update | 同上 | 同上 | 同上 | 同上 |

每一行的“证据来源”必须是可定位的文件或需求条目，不能写“一般认为”。`optional` 与 `absent` 也必须给出理由：为什么该能力在目标应用里不会出现。

#### 2.1.2 方法与判定

| 完成 | ID | 步骤 | 通过证据 |
|---|---|---|---|
| [ ] | M4-Q1 | 冻结板上应用画像：设备到底做 WebTransport 服务端/客户端、只做 WebRTC、还是只做遥测；画出数据流 | `docs/m4-quic-decision.md` 的“应用画像”节 + 数据流图 |
| [ ] | M4-Q2 | 完成 §2.1.1 的 QC1–QC10 矩阵，每行有 required/optional/absent 与证据 | 决策文档矩阵；无空单元格 |
| [ ] | M4-Q3 | 对每个 required 能力做替代性分析：WebRTC DataChannel/SCTP、纯 RTP、UDP/TCP 自定义协议能否替代；替代结论要有协议对比或原型/抓包证据。缩减的 QUIC profile 不算“替代 QUIC”，只影响 M4-S 的移植范围 | 决策文档“替代性分析”节；对比表 + 证据链接 |
| [ ] | M4-Q4 | 回答 DEPENDENCY_AUDIT §11 E6 的五个问题并给出测量：可用 RAM、密码学加速能力、MTU 与网络栈缓冲所有权、板上是否需要浏览器级 WebTransport、最大并发连接/流 | `measurements/m4/e6/` 原始日志 + 决策文档汇总 |
| [ ] | M4-Q5 | 记录唯一结论：`PROVEN` / `REFUTED` / `INFEASIBLE`；`UNDECIDED` 不算通过 | 决策文档结论节 + 签署 |
| [ ] | M4-Q6 | 若 `PROVEN`：移植计划逐条映射 ARCH §14 的 7 个阶段（替换 std → 抽象地址/时间 → 处理 tracing/平台验证 → 可移植 crypto/TLS → 显式 limits → 有界容器 → 上游差分测试） | `docs/m4-quic-port-plan.md` 的 7 行映射表；每行有任务 ID 与验收测试 |

**判定规则（“本文件”设定）**：

| 结论 | 成立条件 | 后续动作 |
|---|---|---|
| `PROVEN` | 至少一个 QC_i 是 required，且 Q3 证明无可用替代，且 Q4 的保守预算能容纳 | 按 ARCH §14 七阶段移植；进入 M4-S |
| `REFUTED` | 所有 QC_i 为 optional/absent，或每个 required QC_i 都有被接受的替代方案 | 不移植 QUIC；记录替代方案；M4-S 只覆盖实际需要的 WebRTC 组件 |
| `INFEASIBLE` | 有 required 能力，但 Q4/预算证明在该目标上无法容纳且无允许的预算提升 | 拒绝该目标的 QUIC；记录原因；可换目标（回到 M4-0）或缩小应用画像 |
| `UNDECIDED` | 任一矩阵行无证据，或结论未签署 | 门禁失败；不得进入任何移植工作 |

**“否定”不是“没做”**：`REFUTED`/`INFEASIBLE` 必须有矩阵、画像、替代分析和测量。只有“我们觉得用不上”不构成否定。

#### 2.1.3 决策证据

| 完成 | ID | 证据 |
|---|---|---|
| [ ] | M4-Q-1 | `docs/m4-quic-decision.md` 已合并，含 QC1–QC10 矩阵、应用画像、替代性分析、E6 五问回答、唯一结论与签署 |
| [ ] | M4-Q-2 | 若 `PROVEN`：`docs/m4-quic-port-plan.md` 已合并，含 ARCH §14 七阶段逐条映射与差分测试计划 |
| [ ] | M4-Q-3 | 若 `REFUTED`/`INFEASIBLE`：决策文档含“被否定项清单”（逐项写明查找过的需求来源和未找到的证据），并列出实际要移植的组件 |

### 2.2 M4-R：资源预算清单

ARCH §16 的 11 个 `MAX_*` 是门禁下限，不得改名或省略。另因 ARCH §14 第 5 阶段明确要求 ACK state 有界，追加 `MAX_ACK_STATE_BYTES`（标注为“本文件补充”，不是 §16 原文）。

| 完成 | ID | 限制名 | 所属层（ARCH §5 crate） | 单位 | 超限行为（必须显式） | 通过证据 |
|---|---|---|---|---|---|---|
| [ ] | M4-R1 | `MAX_ICE_CANDIDATES` | `rtx-ice` | 个 | 拒绝新候选并返回类型化错误；已有候选不受影响 | `crates/rtx-ice/tests/resource_limits.rs::m4_r01_max_ice_candidates_overflow_is_explicit` |
| [ ] | M4-R2 | `MAX_ICE_PAIRS` | `rtx-ice` | 对 | 拒绝新建 pair；不得静默驱逐后继续增长 | `m4_r02_max_ice_pairs_overflow_is_explicit` |
| [ ] | M4-R3 | `MAX_RTP_STREAMS` | `rtx-webrtc`（或实际拥有流表的 crate，须在预算文档登记） | 个 | 拒绝新流并返回类型化错误；不扩表 | `m4_r03_max_rtp_streams_overflow_is_explicit` |
| [ ] | M4-R4 | `MAX_REORDERED_PACKETS` | `rtx-rtp` / `rtx-webrtc` | 个 | 超出重排窗口的包显式丢弃并计数；不扩窗口 | `m4_r04_max_reordered_packets_drops_and_counts` |
| [ ] | M4-R5 | `MAX_NACK_HISTORY` | `rtx-webrtc` / `rtx-rtp`（实际拥有 NACK 历史的 crate，须在预算文档登记） | 个 | 按文档化策略淘汰最旧记录并计数，或拒绝请求；不得无界增长 | `m4_r05_max_nack_history_is_bounded` |
| [ ] | M4-R6 | `MAX_QUIC_STREAMS_BIDI` | `rtx-quic` | 个 | 本端 open 被阻塞/报错；对端超限触发传输错误；不扩 map | `crates/rtx-quic/tests/resource_limits.rs::m4_r06_max_quic_streams_bidi_overflow_is_explicit` |
| [ ] | M4-R7 | `MAX_QUIC_STREAMS_UNI` | `rtx-quic` | 个 | 同上 | `m4_r07_max_quic_streams_uni_overflow_is_explicit` |
| [ ] | M4-R8 | `MAX_QUIC_DATAGRAM_QUEUE_BYTES` | `rtx-quic` | 字节 | 发送返回 `WouldBlock`/显式丢弃并计数；绝不扩堆 | `m4_r08_max_datagram_queue_bytes_backpressures` |
| [ ] | M4-R9 | `MAX_REASSEMBLY_BYTES` | `rtx-quic` | 字节 | 中止该流/重组并返回错误；计数；不扩缓冲 | `m4_r09_max_reassembly_bytes_aborts_explicitly` |
| [ ] | M4-R10 | `MAX_CONNECTION_IDS` | `rtx-quic` | 个 | 拒绝新 CID 或停止签发；显式错误/计数 | `m4_r10_max_connection_ids_is_bounded` |
| [ ] | M4-R11 | `MAX_PENDING_TIMERS` | `rtx-core` / `rtx-quic` | 个 | 定时器注册返回类型化错误；不扩堆 | `m4_r11_max_pending_timers_errors` |
| [ ] | M4-R12 | `MAX_ACK_STATE_BYTES`（本文件补充，依据 ARCH §14 第 5 阶段） | `rtx-quic` | 字节 | 触发立即 ACK 并只保留最近区间；计数；上限不可突破 | `m4_r12_max_ack_state_bytes_is_bounded` |

#### 2.2.1 通用规则

| 完成 | ID | 规则 | 通过证据 |
|---|---|---|---|
| [ ] | M4-RB1 | 每个限制在选中目标上都有明确数值；数值、单位、所属 crate、失败模式登记在 `docs/m4-resource-budget.md`；未设值视为未通过 | 预算文档表格；评审签署 |
| [ ] | M4-RB2 | 超限只能产生三类结果之一：背压（`WouldBlock`/重试）、丢弃（带计数）、类型化错误；不得静默扩堆，不得 panic/abort | 每个 R 测试断言具体返回值/计数；错误类型在 `src` 中可见 |
| [ ] | M4-RB3 | 达到上限后继续输入，`alloc_count` 与 `peak_live_bytes` 不增加（初始化时按上限预分配允许） | 每个 R 测试内的计数分配器断言 delta 为 0；原始日志 |
| [ ] | M4-RB4 | 预算文档必须列出每个动态容器 → 对应上限的映射，证明没有“无上限的 Vec/Map/Deque”留在状态路径上 | `docs/m4-resource-budget.md` 的“容器 → 上限”表 + 源码评审记录 |
| [ ] | M4-RB5 | Linux profile 的数值可以更大，但同样必须有界（ARCH §16 最后一段） | `docs/m4-resource-budget.md` 的 Linux/embedded 两列 |
| [ ] | M4-RB6 | 用固定大小堆（例如 64 KiB，数值由目标决定并登记）跑最大负载，不出现分配失败；若失败则预算不足 | `measurements/m4/<date>-<commit>/heap-limit.log` |

### 2.3 M4-M：最坏内存实测方法

“最坏”指单次运行中同时达到所有配置上限，而不是逐项峰值相加。所有数字必须来自目标 ELF 的实际运行与链接产物，不能用估算代替。

| 完成 | ID | 步骤 | 通过证据 |
|---|---|---|---|
| [ ] | M4-M1 | 链接 release ELF：`cargo build --release --no-default-features --target <triple>`，用 `cargo size` 或 `arm-none-eabi-size` 记录 `.text`、`.rodata`、`.data`、`.bss` | `measurements/m4/<date>-<commit>/size.txt`；ELF 的 SHA-256 记录在报告中 |
| [ ] | M4-M2 | 栈高水位：启动时用固定图案（如 `0xAA`）填充主栈与中断栈，跑完最坏场景后扫描；两栈分开报告 | `.../memory.log` 中 `main_stack_high_water`、`isr_stack_high_water`；扫描脚本/代码位置 |
| [ ] | M4-M3 | 堆峰值：全局计数分配器记录 `peak_live_bytes`、`alloc_count`、`free_count`，以及峰值时的最大连续空闲块（分配器不支持时写明原因） | `.../memory.log`；`crates/rtx-testkit/src/alloc.rs` 或板级等价实现 |
| [ ] | M4-M4 | 最坏场景：一次运行同时达到所有实际移植组件的上限。若含 QUIC：`MAX_QUIC_STREAMS_BIDI`、`MAX_QUIC_STREAMS_UNI`、`MAX_QUIC_DATAGRAM_QUEUE_BYTES`、`MAX_REASSEMBLY_BYTES`、`MAX_CONNECTION_IDS`、`MAX_PENDING_TIMERS`、`MAX_ACK_STATE_BYTES`、最大连接数、最大证书链，并包含丢包/PTO 重传；若含 WebRTC：`MAX_ICE_CANDIDATES`、`MAX_ICE_PAIRS`、`MAX_RTP_STREAMS`、`MAX_REORDERED_PACKETS`、`MAX_NACK_HISTORY` 同时达到上限 | `firmware/m4-worst-case/src/main.rs`；场景表；`.../worst-case.log` |
| [ ] | M4-M5 | 预算等式：`静态 RAM (.data+.bss) + 堆峰值 + 最大栈 + 保留余量 ≤ 目标 SRAM`；`Flash (.text+.rodata+.data 加载映像) ≤ 目标 Flash`；余量必须为正，报告具体数值 | `docs/m4-memory-report.md` 的预算表；数值与 M4-M1/M2/M3 一致 |
| [ ] | M4-M6 | 可复现：`scripts/m4/memory_report.sh` 固定工具链、构建、烧录/运行、采集日志；CI 作业 `embedded-memory` 调用同一脚本 | 脚本 + CI 绿跑链接 + artifact |
| [ ] | M4-M7 | 最终数字来自真实开发板；QEMU 只允许做回归对比，不得作为 M4-M 的最终证据 | 板卡序列号/runner 标签；QEMU 结果单独标注“回归用” |

**余量规则**：本文件建议主栈余量 ≥ 20%、堆余量 ≥ 10%，但门禁只要求“余量为正且有评审接受的数值”。若余量低于建议值，必须在内存报告中说明最坏场景覆盖理由并取得签署。

**一致性规则**：M4-M1 的 `.text/.data/.bss` 必须与 CI `embedded-size` 作业使用同一 ELF（SHA-256 相同），否则报告无效。

### 2.4 M4-C：裸机 CI 要求

现有 CI 只有 `cargo check --workspace --no-default-features --target thumbv7em-none-eabihf`（`.github/workflows/ci.yml` 的 `test` 作业第 4 步）。`check` 不链接、不产 ELF、不跑板上代码，因此**不足以**满足 M4。M4 要求下列作业存在且为必需检查。

| 完成 | ID | 要求 | 通过证据 |
|---|---|---|---|
| [ ] | M4-C1 | `embedded-build`：对选中 target triple 构建最小固件 `firmware/m4-smoke`（`cargo build --no-default-features --release`），必须链接出 ELF | workflow 文件中的作业；绿跑链接；ELF artifact |
| [ ] | M4-C2 | `embedded-lint`：对同一 target 执行 `cargo clippy --no-default-features -- -D warnings` | 同上 |
| [ ] | M4-C3 | `embedded-size`：比较 ELF 的 `.text/.rodata/.data/.bss` 与 M4-M 预算；超限失败 | 作业日志 + 失败阈值配置 |
| [ ] | M4-C4 | `embedded-smoke`：在真实板或 QEMU 上运行最小固件，覆盖时间、buffer、crypto provider、至少一条协议路径，返回非零即失败 | 串口/探针日志；runner 标签；绿跑链接 |
| [ ] | M4-C5 | `embedded-memory`：运行 `scripts/m4/memory_report.sh`，产出 M4-M 日志并检查预算 | 绿跑链接 + artifact |
| [ ] | M4-C6 | 依赖闭包检查：`cargo tree --target <triple> -e normal` 结果归档，且闭包内所有 crate 都能为该 target 成功编译（由 C1 的链接构建证明） | `measurements/m4/deps/target-tree.txt`；C1 绿跑链接 |
| [ ] | M4-C7 | 工具链固定：`rust-toolchain.toml` 锁定版本与 target；CI 不使用“latest stable”漂移 | 文件路径 + CI 日志中的 `rustc --version` |
| [ ] | M4-C8 | 分支保护：上述检查是 `main` 的 required status checks；不能靠人工记得跑 | `gh api repos/medivhc/rtx-rs/branches/main/protection` 输出的 required checks JSON，归档到 `measurements/m4/ci/protection.json` |

**判定细节**：`embedded-smoke` 在 QEMU 上通过只能证明可启动与逻辑路径；M4-M 的最终内存数字仍必须在真实板上取得。若目标没有真实板（M4-V9），M4 整体不通过，不能用 QEMU 替代。

### 2.5 M4-S：移植范围（ARCH §20 M4 “port only the required components”）

| 完成 | ID | 要求 | 通过证据 |
|---|---|---|---|
| [ ] | M4-S1 | 每个被移植的模块都能映射到 M4-Q 的一个 required 行；若 M4-Q 为 `REFUTED`/`INFEASIBLE`，映射到应用画像中的一项 WebRTC 需求。没有“顺手移植”的模块 | `docs/m4-quic-port-plan.md` 或 `docs/m4-port-scope.md` 的“模块 → 能力”表；PR 列表逐项对应 |
| [ ] | M4-S2 | 每个被移植的协议组件都有对上游固定 revision 的差分测试（ARCH §18、§14 第 7 阶段）：QUIC 对 `quinn-proto` @ `9d729c1b6b7ad30d45d40265037eeeb9d98a7420`；WebRTC 组件对 DEPENDENCY_AUDIT §1 的 str0m @ `634e76bb830e167e2208c6e743acfb4678e2675c` / webrtc-rs @ `5573fe50ccca69fb8c72272be60c8adde59b7ef0` | `crates/<crate>/tests/differential_*.rs`；测试内常量记录 revision；`cargo test` 通过 |
| [ ] | M4-S3 | 密码学只通过 `rtx-crypto` provider trait 接入；依赖树中不出现新增密码学原语实现；不自定义 AEAD/KEX/HMAC 构造（ARCH §3、§12） | `cargo tree -p <crate> -e normal` 归档；API 评审记录 |
| [ ] | M4-S4 | 每个被移植的有状态组件都接入 M4-R 的对应限制与超限测试；没有“先移植、预算后补”的组件 | 组件 → R 条目映射表；测试列表 |

### 2.6 M4 出口判定

| 完成 | 条件 | 证据 |
|---|---|---|
| [ ] | M4-0 全部通过；目标文档合并早于所有移植 PR（M4-0-5） | 目标文档链接 + `git log`/PR 时间线 |
| [ ] | M4-Q 结论为 `PROVEN`/`REFUTED`/`INFEASIBLE` 且有证据；`UNDECIDED` 即失败 | `docs/m4-quic-decision.md` 与签署 |
| [ ] | M4-R1–R12 与 RB1–RB6 全部通过 | `docs/m4-resource-budget.md` + 测试列表 |
| [ ] | M4-M1–M7 全部通过；预算等式中余量为正 | `docs/m4-memory-report.md` + 原始日志 |
| [ ] | M4-C1–C8 全部通过；required checks 生效 | workflow 绿跑 + `protection.json` |
| [ ] | M4-S1–S4 全部通过；若 M4-Q 为 `REFUTED`/`INFEASIBLE`，S1/S4 只覆盖实际移植的 WebRTC 组件 | 移植清单 + 差分测试列表 |
| [ ] | 不存在阻塞性 GAP | §5 已登记缺口表（无阻塞行） |

---

## 3. 非目标（与 ARCH §3 一致）

| 完成 | 非目标 | ARCH 依据 | 对门禁的含义 | 通过证据（否定性判定） |
|---|---|---|---|---|
| [ ] | 不从头写 QUIC | ARCH §3 第 1 条；§14 末段；DEPENDENCY_AUDIT §5.6 | M4 只能按 §14 七阶段移植/裁剪 `quinn-proto`；提出“重写 QUIC”方案即判 M4-Q 失败 | M4-Q6 的七阶段映射表；代码评审确认没有新建 QUIC 协议实现模块；PR 清单 |
| [ ] | 不造新密码学原语 | ARCH §3 第 2 条；§12 | 只用现有 provider 的 AEAD/hash/HMAC/KEX；M4-T5、M4-S3 检查；自定义构造即失败 | `cargo tree` 依赖清单；`rtx-crypto` provider trait 实现清单；API 评审记录 |
| [ ] | 不做浏览器级 PeerConnection | ARCH §3 第 3 条；§13 | M3 facade 不是 PeerConnection；M4 不要求 SDP/完整 ICE/DTLS/SCTP 全套；只移植目标真正需要的模块 | M3-Q0 公共外观清单；M4-S1 模块→能力表；PR 评审确认没有 SDP offer/answer 实现 |
| [ ] | 不透明支持所有 MCU 类别 | ARCH §3 第 4 条；§4 | M4 只对一个选定目标负责；不为“通用性”增加未评审的 HAL/抽象层 | `docs/m4-target-selection.md` 只选一个目标；HAL/抽象层 PR 评审记录 |
| [ ] | 不做通用 async runtime 抽象 | ARCH §3 第 5 条；§7 | facade 保持 Sans-I/O；M3-0-2 禁止 Tokio 进入 `rtx-quic` 公共依赖 | `cargo tree -p rtx-quic -e normal` 无 `tokio`；`rtx-core` 无 runtime trait 的评审记录 |
| [ ] | 不做应用层媒体编解码 | ARCH §3 第 6 条；§19 | 1080p30/4K 基准使用预编码载荷；不实现 H.264/AV1 等编解码器 | 基准输入为预编码文件的记录；依赖树/源码评审确认无编解码器实现 |
| [ ] | 不做完整 HTTP/3 | ARCH §15 末句 | M3-H 只覆盖 §15 的 8 个子集；QPACK 动态表、服务端推送、完整 Huffman 编码器不进入门禁 | M3-H 的 fixture 清单；`cargo tree`/源码评审确认没有完整 HTTP/3 状态机或动态 QPACK 表 |
| [ ] | 不把 0-RTT、连接迁移、多会话复用当作默认 M3 能力 | ARCH §15；§19 | 只有 Chrome 互通或 M4-Q 明确要求时才纳入；否则登记为范围外，不写成“已支持” | M3-Q/M3-H 条目清单中没有这些能力；若实现，附 Chrome 抓包或 M4-Q 需求依据 |

**范围变更规则**：M3/M4 实现中发现需要新增上述非目标能力时，停下并单独提 ARCH 修订 PR。不得在本门禁文档里偷偷扩项，也不得用实现“顺带完成”来绕过评审。

---

## 4. GAP（缺口声明）规范

任何未通过项，要么修掉，要么登记为 GAP。GAP 的字段缺一不可。

| 字段 | 要求 |
|---|---|
| ID | `GAP-M3-<组>-<两位序号>` 或 `GAP-M4-<组>-<两位序号>`，例如 `GAP-M3-B1-01`；`<组>` 取条目 ID（如 `B1`、`PS1`、`T`），同类问题多条记录时序号递增 |
| 类型 | `阻塞` 或 `非阻塞` |
| 场景与复现 | 命令/脚本/步骤；必须能复现 |
| 期望依据 | ARCH 章节、RFC/draft 章节，或本文条目 ID |
| 实际证据 | 日志/抓包/qlog/报告路径 + 浏览器/板卡版本 |
| 影响 | 哪些条目受影响；是否阻塞 M3/M4 出口 |
| 处置 | `fix` / `defer` / `reject`；`defer` 必须写重测日期 |
| 责任与复核 | owner、issue 链接、复核人 |
| 状态 | `OPEN` / `FIXED` / `ACCEPTED`；修好后保留原行，追加修复证据 |

规则：

1. 阻塞 GAP：导致 M3/M4 出口不能成立。存在任一阻塞 GAP 时，§6 结论必须是 FAIL。
2. 非阻塞 GAP：只允许用于本文标注“条件适用”的项，或明确不在所选 M3/M4 profile 内的功能；必须由复核人签署。
3. GAP 不能豁免 ARCH §14/§15/§16 的强制项；例如不能用 GAP 跳过 `MAX_QUIC_STREAMS_BIDI`。
4. 不允许删除历史 GAP 行；只能改状态并追加证据。
5. “已知问题”“后续优化”“环境限制”不是 GAP；必须落到具体字段。

---

## 5. 已登记缺口

本文件创建时 M3/M4 尚未开工，因此没有已登记缺口。后续按 §4 追加行，不覆盖历史。

| ID | 类型 | 摘要 | 状态 | 证据 |
|---|---|---|---|---|
| GAP-M3-B0-02 | 阻塞 | Chrome 建立 WebTransport 会话失败：服务端 SETTINGS 不含 legacy ENABLE_WEBTRANSPORT（0x2b603742），Chrome 以 net::ERR_METHOD_NOT_SUPPORTED 拒绝，B1/B2 因此 not_run（被 B0 阻塞，未执行） | OPEN | PR #25（合并 ddc43e4）：interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md（放宽相位）+ 同目录 -baseline/report.md（基线相位 H3_SETTINGS_ERROR 0x0101）；Chrome for Testing 155.0.8059.39 |
| GAP-M3-B3-01 | 非阻塞（条件适用） | Firefox 互通未判定：未找到可用的 Firefox 二进制（已查 command -v firefox、/usr/lib/firefox/firefox、Playwright 缓存、/snap/bin/firefox），B3 按条件适用项记 NOT DETERMINED，待有 Firefox 二进制后重测 | OPEN | PR #25（合并 ddc43e4）：同上放宽相位 report.md 状态表 B3 行 |

---

## 6. 判定汇总（验收 PR 填写）

### 6.1 分组结论

| Gate 组 | 条目数 | 通过数 | 阻塞 GAP 数 | 结论（PASS/FAIL） | 复核人 |
|---|---:|---:|---:|---|---|
| M3-0 入口 | 4 |  |  |  |  |
| M3-Q 外观 | 9 |  |  |  |  |
| M3-H H3/WebTransport | 8 |  |  |  |  |
| M3-B 互通 | 6 |  |  |  |  |
| M3-F 解码器 fuzz | 3 |  |  |  |  |
| M3-P 基准 | 8 + 10 + 1 + 6 + 6 |  |  |  |  |
| **M3 合计** |  |  |  |  |  |
| M4-0 目标 | 8 + 10 + 5 |  |  |  |  |
| M4-Q QUIC 决策 | 10 + 6 + 3 |  |  |  |  |
| M4-R 预算 | 12 + 6 |  |  |  |  |
| M4-M 内存 | 7 |  |  |  |  |
| M4-C 裸机 CI | 8 |  |  |  |  |
| M4-S 移植范围 | 4 |  |  |  |  |
| **M4 合计** |  |  |  |  |  |

（条目数按“判定单元”计：M3-P 的 8 为 P1–P8，10 为 PS1–PS10，1 为 PB1，两个 6 为 PM1–PM6 与 PT1–PT6；M4-0 的 8 为 T1–T8，10 为 V1–V10，5 为 M4-0-1–M4-0-5；M4-Q 的 10 为 QC1–QC10，6 为 Q1–Q6，3 为 Q-1–Q-3。）

### 6.2 必填附件

| 附件 | 路径/链接 | 是否存在 |
|---|---|---|
| 被测 commit | `git rev-parse HEAD` 输出 |  |
| CI 运行 | 全绿 run URL |  |
| M3 互通报告 | `interop/m3/.../report.md` |  |
| M3 基准报告 | `docs/m3-benchmarks.md` + `benchmarks/m3/results/` |  |
| M4 目标选择 | `docs/m4-target-selection.md` |  |
| M4 QUIC 决策 | `docs/m4-quic-decision.md` |  |
| M4 预算表 | `docs/m4-resource-budget.md` |  |
| M4 内存报告 | `docs/m4-memory-report.md` + `measurements/m4/.../` |  |
| 分支保护 | `measurements/m4/ci/protection.json` |  |

### 6.3 签署

| 项 | 内容 |
|---|---|
| 结论 | PASS / FAIL |
| 被测 commit |  |
| 验收 PR |  |
| 复核人 |  |
| 日期 |  |
| 遗留非阻塞 GAP |  |

结论只能是 PASS 或 FAIL。空白、`TBD`、`基本通过`均视为 FAIL。

---

## 7. ARCH 追溯矩阵

用于逐项核对：左侧是 ARCH 原文所在章节与要点，右侧是本文条目。章节号与 crate 名均按基线 commit 核对。

| ARCH 依据 | 原文要点 | 本文条目 |
|---|---|---|
| §3 | 非目标：新 QUIC、新密码学原语、完整 PeerConnection、所有 MCU、通用 async runtime、应用层编解码 | §3 全部条目 |
| §4 | Tier A/B/C/D；Tier C 每个动态结构仍有最大值 | M4-T2、M4-RB5 |
| §5 | 规划 crate 名 | 全文路径与 crate 归属 |
| §7 | Sans-I/O；不暴露 Tokio/UdpSocket/Instant/task handle | M3-0-2、M3-Q5、M3-Q6、M4-V6 |
| §8 | `Timestamp(u64)` 单调微秒；绝对 deadline | M3-Q6、M4-T6、M4-V8 |
| §11 | 调用方缓冲、借用切片、无需 Tokio 的编解码 | M3-H1、M3-H2、M3-PT2 |
| §12 | provider-neutral、无分配 trait 边界、不新增原语 | M4-T5、M4-S3、§3 |
| §13 | 不在下层测量前构建完整 PeerConnection | §3“不做浏览器级 PeerConnection”、M3-M4 范围 |
| §14 | Linux 8 项能力；不镜像 Quinn 全部 API | M3-Q0–Q8 |
| §14 | 嵌入式 7 阶段移植；不从头重写 QUIC | M4-Q6、M4-S1、M4-S2、§3 |
| §15 | 8 个初始子集；子集由浏览器互通驱动 | M3-H1–H8、M3-B0–B5 |
| §16 | 11 个 `MAX_*`；超限显式背压/丢弃/报错；不静默扩堆 | M4-R1–R11、M4-RB1–RB3；M4-R12 为 §14 第 5 阶段的补充 |
| §17 | 可预测分配；选定快路径零稳态分配 | M3-P5–P7、M3-PT2–PT4 |
| §18 | 确定性测试、差分测试、fuzz、互通 peer 列表 | M3-0-4、M3-B4、M3-F1–F3、M4-M7、M4-S2 |
| §19 | 8 个基准维度 | M3-P1–P8 |
| §19 | 9 条场景（1080p30 与 4K 拆为两行，共 10 个判定项） | M3-PS1–PS10 |
| §20 M3 | facade、最小 H3/WebTransport、浏览器 DATAGRAM/流互通、分配与批量基准 | M3-Q、M3-H、M3-B、M3-P |
| §20 M4 | 选目标、证明/否定完整 QUIC、只移植必需组件、资源预算、最坏内存 | M4-0、M4-Q、M4-S、M4-R、M4-M |
| DEPENDENCY_AUDIT §1 | 审计固定 revision（quinn `9d729c1...`、web-transport `d4e4e45...`、str0m/webrtc-rs） | M3-0-1、M3-B4、M4-S2 |
| DEPENDENCY_AUDIT §5.3/§5.5/§5.6 | QUIC 堆结构、`no_std` 障碍、复用不重写 | M4-Q、M4-R、§3 |
| DEPENDENCY_AUDIT §9 | 分配计数项与 0 分配目标；DATAGRAM 只测量不承诺 | M3-P6、M3-P7、M3-PT2、M3-PT3、M3-PS10 |
| DEPENDENCY_AUDIT §11 E4/E5/E6 | Quinn facade、WebTransport codec、嵌入式可行性五问 | M3-Q、M3-H、M4-Q4 |
