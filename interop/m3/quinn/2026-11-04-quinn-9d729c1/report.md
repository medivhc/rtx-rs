# B4 Quinn 互通证据报告（第 18 步：矩阵组装 + 正式报告）

- 日期：2026-11-04
- 分支：`b4/quinn-interop-evidence`
- 分支头：`ea870b607aeb2db26f2096f686c9061612c04190`
- 工作目录：`interop/m3/quinn`
- 测试命令：`cargo test --all-targets`
- 原始日志：`cargo-test.log`（本目录，112 行，全量原始输出）

## 上游 revision（钉死，本次未改动）

| 组件 | revision |
| --- | --- |
| quinn | `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` |
| web-transport-proto（web-transport） | `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` |

## 全量测试结果总览

- 集成测试：15 个，15 pass / 0 fail / 0 ignored。
- `src/main.rs` 单元测试二进制：0 个测试（`running 0 tests`，ok）。
- 日志中 `test result: ok` 共 16 行（15 个集成测试 + 1 个单元测试二进制），与预期一致。

## 逐项测试结果

### QUIC 层（10 个）

| # | 测试 | 方向 | payload / 断言 | 结果 |
| --- | --- | --- | --- | --- |
| 1 | `endpoint_smoke`（`rtx_quic_endpoint_creates`） | 本地构造，无网络 | 仅构造 rtx-quic endpoint | pass |
| 2 | `dual_endpoint_smoke`（`dual_endpoints_create`） | 本地构造，无网络 | rtx-quic + quinn 双端构造 | pass |
| 3 | `loopback_handshake` | quinn client → rtx-quic server | ALPN `h3` 握手 | pass |
| 4 | `datagram_once` | quinn → rtx | DATAGRAM，21 字节 `datagram-once-payload` | pass |
| 5 | `uni_stream_once` | quinn → rtx | 单向流，23 字节 `uni-stream-once-payload` | pass |
| 6 | `bi_stream_once` | quinn ⇄ rtx | 双向流：请求 22 字节 `bi-stream-once-payload` + 应答 23 字节 `bi-stream-once-response` | pass |
| 7 | `reverse_loopback_handshake` | rtx client → quinn server | ALPN `h3` 握手（角色互换） | pass |
| 8 | `reverse_datagram_once` | rtx → quinn | DATAGRAM，21 字节 `reverse-datagram-once` | pass |
| 9 | `reverse_uni_stream_once` | rtx → quinn | 单向流，23 字节 `reverse-uni-stream-once` | pass |
| 10 | `reverse_bi_stream_once` | rtx ⇄ quinn | 双向流：请求 22 字节 `reverse-bi-stream-once` + 应答 `reverse-bi-response` | pass |

### H3 层（5 个）

| # | 测试 | 方向 | payload / 断言 | 结果 |
| --- | --- | --- | --- | --- |
| 11 | `h3_handshake_once` | 正向：quinn client（web-transport-proto 手工驱动）↔ rtx-quic server（rtx-h3） | SETTINGS 双向交换、扩展 CONNECT、`SessionId::new(0)`、200 响应、双侧关闭 | pass |
| 12 | `reverse_h3_handshake_once` | 反向：rtx client（rtx-h3）↔ quinn server（web-transport-proto） | SETTINGS 双向交换、CONNECT、`SessionId::new(0)`、200 响应 | pass |
| 13 | `h3_session_datagram_once` | H3 会话 session 0 内 DATAGRAM，quinn → rtx | 24 字节 `h3-session-datagram-once` | pass |
| 14 | `h3_session_wt_stream_once` | H3 会话 session 0 内 WT 数据流，quinn → rtx 单向流 | WT uni 流头 `[40 54 00]`（varint(0x54) 两字节形 `[0x40,0x54]` + varint(0) `[0x00]`）+ 22 字节 `wt-stream-once-payload` | pass |
| 15 | `h3_session_close_once` | H3 会话 session 0 内关闭，quinn → rtx | 关闭 capsule 类型 `0x2843`、code `420`、message `h3-session-close-once`，包在 H3 DATA 帧（帧类型 `0x00`）内 | pass |

所有 15 项的上游 revision 均为上表钉死的 quinn `9d729c1…` 与 web-transport `d4e4e458…`。

## 层小结

### QUIC 层小结

10/10 通过。覆盖：本地端点构造（rtx 单端、rtx+quinn 双端）、双向握手（quinn→rtx 与 rtx→quinn，ALPN `h3`）、双向 DATAGRAM、双向单向流、双向双向流（请求+应答）。QUIC 层各方向、各传输类型的基础互通均得到验证。

### H3 层小结

5/5 通过。覆盖：正向与反向的 H3/WebTransport 握手（SETTINGS 双向、扩展 CONNECT、`SessionId::new(0)`、200 响应、双侧关闭），以及 session 0 内的 DATAGRAM、WT 单向数据流（WT uni 流头 `[40 54 00]`）、会话关闭 capsule（`0x2843`，code 420，DATA 帧内）。H3/WebTransport 层在 session 0 上的握手、数据、关闭基础路径均得到验证。

## 已知局限（如实列出，不得省略）

1. **B2 的 DATAGRAM 前缀口径差异（未解决）**：quinn 侧用完整 session ID 作为 DATAGRAM 前缀，rtx 侧用 quarter stream ID（`SessionId::quarter`）前缀并校验。本证据只测了 session ID 0——此时两种编码恰好一致（均为 `0x00`）。当 session ID ≥ 4 时两种编码分叉：以流 ID 4 为例，quinn 前缀为 `0x04`，rtx 期望 quarter `0x01`，解码回 `WrongSession`。这是已知未解决的口径差异。**本报告不得被引用为多会话 DATAGRAM 已互通的证据。**
2. **反向 WT 数据流未测**：只测了 quinn → rtx 的 WT 单向数据流（`h3_session_wt_stream_once`），未测 rtx → quinn 方向。
3. **反向 WT 会话关闭未测**：只测了 quinn → rtx 的关闭 capsule（`h3_session_close_once`），未测 rtx → quinn 方向。
4. **多流并发、半关闭/reset、大 payload 均未测**：各测试 payload 均为 21–24 字节小量；DATAGRAM 与流均未做 1 MiB 级测试。
5. **本报告只是互通证据，不改变门禁 `docs/m3-m4-gates.md` §5 状态**；B4 是否通过的判定留给后续验收步骤。

## 结论

在钉死的上游 revision（quinn `9d729c1…`、web-transport `d4e4e458…`）下，`interop/m3/quinn` 全量 15 个集成测试全部通过（15/15），`src/main.rs` 单元二进制 0 测试。QUIC 层 10/10、H3 层 5/5。

以上结论严格限于本报告所列测试范围与上述已知局限。本报告仅为互通证据，不构成 B4 通过结论，不改变门禁 §5 状态。