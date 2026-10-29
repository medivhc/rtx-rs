# interop/m3/rtx-server — R6-3 WebTransport-over-HTTP/3 server harness

本目录的职责：在 **R6-2 / R6-2b** 的编解码之上，造出一个**可运行的 rtx
WebTransport 服务端**，并用无浏览器的回环矩阵证明会话、DATAGRAM 与流路径可用。

边界（必须一直成立）：

- 本目录证明的是“rtx 服务端 + 审计基线参考客户端（`quinn` +
  `web-transport-proto`）在 loopback 上跑通”，**不**证明 Chrome/Firefox 互通。
  浏览器实测（M3-B0/B1/B2/B3/B5）是 **R6-4**，本目录不跑浏览器、不写
  `interop/m3/chrome/` 新报告、不宣称任何 Chrome 结论。
- 服务端二进制只依赖 `rtx-core` / `rtx-wire` / `rtx-h3` /
  `rtx-webtransport` / `rtx-quic`；`quinn` 与 `web-transport-proto` 只出现在
  `[dev-dependencies]`，只作回环客户端与协议 oracle。
- 不改任何已有 crate、已有文档、`interop/m3/chrome/`、CI 或 workspace 清单。

## 目录结构

```
interop/m3/rtx-server/
├── Cargo.toml                  # 独立 workspace（不是 rtx-rs workspace 成员）
├── Cargo.lock                  # 与参考实现同源、可复现
├── src/main.rs                 # std-only 服务端：泵循环 + H3 + WebTransport 回显
├── tests/loopback.rs           # quinn + web-transport-proto 回环矩阵
├── run-loopback.sh             # 一键证书生成 -> 测试 -> 归档 evidence/report.md
├── evidence/<YYYY-MM-DD>-loopback/
│   ├── report.md               # 本次回环证据
│   ├── server.log              # 服务端结构化日志
│   └── hashes.txt              # 矩阵的机器可读记录（发送/接收/丢失/字节/SHA-256）
└── README.md
```

## 依赖

| 依赖 | 用途 | 备注 |
|---|---|---|
| Rust 工具链 | 构建服务端与回环测试 | 独立 crate，不进 workspace 覆盖率分母 / thumbv7em 检查 |
| `openssl` | `run-loopback.sh` 运行时生成 DER 证书与私钥 | 只存在于 `mktemp` 目录，EXIT trap 删除 |
| `quinn` @ `9d729c1b…` | 回环 QUIC 客户端（仅 dev-dependencies） | 与 `DEPENDENCY_AUDIT.md` §1 一致 |
| `web-transport-proto` @ `d4e4e458…` | 回环 H3/WebTransport oracle（仅 dev-dependencies） | 与 R6-2c 同源 |

服务端**正常依赖树**里不得出现 `quinn` 本体和 `web-transport-proto`：

```
cargo tree -p rtx-wt-server -e normal | grep -E "quinn |web-transport-proto"
```

`quinn-proto` 经 `rtx-quic` 出现是设计的引擎依赖（评审须与 `quinn` 本体区分）。

## 运行

```bash
# 从仓库根或任意位置均可
./interop/m3/rtx-server/run-loopback.sh
# 排障时可保留临时证书/日志目录：
#   KEEP_WORK=1 ./interop/m3/rtx-server/run-loopback.sh

# 只跑测试（会自己生成一次性 rcgen 证书，不进仓库）：
cd interop/m3/rtx-server && cargo test --test loopback
```

脚本顺序：`openssl` 生成 DER 证书/私钥（`mktemp`）→ `cargo test --test
loopback`（服务端二进制由 Cargo 以 `CARGO_BIN_EXE_rtx-wt-server` 提供）→
把 `server.log` / `hashes.txt` 归档到 `evidence/<date>-loopback/` → 生成
`report.md` → EXIT trap 删除临时目录。证据目录只含三个文本文件，不含证书、
私钥、PNG 或 `.screenshots`。

## 服务端 CLI 与日志

```
rtx-wt-server --bind 127.0.0.1:0 \
              --cert-chain-der /path/cert.der \
              --key-der /path/key.pem-pkcs8.der \
              --log /path/server.log
```

- `--bind` 支持端口 0；绑定后首行日志 `event=server_listening addr=<实际地址>`，
  回环测试解析该行取端口，不硬编码、不轮询固定端口。
- 证书只接受 DER：文件以 `-----BEGIN` 开头会被显式拒绝；代码里没有任何证书。
- `--log` 由调用方决定路径（脚本给 `mktemp` staging，测试给临时目录）；服务端
  不写仓库固定位置。
- 日志为 `ts_ms=<墙钟> event=<name> key=value …` 行格式，逐行 flush。墙钟只用于
  `ts_ms=` 前缀，协议时间一律用单调 `Instant` 换算的 `rtx_core::Timestamp`。

**等待机制（无 `thread::sleep`）**：`src/main.rs` 用
`std::net::UdpSocket::set_read_timeout` 驱动泵循环。每轮先排空
`Endpoint::poll_transmit`，再处理事件/流/DATAGRAM，然后取
`Endpoint::poll_timeout` 的绝对截止时间，等待时长 = `min(截止时间-now, 50 ms)`
（至少 1 µs）；socket 超时后若截止时间已到就调用
`Endpoint::handle_timeout`。源码里没有任何 `std::thread::sleep`：

```
grep -R "thread::sleep" interop/m3/rtx-server/src   # 无匹配
```

## 服务端 SETTINGS（钉死 5 项）

| id | 值 | 名称 |
|---|---|---|
| `0x01` | 0 | `QPACK_MAX_TABLE_CAPACITY`（动态表关闭） |
| `0x07` | 0 | `QPACK_BLOCKED_STREAMS`（动态表关闭） |
| `0x08` | 1 | `ENABLE_CONNECT_PROTOCOL` |
| `0x33` | 1 | `H3_DATAGRAM` |
| `0xc671706a` | 100 | `WEBTRANSPORT_MAX_SESSIONS`（harness 容量选择，不是协议要求） |

`rtx-h3` 的 `Settings::encode` 按设计丢弃已弃用对与 GREASE 对，所以只能发出
这 5 项；R6-2c 参考服务端的 6 项含已弃用 `0xffd277` / `0x2b603742` /
`0x2b603743`，差额是编解码层设计的一致表现，不是缺陷。

**N4 裁决（本单实现）**：不发 `0x2c7cf000`（`draft-ietf-webtrans-http3-15`
§9.2 的 `SETTINGS_WT_ENABLED`）。Chrome 156 实际协商的是已弃用
`0x2b603742`；在“观察到有 Chrome 版本协商 `0x2c7cf000`”之前，发一个对方不协商
的 codepoint 属于未经验证的行为。评审与 R6-4 不得把这一项当成“draft-15
要求缺失”判错。

## DATAGRAM 协商与“全值”

`TransportConfig` 的 `datagram_receive_buffer_bytes = Some(1100)`（facade 默认
本身就开启 DATAGRAM；这里显式钉死并写进 README）。`quinn-proto` 把该值原样
写进 `max_datagram_frame_size` 传输参数，所以：

- 服务端日志 `event=quic_handshake_complete … peer_max_datagram_frame_size=<值>`
  来自握手信息 `HandshakeInfo::peer_transport_parameters` 的解析（参数 id
  `0x20`），不是手写常量；
- 回环客户端同样声明 1100，因此协商值是 1100；
- 回环矩阵的“全值”取 **两侧引擎都接受的完整载荷**：
  `1100 - 32 = 1068` 字节（quinn-proto 0.11.19 的接收检查是
  `payload + size_of::<Datagram>() > window` 就判 PROTOCOL_VIOLATION；0.12
  客户端的发送预算是 `window - 9`）。HTTP Datagram 载荷 1068 字节 = 1 字节
  quarter stream ID + 1067 字节 WebTransport 载荷。`report.md` 同时记录
  协商值与这个完整载荷数值。

## H3 会话（服务端逻辑）

- **单向流分发**（首 varint 类型）：`0x00` 控制流、`0x02` QPACK 编码器流、
  `0x03` QPACK 解码器流（后两者只排空、不建动态表）、`0x54` WebTransport
  单向流（后跟 session ID）；未知类型按 H3 规则忽略并记录
  `event=uni_stream_unknown_type`，不崩溃。`0x54`/`0x41` 来自
  `draft-ietf-webtrans-http3-15` §4.2/§4.3。
- **控制流**：收客户端 SETTINGS 帧（`rtx-wire` 帧头 + `Settings::decode`），
  逐项记录 `event=h3_setting id=… value=… class=known|deprecated|grease|unknown
  ignored=…`，然后发服务端 SETTINGS（`Settings::encode` + `0x04` 帧头）。
- **extended CONNECT**：双向流首帧为 HEADERS（`0x01`）→ `FieldSection` 解码
  → `ConnectRequest::decode`；只接受 `:method == CONNECT` 且
  `:protocol == webtransport`，否则回 400 并记录，绝不回 200。
- **session ID 换算式**：session ID = CONNECT 流 ID（client-initiated
  bidirectional，低两位 `00`，即 `≡ 0 mod 4`）；HTTP Datagram 的 quarter
  stream ID = `SessionId >> 2`（`rtx-webtransport::ids` 的
  `SessionId/QuarterStreamId`）。README 与 `report.md` 记录同一算式。
- **capsule 承载方式**：CONNECT 流上的 capsule 放在 HTTP/3 **DATA 帧**里
  （`RFC 9297` §3.2；审计基线 `web-transport-proto::Http3CapsuleReader`
  以同样方式读取，回环以它为事实标准）。capsule 本身的字节由
  `rtx-webtransport::capsules` 编解码。
  - `WT_CLOSE_SESSION`（`0x2843`）：记日志、移除会话、结束 CONNECT 流发送侧，
    同一 QUIC 连接继续服务下一会话。
  - `WT_DRAIN_SESSION`（`0x78AE`）：只记日志并标记 drained；**不提前关闭
    连接**（draft §4.7 语义），会话仍可继续收发。
  - 未知 capsule（`Capsule::Unknown`）原样记录 `event=capsule_unknown` 后丢弃，
    不崩溃。
- **QPACK**：编码侧只发静态表引用与非 Huffman 字面量（`encode_fields`，
  前缀 `00 00`）；解码侧用 `ensure_dynamic_table_disabled` 拒绝动态表容量非 0
  的设置组合，并按 `H3_SETTINGS_ERROR` 关连接。注意：Chrome 156 的 SETTINGS
  带 `0x01=65536` / `0x07=100`，会命中该拒绝分支；这是 R6-2b 的 H4 边界，
  R6-4 若要跑 Chrome 必须先由协调者裁决是否放宽，本单不改。
- **服务端 SETTINGS 发送时机**：收到客户端 SETTINGS 之后。

## DATAGRAM 回显

收 QUIC DATAGRAM → 用 `QuarterStreamId` 定位会话 → `Datagram::decode(input,
session, max_len=1100)`：

- `WrongSession`（quarter 不属于任何会话）记日志并丢弃，连接继续；
- `Malformed`（空载荷/截断）记日志并丢弃；
- `TooLarge` 记日志并丢弃，不截断、不崩溃。

回显用 `Datagram::encode(session, payload, max_len, output)` + `send_datagram`
发回同一会话；编码失败（超限等）记 `datagram_echo_failed` 并显式放弃，绝不
静默截断。

**不可靠语义**：QUIC DATAGRAM 不重传、不保证顺序。回环 0 丢失是 loopback
环境的实测结果，不是协议保证；R6-4 的 Chrome 矩阵必须按 `M3-B1` 记录真实
丢失数。

## 流回显与服务端主动流

- 客户端双向流：读到 FIN（half-close）→ 把全部字节原样从同一流写回 →
  `finish_stream`；客户端中途 reset → 记 `event=stream_reset role=client`，
  其余流不受影响。
- 客户端单向流：读到 FIN → 在服务端新开的单向流（`open_uni`）上写回 →
  `finish_stream`。新流带 `0x54` + session ID 头。
- 每个会话建立后，harness **主动**开两条服务端流（R6-4 的 B2 可直接复用）：
  - 单向流：`0x54` + session ID + 1 MiB 确定性载荷（`0..255` 循环）；
  - 双向流：`0x41` + session ID + 4096 字节载荷，随后 `reset_stream(code=7)`。
    客户端必须观察到 reset；`RESET_STREAM` 可能丢弃排队数据，所以 reset 流上
    的 session 头是**可选**的，服务端日志才是权威记录。

确定性载荷：从 0 起的 `0..255` 循环，取前 N 字节；因此所有 SHA-256 重跑一致。

## 回环矩阵（`M3-B` 前置条件，缺一即失败）

- 会话：同一 QUIC 连接上顺序 3 个 + 第二条连接上并发 2 个，CONNECT 均 200，
  服务端日志各有 `connect_request_decoded` 与 `response_headers_sent`。
- DATAGRAM：每方向 100 个 × 3 种尺寸（1 B、1000 B、完整载荷 1067 B（HTTP
  Datagram 1068 B）），双向 SHA-256 一致、丢失 0；另加 WrongSession 与空
  （畸形）各 1 个，服务端记日志丢弃、连接继续。
- 流：客户端单向 1 MiB、客户端双向 1 MiB、10 条并发双向各 1 MiB、服务端单向
  1 MiB（每会话一条）、服务端 reset 双向（每会话一条）、客户端 reset 1 条；
  全部 half-close，SHA-256 双向一致，其余流不受影响。
- 会话关闭：`WT_DRAIN_SESSION` 后会话仍可用；`WT_CLOSE_SESSION` 后同一连接
  仍能建立新会话。
- 新增会话的自动流也计入矩阵（服务端单向 5 × 1 MiB、服务端 reset 5 条）。

**为什么 DATAGRAM 是“发送-接收交替”**：`max_datagram_frame_size` 同时也是
`quinn-proto` 的接收队列字节预算（1100），一次性打 100 个 1068 B 的突发会因
队列预算而非 harness 缺陷丢包。回环用成对回显把“丢失=0”变成可判定的 harness
断言；真实突发的丢包数字留给 R6-4 的 `M3-B1`。

## 证据

`evidence/<date>-loopback/`：

- `report.md`：commit、harness 版本、环境、服务端 SETTINGS 5 项、协商
  `max_datagram_frame_size`、矩阵逐项（发送/接收/丢失/字节/SHA-256）、N4 裁决
  复述、未做项。
- `server.log`：本次运行的服务端结构化日志。
- `hashes.txt`：矩阵的 TSV（`item, sends, receives, lost, bytes, sha256,
  detail`），重跑复现。

## 明确不做

Chrome 实测（R6-4）、B4 `quinn` 参考互通记录（本单的 `quinn` 只是回环客户端）、
B3 Firefox 判定、基准（P7）、嵌入式移植（P8）、完整 HTTP/3（QPACK 动态表、
服务端推送、完整 Huffman 编码器）、0-RTT、连接迁移、多会话默认能力、改 CI、
改任何既有 crate/文档/`interop/m3/chrome/`。
