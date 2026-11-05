# H3/WebTransport 层探查笔记（H3-PROBE）

> **状态：只读探查（B4 拆步第 12 步）。不写实现、不落测试、不改任何代码。**
> 本文件是该步骤唯一新增文件，未提交。所有结论均给出 checkout 内文件路径 + 关键签名/行号；
> 未查到证据的地方明确标注，不猜。

## 0. 环境与 revision 核对

| 项 | 值 | 证据 |
| --- | --- | --- |
| 本仓库 | `/work/build/rtx-b4`，分支 `b4/quinn-interop-evidence`，头 `ea870b6` | `git branch --show-current` / `git rev-parse --short HEAD` |
| quinn 上游 checkout | `/work/build/rtx-b4-upstream/quinn`，HEAD = `9d729c1b6b7ad30d45d40265037eeeb9d98a7420`（与钉死值一致） | `git -C ... rev-parse HEAD` |
| web-transport 上游 checkout | `/work/build/rtx-b4-upstream/web-transport`，HEAD = `d4e4e458da556ac3033c9b63f6db5110d3ab5adc`（与钉死值一致） | 同上 |
| cargo git checkout | `/work/nexus-dev/.cargo/git/checkouts/quinn-3d7ed53a5c53d189/9d729c1`、`/work/nexus-dev/.cargo/git/checkouts/web-transport-c59b4a359dc4ff07/d4e4e45`（目录存在，与钉死 rev 对应） | `ls` |
| interop 锁文件 | quinn `0.12.0`（source = git rev 9d729c1…）、web-transport-proto `0.6.2`（source = git rev d4e4e458…） | `interop/m3/quinn/Cargo.lock:433-435`、`:995-997` |
| QUIC 层现状 | 10 项单项测试全过；ALPN `h3` 握手正反向已证（#3/#7）、DATAGRAM 双向已证（#4/#8） | `interop/m3/quinn/QUIC-LAYER-INTERIM.md` 第 2、4 节 |

---

## 1. quinn 侧：H3 CONNECT / WebTransport 会话怎么建立（问题 1）

### 1.1 quinn 仓库本身没有 H3

- `quinn@9d729c1` 的 workspace 成员只有 `quinn`、`quinn-proto`、`quinn-udp`、`bench`、`perf`、`fuzz`、`docs/book`
  （`/work/build/rtx-b4-upstream/quinn/Cargo.toml:2`）。**不存在 `quinn-h3` 或 `h3` crate**；
  `quinn/src`、`quinn-proto/src` 内 grep `quinn-h3|"h3"` 无命中。
- quinn 只提供 QUIC 传输 + rustls 接入；ALPN `h3` 只是 rustls 配置里的字节串，H3 报文流必须由使用方自己在
  quinn 的流上驱动。这正是 `web-transport-quinn` 所做的事（见 1.4）。
- 与 H3/WT 相关的 quinn API（`quinn/src/connection.rs`）：
  - `pub fn open_uni(&self) -> OpenUni<'_>`（:330）、`pub fn open_bi(&self) -> OpenBi<'_>`（:347）
  - `pub fn accept_uni(&self) -> AcceptUni<'_>`（:359）、`pub fn accept_bi(&self) -> AcceptBi<'_>`（:380）
  - `pub fn read_datagram(&self) -> ReadDatagram<'_>`（:392）、`pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>`（:513）、
    `pub async fn send_datagram_wait(...)`（:541）、`pub fn max_datagram_size(&self) -> Option<usize>`（:560）
  - `pub fn close(&self, error_code: VarInt, reason: &[u8])`（:468）、`pub async fn closed(&self) -> ConnectionError`（:404）
  - DATAGRAM 接收默认开启：`datagram_receive_buffer_size` 默认 `Some(STREAM_RWND as usize)`
    （`quinn-proto/src/config/transport.rs:405`，setter 在 :303）。
- 流的 tokio 异步适配是无条件实现：`impl tokio::io::AsyncRead for RecvStream`（`quinn/src/recv_stream.rs:531`）、
  `impl tokio::io::AsyncWrite for SendStream`（`quinn/src/send_stream.rs:337`）。
  因此 web-transport-proto 的 `AsyncRead/AsyncWrite` 型 codec 可以直接作用在 quinn 流上。

### 1.2 web-transport 仓库（d4e4e458）crate 清单

`/work/build/rtx-b4-upstream/web-transport/Cargo.toml` workspace 成员及分工：

| crate | 提供什么 | 证据 |
| --- | --- | --- |
| `web-transport-proto` | **纯 wire codec**（不依赖 quinn）：H3 SETTINGS、扩展 CONNECT、QPACK 静态表子集、H3 帧/单向流类型、WT capsule、H3 错误码空间、varint | `rs/web-transport-proto/src/lib.rs:1-20`（模块 capsule/connect/error/frame/settings/stream/varint/huffman/qpack） |
| `web-transport-quinn` | 在 quinn 0.11（crates.io）上的**单会话 WT 实现**：Client/Server/Session、H3 握手时序、流头与 DATAGRAM 会话前缀、close capsule 流程 | `rs/web-transport-quinn/src/lib.rs:20-24`（Limitations：只做单会话、独占 QUIC 连接） |
| `web-transport-trait` | 泛型 `Session`/`SendStream`/`RecvStream`/`Error`/`Stats` trait | `rs/web-transport-trait/src/lib.rs:79-141` |
| `web-transport` | umbrella：native 走 quinn、wasm 走浏览器 | `rs/web-transport/src/lib.rs:1-17` |
| `qmux` | **moq 相关**：`draft-ietf-quic-qmux-02`（可靠传输上的 QMux 复用，自带 ALPN 表 `qmux-02/01/00`、legacy `webtransport` ALPN），与 H3 CONNECT 路径无关 | `rs/qmux/Cargo.toml:3`、`rs/qmux/src/alpn.rs:1-25` |
| `web-transport-noq` / `-iroh` / `-quiche` / `-node` / `-wasm` / `-ffi` | 其他后端/绑定（Noq = quinn fork 等），与本探查无关 | 各 `Cargo.toml` description |

**interop 可用的只有 `web-transport-proto`**：`interop/m3/quinn/Cargo.toml` dev-deps 声明了
`web-transport-proto`（git rev d4e4e458…）与 `quinn`（git rev 9d729c1…），未声明 `web-transport-quinn`。
且 `web-transport-quinn` 依赖 **crates.io 的 quinn 0.11**（`rs/web-transport-quinn/Cargo.toml:26-30`），
与 interop 钉死的 **git quinn 0.12.0** 是两个不同 source 的包、类型不互通；其握手内部类型
`Connecting/Connected/Settings` 也**不是公开 API**（`rs/web-transport-quinn/src/lib.rs:44-51`：
`mod connect; mod settings;` 私有，仅 `pub use connect::ConnectError`）。
⇒ quinn 侧 H3 报文只能在测试里用 `web-transport-proto` codec + git quinn 手工驱动（详见第 5 节卡点 B1）。

### 1.3 web-transport-proto：wire 级结论（路径均在 `rs/web-transport-proto/src/`）

**SETTINGS（settings.rs）**
- 常量表（:69-86）：`ENABLE_CONNECT_PROTOCOL = 0x8`、`ENABLE_DATAGRAM = 0x33`、
  `ENABLE_DATAGRAM_DEPRECATED = 0xFFD277`（"still used by Chrome"）、
  `WEBTRANSPORT_ENABLE_DEPRECATED = 0x2b603742`、`WEBTRANSPORT_MAX_SESSIONS_DEPRECATED = 0x2b603743`（draft 06 移除）、
  `WEBTRANSPORT_MAX_SESSIONS = 0xc671706a`（"New way"）。
- `pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, SettingsError>`（:121，要求流首 varint 为 `StreamUni::CONTROL`、帧类型 `Frame::SETTINGS`；GREASE 设置项丢弃 :138-140）。
- `pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Self, SettingsError>`（:147，逐帧读、跳过 GREASE 帧 :174-180、`MAX_FRAME_SIZE = 65536` 上限 frame.rs:64）。
- `pub fn encode<B: BufMut>(&self, buf: &mut B)`（:207，写 `CONTROL 流类型 + SETTINGS 帧 + 长度 + id/value 对`）。
- `pub fn enable_webtransport(&mut self, max_sessions: u32)`（:231-242）：置
  `0x08=1, 0x33=1, 0xffd277=1, 0xc671706a=max, 0x2b603743=max, 0x2b603742=1`（新旧两代全发）。
- `pub fn supports_webtransport(&self) -> u64`（:245-285）判定口径：
  先要 `(0x33 ∨ 0xffd277) == 1`，再看 `0xc671706a`（非零即启用，返回其值）；
  否则回退 legacy：`0x2b603742 == 1` 时返回 `0x2b603743` 的值（缺省按 1）。

**扩展 CONNECT（connect.rs）**
- `pub struct ConnectRequest { pub url: Url, pub protocols: Vec<String>, pub headers: http::HeaderMap }`（:88-97）。
- `pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), ConnectError>`（:205-244）：写 `HEADERS 帧(0x01)`，
  QPACK 字段为 `:method=CONNECT, :scheme, :authority, :path(含 query), :protocol=webtransport`（:219-227），
  可选 `wt-available-protocols`（:229-232，RFC 8941 列表，头名常量 :430）。
- `pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Self, ConnectError>`（:200-203，经
  `read_headers_frame` :379-418 跳 GREASE 帧）。
- 解码校验（`decode_headers` :137-197）：`:scheme` 必须 `https`（:140-144）、`:authority`/`:path` 必需（:146-150）、
  `:method` 必须 `CONNECT`（:152-159）、`:protocol` 必须 `webtransport`（:161-164）。
- `pub struct ConnectResponse { pub status: http::status::StatusCode, pub protocol: Option<String> }`（:267-273）、
  `pub const OK`（:276-279）。
- `ConnectResponse::encode`（:331-351）：`:status` + **`sec-webtransport-http3-draft: draft02`**（:334，legacy draft-02 标记），
  可选 `wt-protocol`（:336-339，常量 :432）。`decode_headers`（:302-323）只要求 `:status` 为 success（:305-314）。

**流/帧类型与 capsule**
- 单向流类型（stream.rs:39-45）：`CONTROL = 0x00, PUSH = 0x01, QPACK_ENCODER = 0x02, QPACK_DECODER = 0x03, WEBTRANSPORT = 0x54`。
- 帧类型（frame.rs:67-72）：`DATA = 0x00, HEADERS = 0x01, SETTINGS = 0x04, WEBTRANSPORT = 0x41`；`Frame::read`（:30-48）跳过 GREASE 帧。
- capsule（capsule.rs）：`CLOSE_WEBTRANSPORT_SESSION_TYPE = 0x2843`（:9，注明 draft-ietf-webtrans-http3-06）；
  `pub enum Capsule { CloseWebTransportSession { code: u32, reason: String }, Grease{..}, Unknown{..} }`（:12-16）；
  decode 读 `u32 code + 余下字节按 UTF-8`（:43-64）。**没有 `WT_DRAIN_SESSION(0x78AE)`**——会落成 `Unknown`。
- H3 错误码空间（error.rs）：`ERROR_FIRST = 0x52e4a40fa8db`、`ERROR_LAST = 0x52e5ac983162`（:2-3）；
  `pub const fn error_from_http3(code: u64) -> Option<u32>`（:5）、`pub const fn error_to_http3(code: u32) -> u64`（:16）。
- QPACK（qpack.rs）：`pub struct Headers { pub fields: HashMap<String,String> }`（:41）；只支持**静态表 + 字面量**、
  明确拒绝动态表引用（:1-3 注释、decode :54-107 对 `0b10xx/0b0100/0b0001/0b0000` 返回 `DynamicEntry`）；
  编码 `encode`（:166-185）先写 `00 00` 前缀（insert count / delta base 均 0，:168-169），**伪头排前**（:171-174），
  优先静态全匹配 index（:177-178 → `0xC0` 型 :187-196）、次选静态名引用 + 非 Huffman 值（:179-180 → `0x50` 型 :198-214）、
  否则全字面量非 Huffman（:181-183 → `0x20` 型 :216-235）；静态表 `PREDEFINED_HEADERS: [(&str,&str); 99]`（:518，RFC 9204）；
  `decode_string`（:313-333）H=0 走原始字节、H=1 走 Huffman 解码。

### 1.4 web-transport-quinn：会话建立时序（quinn 上怎么发 CONNECT）

路径均在 `rs/web-transport-quinn/src/`。这是**参考时序**（interop 不能直接引它，见 1.2，但它证明了
"web-transport-proto codec + quinn 裸流"足以驱动完整 WT 握手）：

- ALPN：`pub const ALPN: &str = "h3"`（lib.rs:54）；client 在 rustls 配置里写死（client.rs:159）、server 同（server.rs:86）。
- **客户端**：`Client::connect(&self, request: impl Into<ConnectRequest>) -> Result<Session, ClientError>`（client.rs:229-271）
  = QUIC 连接（`endpoint.connect_with`）→ `Session::connect(conn, request)`（session.rs:237-254）：
  1. `Settings::connect(&conn)`（settings.rs:37-44）——`try_join!` **并发**做两件事：
     `open`：`conn.open_uni()` 后立即写己方 SETTINGS（`Settings::default() + enable_webtransport(1)`，settings.rs:59-69）；
     `accept`：`conn.accept_uni()` 取**第一条**对端单向流，`web_transport_proto::Settings::read` 解析（settings.rs:46-57），
     `supports_webtransport() == 0` 即报 `SettingsError::WebTransportUnsupported`（:52-54）。
  2. `Connected::open(&conn, request)`（connect.rs:115-148）：`conn.open_bi()` → `ConnectRequest::write`（HEADERS 帧）→
     `ConnectResponse::read` → 非 200 报 `ConnectError::ErrorStatus`（:131-133）。
  3. `Session::new(conn, settings, connect)`（session.rs:129-179）。
- **服务端**：`Server::accept(&mut self) -> Option<Request>`（server.rs:122-139）→
  `Request::accept(conn)`（server.rs:151-164）= `Settings::connect`（与客户端同一函数：也先发己方 SETTINGS、
  读对端 SETTINGS）→ `Connecting::accept(&conn)`（connect.rs:42-56：`conn.accept_bi()` + `ConnectRequest::read`）；
  然后 `Request::ok()/respond()/reject(status)`（server.rs:166-186）写回 `ConnectResponse`（connect.rs:59-87）得到 `Session`。
- **SETTINGS 交换顺序**：无严格先后——两侧都是"握手完成后立刻并发地开自己的控制流 + 读对端控制流"。
  隐含约束：`accept_uni` 拿到的**第一条**单向流必须是对端控制流（settings.rs:47-48），
  所以控制流必须是每条连接上第一条被打开的单向流；两侧都**不开 QPACK encoder/decoder 流**
  （若对端开了，`SessionAccept` 只 hold 住不关：session.rs:712-715、:834-839）。
- **会话 ID**：= CONNECT 所在双向流的 QUIC stream ID。`Connected::session_id(&self) -> VarInt`
  （connect.rs:151-156：`self.send.id()` 原值）。

### 1.5 会话流与 DATAGRAM 怎么对应（web-transport-quinn，session.rs）

`Session::new` 缓存三种前缀（session.rs:133-143）：
- 单向 WT 流：`varint(0x54 StreamUni::WEBTRANSPORT) + varint(session_id)`（:134-136；`open_uni` :290-298 → :1072-1092 写前缀）。
- 双向 WT 流：`varint(0x41 Frame::WEBTRANSPORT) + varint(session_id)`（:138-140；`open_bi` :301-309 → :1094-1115）。
- DATAGRAM：`varint(session_id)` 前缀 + 载荷（:142-143；`send_datagram` :324-341、`read_datagram` :316-318 → :1157-1180
  校验并剥掉前缀，不匹配报 `WebTransportError::UnknownSession`）。
  **注意：这里的前缀是完整 stream ID（session_id 原值），不是 RFC 9298 的 quarter stream ID**——
  整个 web-transport checkout grep `quarter` 零命中（探查命令见第 5 节 B2）。
- 接收侧流头校验：`SessionAccept::decode_uni`（:849-866，读 `0x54` 后校验 session_id）、
  `decode_bi`（:921-939，读帧类型必须 `0x41` + 校验 session_id）。

### 1.6 关闭/reset 怎么表达（web-transport-quinn）

- 会话关闭 `Session::close(&self, code: u32, reason: &[u8])`（session.rs:397-428）：
  在 CONNECT 流上把 `Capsule::CloseWebTransportSession{code,reason}` **包进 H3 DATA 帧**写出
  （`close_with_capsule` :432-486：`Frame::DATA + len + capsule`，引 RFC 9297 §3.2 注释 :443-445）→ `finish()` →
  等对端关连接（超时 max(3*rtt, 100ms) 后强制）→ `conn.close(error_to_http3(code), ...)`。
- 接收方向：后台任务 `run_recv`/`read_capsules`（session.rs:183-233）从 CONNECT recv 流读 capsule；
  收到 `CloseWebTransportSession` → 记录 `WebTransportError::Closed(code, reason)` 并 `conn.close(http3_code)`；
  流被 FIN 而无 capsule → 视为 `LocallyClosed` 同样关连接。
- 流级 reset/stop：`SendStream::reset(code: u32)`（send.rs:66-71）经 `encode_stream_code(code, raw)`
  把应用码映射进 H3 码空间（error.rs:138-144：`error_to_http3`）；对端码经 `decode_stream_code`（error.rs:146-156）还原。
  连接级错误同样经 `error_from_http3` 还原（error.rs:53-66）。

---

## 2. rtx 侧：如何回应 H3 CONNECT / WebTransport 会话（问题 2）

### 2.1 rtx-h3（`crates/rtx-h3/`，no_std 纯 codec，无连接/流状态机：src/lib.rs:3-18）

**SETTINGS（src/settings.rs）**
- 常量：`SETTINGS_QPACK_MAX_TABLE_CAPACITY=0x01`（:70）、`SETTINGS_MAX_FIELD_SECTION_SIZE=0x06`（:73）、
  `SETTINGS_QPACK_BLOCKED_STREAMS=0x07`（:76）、`SETTINGS_ENABLE_CONNECT_PROTOCOL=0x08`（:79）、
  `SETTINGS_H3_DATAGRAM=0x33`（:82）、`SETTINGS_H3_DATAGRAM_DEPRECATED=0xFF_D277`（:89）、
  `SETTINGS_WEBTRANSPORT_ENABLE_DEPRECATED=0x2B60_3742`（:96）、`SETTINGS_WEBTRANSPORT_MAX_SESSIONS=0xC671_706A`（:106）。
  **注意：没有 `0x2b603743`（legacy MAX_SESSIONS）常量**——该 id 会按"未知 id 原样存储"处理（:166-167 文档、decode :175-193）。
- **legacy `0x2b603742` 处理口径**：decode-only。`ENCODABLE` 白名单只含
  `[0x01,0x06,0x07,0x08,0x33,0xc671706a]`（:116-123）；`set()` 对非白名单返回 `SettingError::NotEncodable`（:202-212）、
  `encode()` 跳过非白名单项（:299-309）；解码侧保留 legacy 值供查询：
  `pub fn deprecated_webtransport_enable(&self) -> Option<u64>`（:278-280）、`pub fn deprecated_h3_datagram(&self) -> Option<u64>`（:271-273）。
  文档口径（:18-27）："Chrome 仍会发 legacy，故解码接受、编码拒发"。
  `0xc671706a` 的出处考证在模块文档 :29-42（draft-07 §8.2 至 -12；-15 改为 `SETTINGS_WT_ENABLED 0x2c7cf000`，本 crate 未实现 -15 口径）。
- 关键签名：`pub fn decode(payload: &[u8]) -> Result<Self, SettingError>`（:175，重复 id → `DuplicateSetting` :184-186；
  超过 `MAX_SETTINGS_ITEMS=32`（:113）→ `TooManySettings`）；`pub fn encode(&self, output: &mut [u8]) -> Result<usize, SettingError>`（:299）；
  `pub fn encoded_len(&self) -> usize`（:284）；`pub fn set(&mut self, id: u64, value: u64) -> Result<(), SettingError>`（:202）。
  **帧头（0x04）与流类型（0x00 CONTROL）不在本 crate**：载荷级 codec，帧头用 `rtx_wire::h3_frame::Frame`（:5-7 文档）。
- Chrome 实捕 fixture 已证解码：`crates/rtx-h3/tests/fixtures/chrome-settings.bin`（43B，SHA-256 见 tests/settings.rs:9-13）
  含 `0x01,0x06,0x07,0x33,0xffd277,0x2b603742` + 1 个 GREASE（tests/settings.rs:15-19、44-51 模块文档）。

**CONNECT（src/connect.rs）**
- `pub struct ConnectRequest<'a>`（:93-98，四字段借用表示，不依赖 url）；
  `pub const fn new(scheme, authority, path, protocol) -> Self`（:103-115）；
  `pub fn decode(encoded: &[u8], buffers: ConnectBuffers<'a>) -> Result<Self, ConnectError>`（:157-207）：
  要求 `:method==CONNECT`（:175-182，否则 `NotConnect`）、`:scheme/:authority/:path/:protocol` 全必需（:183-199，缺 → `MissingPseudoHeader`）、
  伪头必须全部在普通字段之前（:171-174 `PseudoHeaderAfterField`）、重复伪头拒绝（`DuplicatePseudoHeader`）；
  **不校验 `:protocol` 的值**（:87-91 文档：是否接受 `webtransport` 是服务端策略）；普通字段（如
  `sec-webtransport-http3-draft02`、`origin`）允许出现并被跳过（:194-196）。
- `pub fn encode(&self, output: &mut [u8]) -> Result<usize, ConnectError>`（:214-216）：字段固定为
  `[:method CONNECT, :scheme, :authority, :path, :protocol]`（`fields()` :224-232）。
- `pub struct ConnectBuffers<'a>`（:56-65，caller-owned 存储，`MAX_FIELD_LINE_LEN=1024` :52）。
- 响应：`pub struct ConnectResponse`（:241-244）；`pub fn new(status: u16) -> Result<Self, ConnectError>`（:252-260，100..=599）；
  `pub fn decode(encoded: &[u8]) -> Result<Self, ConnectError>`（:285-309，只要求 `:status`，其他伪头 → `UnexpectedPseudoHeader`，
  普通字段允许）；`pub fn encode(&self, output: &mut [u8]) -> Result<usize, ConnectError>`（:316-319，**只写 `:status`**，
  不发 `sec-webtransport-http3-draft` 头）；`pub const fn status(self) -> u16`（:264）、`pub fn is_success(self) -> bool`（:270-272）。
- Chrome 实捕 fixture：`crates/rtx-h3/tests/fixtures/chrome-connect.bin`（90B）解码出的 7 个字段及顺序
  （`:scheme` 在 `:method` 前，RFC 9114 允许）见 src/connect.rs:11-38 与 tests/connect.rs:47-60。

**QPACK（src/qpack.rs）**
- `pub const MAX_FIELD_LINES: usize = 64`（:41）；`pub const STATIC_TABLE: [(&str, &str); 99]`（:44，RFC 9204，
  首 16 项与 web-transport-proto `PREDEFINED_HEADERS`（qpack.rs:518）逐项一致，含 `(:method, CONNECT)` 索引 15）。
- `pub struct FieldSection<'a>`（:244）；`pub fn new(input: &'a [u8]) -> Result<Self, QpackError>`（:261-283，
  **只接受 Required Insert Count=0 且 Delta Base=0**，否则 `DynamicTableNotSupported`）；
  `pub fn next_field<'s>(&mut self, scratch: &'s mut [u8]) -> Result<Option<Field<'s>>, QpackError>`（:293-338，
  支持三种表示：静态 index `0xC0`、静态名引用+字面量值 `0x50`、全字面量 `0x20`；`0x80/0x40/0x10/0x00` 型动态表引用全部拒绝；
  Huffman 与非 Huffman 字符串都能解（`read_string` :361-389 + `huffman_decode` :495-540））。
- `pub fn encode_fields(fields: &[FieldLine<'_>], output: &mut [u8]) -> Result<usize, QpackError>`（:402-417，
  写 `00 00` 前缀；每行优先静态全匹配 → 静态名引用 → 全字面量，**只发非 Huffman**，`encode_field` :541-570）；
  `pub fn fields_encoded_len(...) -> usize`（:421）；
  `pub fn ensure_dynamic_table_disabled(settings: &Settings) -> Result<(), QpackError>`（:441-449，
  要求 `0x01` 与 `0x07` 缺省或为 0）。

### 2.2 rtx-webtransport（`crates/rtx-webtransport/`，capsule/DATAGRAM/ID 层，src/lib.rs:3-27）

- `ids.rs`：`pub struct SessionId(u64)`（:66）；`pub const fn new(connect_stream_id: u64) -> Result<Self, IdError>`
  （:76-84，要求低 2 位为 `00` 即 client-initiated bi）；`pub const fn quarter(self) -> QuarterStreamId`（:97-99，`>> 2`）；
  `pub struct QuarterStreamId(u64)`（:104）+ `from_stream_id`（:130-138）。
- `datagram.rs`：`pub fn decode(input: &[u8], session: SessionId, max_len: usize) -> Result<(Datagram<'_>, usize), DatagramError>`
  （:67-87）与 `pub fn encode(session: SessionId, payload: &[u8], max_len: usize, output: &mut [u8]) -> Result<usize, DatagramError>`
  （:100-120）。**前缀 = quarter stream ID**（RFC 9298 §2.1 / draft-15 §4.5，模块文档 :1-13；校验 :75-79 `WrongSession`）。
- `capsules.rs`：`pub const WT_CLOSE_SESSION: u64 = 0x2843`（:40）、`WT_DRAIN_SESSION = 0x78AE`（:43）、
  `WT_STREAM_NO_FIN/FIN = 0x190B_4D3C/3B`（:47/:51，H2 变体，H3 互操作用不到）、`MAX_CLOSE_MESSAGE_LEN = 1024`（:55）；
  `pub enum Capsule<'a> { CloseSession { code: u32, message: &'a str }, DrainSession, Stream{..}, Unknown{..} }`（:78-104）；
  `pub fn decode(input: &'a [u8], max_len: usize) -> Result<(Self, usize), CapsuleError>`（:119-136）；
  `CloseSession` payload = `u32 大端 code + UTF-8 message`（:148，framing() 与 web-transport-proto capsule.rs:43-64 的读法一致）。
- **缺口**：本 crate 与 rtx-h3 都没有 WT 流头（`0x54`/`0x41` + Session ID）codec，也没有 H3 流类型/帧类型常量
  （grep `0x54|0x41|WEBTRANSPORT` 于两 crate src 无命中；见卡点 B2/B4）。

### 2.3 底座：rtx-wire 与 rtx-quic

- `rtx-wire/src/h3_frame.rs`：`pub struct Frame<'a>`（:17，varint 类型 + varint 长度 + 借用载荷）；
  `Decode::decode(input) -> Result<(Self, usize), WireError>`（:45-64）、`Encode::encode(&self, output) -> Result<usize, WireError>`（:66-87）。
  帧类型值由调用方给（rtx-h3 tests/settings.rs:47-57 已示范手写 `0x04`）。
- `rtx-wire/src/varint.rs`：`MAX_VARINT`（:26）、`encoded_len`（:32）、`decode`（:53）、`encode`（:73）、`VarInt::new/get`（:100/:109）。
- `rtx-quic/src/endpoint.rs`（H3 测试要驱动的 API）：`new(EndpointConfig)`（:111）、`accept`（:201）、
  `handle_datagram`（:276）、`poll_event/poll_transmit/poll_timeout/handle_timeout`（:324/:340/:379/:393）、
  `open_uni/open_bi`（:413/:425）、`accept_uni/accept_bi -> Result<Option<StreamId>, StreamError>`（:436/:450）、
  `write_stream`（:465）、`read_stream`（:503）、`finish_stream`（:555）、`reset_stream`（:585）、`stop_sending`（:619）、
  `send_datagram`（:654）、`poll_datagram`（:689）、`close`（:719）。
  QUIC 层 10 项测试已用其中握手/流/DATAGRAM 子集跑通（QUIC-LAYER-INTERIM.md §2）。

---

## 3. 两者对接的 API 触点清单（问题 3）

1. **ALPN 与 QUIC 握手（复用，已证）**：ALPN `h3` 正反向握手 = QUIC 层测试 #3/#7
   （`interop/m3/quinn/tests/loopback_handshake.rs`、`reverse_loopback_handshake.rs`）；
   与 web-transport-quinn 的 `ALPN = "h3"`（lib.rs:54）一致。H3 测试直接复用同一 rcgen 证书 +
   `EndpointConfig::with_alpn(vec![b"h3".to_vec()])` + quinn rustls-ring 客户端骨架（`tests/bi_stream_once.rs:45-78`）。
2. **控制流 + SETTINGS（谁先发什么）**：握手完成后**双方各自**：
   (a) `open_uni` 第一条单向流，写 `varint(0x00 CONTROL)` + `Frame(0x04 SETTINGS)`；
   (b) `accept_uni` 读对端第一条单向流并按同格式解析。无先后顺序要求
   （web-transport-quinn 用 `try_join!` 并发：settings.rs:37-44），但**第一条单向流必须是控制流**（settings.rs:47-48）。
   - quinn 侧值：`Settings::default() + enable_webtransport(1)` → `0x08=1, 0x33=1, 0xffd277=1, 0xc671706a=1, 0x2b603743=1, 0x2b603742=1`（proto settings.rs:231-242）。
   - rtx 侧回值须满足对端 `supports_webtransport() != 0`（proto settings.rs:245-285）：
     `0x33=1`（或 legacy `0xffd277=1`）且 `0xc671706a>0`（或 legacy `0x2b603742=1`）。
     rtx-h3 用白名单组合 `0x08=1, 0x33=1, 0xc671706a=1` 即可满足（ENCODABLE settings.rs:116-123），**无需发任何 legacy 值**。
   - rtx 解码 quinn 侧 SETTINGS：6 个 id 均可入 `Settings::decode`（legacy `0xffd277/0x2b603742` 有专门访问器，
     `0x2b603743` 按未知 id 原样存储不报错；无重复 id，≤32 项上限）。
   - QPACK 动态表：两侧都是"静态表 + 字面量"零动态表 profile（1.3/2.1），`0x01/0x07` 均缺省或 0，
     `ensure_dynamic_table_disabled`（rtx qpack.rs:441）与 proto 前缀 `00 00`（proto qpack.rs:168-169）互认；
     **双方都不开 QPACK encoder/decoder 流**。
3. **CONNECT 方法与路径**：客户端 `open_bi` → 写 `Frame(0x01 HEADERS)` + QPACK 段
   `{:method CONNECT, :scheme https, :authority host:port, :path /…, :protocol webtransport}`
   （proto connect.rs:205-244 / rtx connect.rs:214-232 两种编码器输出同一字段集）；
   服务端 `accept_bi` → 解请求（rtx `ConnectRequest::decode` connect.rs:157 / proto `ConnectRequest::read` connect.rs:200）→
   回 `Frame(0x01)` + `{:status 200}`（rtx `ConnectResponse::encode` connect.rs:316；proto 版还会带
   `sec-webtransport-http3-draft: draft02` connect.rs:334，rtx 解码器把普通字段跳过，兼容）。
   路径/authority 取值自由（fixture 用 `https://127.0.0.1:4433/session`，rtx connect.rs:20-26）。
4. **会话 ID**：= CONNECT 双向流的 stream ID（proto 侧 wt-quinn connect.rs:151-156；rtx 侧
   `SessionId::new(connect_stream_id)` ids.rs:76-84，首条 client-initiated bi 流 ID=0，低 2 位校验通过）。
5. **会话流对应**（进入数据面时才需要）：
   - WT 单向流：`varint(0x54) + varint(session_id)` 前缀（proto stream.rs:44 + wt-quinn session.rs:134-136）；
   - WT 双向流：`varint(0x41) + varint(session_id)` 前缀（proto frame.rs:71 + wt-quinn session.rs:138-140）；
   - rtx 侧无此 codec（B2），测试需用 `rtx_wire::varint` 手工构帧/解帧。
6. **DATAGRAM 对应**：quinn 侧 = `varint(session_id 完整值)` + 载荷（wt-quinn session.rs:142-143/:324-341/:1157-1180）；
   rtx 侧 = `varint(quarter stream id)` + 载荷（rtx datagram.rs:67-120 + ids.rs:97-99）。
   **两者口径冲突**，仅当 CONNECT 流 ID=0 时编码巧合一致（varint 0）；ID≥4 分叉（4 vs 1）。见卡点 B2。
   QUIC 传输层 DATAGRAM 协商（`max_datagram_frame_size`）已由 #4/#8 双向验证；quinn 接收缓冲默认开启
   （quinn-proto transport.rs:405），rtx-quic `send_datagram/poll_datagram`（endpoint.rs:654/:689）已用过。
7. **关闭/reset 表达**：
   - 会话级：CONNECT 流上 `Frame(0x00 DATA){ capsule 0x2843: u32 code + UTF-8 reason }` → FIN →
     连接 `close(error_to_http3(code))`（wt-quinn session.rs:397-486）。
     rtx 对应物：`rtx_webtransport::capsules::Capsule::CloseSession`（type 0x2843、payload 同构，capsules.rs:40/:78-104/:148），
     DATA 帧包装用 `rtx_wire::h3_frame::Frame`；**H3 错误码空间映射 rtx 侧没有**，可直接调
     `web_transport_proto::error_to_http3/error_from_http3`（已是 dev-dep；proto error.rs:5/:16）。
   - `WT_DRAIN_SESSION(0x78AE)`：rtx 有（capsules.rs:43），proto 侧无此类型 → 落 `Unknown` 并被忽略
     （wt-quinn session.rs:223-225），不构成冲突。
   - 流级：quinn 侧 reset/stop 码经 `encode_stream_code` 进 H3 码空间（wt-quinn error.rs:138-156）；
     rtx 侧 `reset_stream/stop_sending/close` 用裸码（endpoint.rs:585/:619/:719），映射同样落在测试/胶水层。

---

## 4. 第一个最小 H3 握手测试的步骤草图（问题 4，只画步骤，不写文件）

**范围**：正向一条——quinn 客户端（测试内用 `web-transport-proto` codec 手工驱动）↔ rtx-quic 服务端
（rtx-h3 codec）。只做 SETTINGS + CONNECT + 200，**不碰 DATAGRAM、不开 WT 数据流、不测关闭**（避开 B2/B3）。

1. **建连**（复用 `tests/bi_stream_once.rs:45-98` 骨架）：rcgen 自签证书；rtx `EndpointConfig::with_alpn(h3)` +
   server identity；quinn `ClientConfig`（rustls-ring，ALPN h3，root=自签证书）；`127.0.0.1:0` UDP + 泵循环
   （poll_transmit/handle_datagram/poll_timeout/poll_event）。等双方 HandshakeComplete / `Connecting` resolve。
2. **客户端发 SETTINGS**：quinn `conn.open_uni()` → 写
   `web_transport_proto::Settings::default() + enable_webtransport(1)` 的 `write()` 输出
   （即 `0x00 + Frame(0x04) + 6 个 id/value`；proto settings.rs:207-229）。
3. **服务端收 SETTINGS**：rtx 泵循环 `accept_uni(cid)` 得到首条单向流 → `read_stream` 累积字节 →
   测试侧解 `varint(0x00)`（CONTROL，常量测试自定义）→ `rtx_wire::h3_frame::Frame::decode` 得 type=0x04 →
   `rtx_h3::settings::Settings::decode(payload)`。
   **断言**：`enable_connect_protocol()==Some(1)`、`h3_datagram()==Some(1)`、`webtransport_max_sessions()==Some(1)`；
   legacy `deprecated_webtransport_enable()==Some(1)`、`deprecated_h3_datagram()==Some(1)`（记录口径，不作通过条件也可）。
4. **服务端回 SETTINGS**：rtx `open_uni(cid)` → 写 `varint(0x00)` + `Frame(0x04){ Settings: 0x08=1, 0x33=1, 0xc671706a=1 }`
   （`rtx_h3 Settings::set/encoded_len/encode`）。
5. **客户端读 SETTINGS**：quinn `conn.accept_uni()` → `web_transport_proto::Settings::read(&mut recv)`
   （quinn RecvStream 有 tokio AsyncRead，recv_stream.rs:531）。**断言** `supports_webtransport() != 0`。
6. **客户端发 CONNECT**：`conn.open_bi()` → `ConnectRequest::new(Url::parse("https://localhost/session"))` 的
   `write()`（HEADERS 帧，5 个伪头）。
7. **服务端收 CONNECT**：rtx `accept_bi(cid)` → 读齐 `Frame(0x01)` → `rtx_h3::connect::ConnectRequest::decode(payload, ConnectBuffers)`。
   **断言**：`scheme()=="https"`、`authority()=="localhost"`（以测试 URL 为准）、`path()=="/session"`、`protocol()=="webtransport"`；
   `rtx_webtransport::ids::SessionId::new(connect_stream_id.get())` 成功（ID 低 2 位=00）。
8. **服务端回 200**：同一 bi 流 `write_stream` 写 `Frame(0x01){ ConnectResponse::new(200)?.encode() }`（可选 `finish_stream` 之前保留流——
   真实 WT 会话中 CONNECT 流要保持打开承载 capsule；最小测试可只写不 finish）。
9. **客户端收响应**：`web_transport_proto::ConnectResponse::read(&mut recv)`。**断言** `status == 200`。
10. **收尾**：双方 `close`，泵循环退出；总超时沿用 10s 模式。

反向测试（rtx 客户端 → quinn 服务端）为上述 2-9 的角色互换：quinn 服务端用 proto codec 走
`Settings::connect`+`Connecting::accept`+`respond(OK)` 的等价手工时序（1.4 服务端一节），rtx 客户端用
rtx-h3 编码器构造 SETTINGS/CONNECT。第一个测试可只做正向。

---

## 5. 卡点（问题 5：只汇报 + 证据，不写实现）

**B1（第一个测试的直接前置）：interop crate 缺 rtx 侧 H3 依赖，且 web-transport-quinn 不可用作替代。**
- `interop/m3/quinn/Cargo.toml`：deps 只有 `rtx-quic/rtx-core/bytes/tokio/rcgen/sha2/hex`；dev-deps 只有
  `quinn(git 9d729c1)/web-transport-proto(git d4e4e458)/tokio/url`。**没有 `rtx-h3`（及其传递依赖 `rtx-wire`）、
  没有 `rtx-webtransport`** → 写 H3 测试前必须先改这份 Cargo.toml（本步不改）。
- 不能用 `web-transport-quinn` 高层 API 走捷径：(a) 它依赖 crates.io `quinn 0.11`
  （`rs/web-transport-quinn/Cargo.toml:26-30`），与 interop 钉死的 git `quinn 0.12.0`（Cargo.lock:433-435）
  是不同 source 的两个包，`quinn::Connection` 类型不互通；(b) 其握手内部件 `Connecting/Connected/Settings`
  非公开（lib.rs:44-51），公开面只有 `Client/Server/Session`，且要求启用其 `aws-lc-rs/ring` feature 自建 endpoint。
  ⇒ 结论：quinn 侧 H3 报文必须由测试用 `web-transport-proto`（纯 codec，无 quinn 依赖，proto Cargo.toml:15-23）
  + git quinn 手工驱动。这也是 Cargo.toml 里 `web-transport-proto` 声明的合理用法。

**B2（口径冲突，DATAGRAM；不阻塞最小握手）：datagram 会话前缀两种口径。**
- web-transport-quinn 前缀 = **完整 session ID**（CONNECT 流 stream ID 原值）：session.rs:142-143、
  send_datagram :324-341、read_datagram_owned :1157-1180；`Connected::session_id()` connect.rs:151-156。
- rtx-webtransport 前缀 = **quarter stream ID**（`stream_id >> 2`）：datagram.rs:4-7 文档 + decode :75-79 +
  encode :106-118；ids.rs:92-99。
- 证据：web-transport 整个 rs/ 目录 grep `quarter|Quarter` 零命中（探查命令：
  `grep -rn "quarter\|Quarter" rs/web-transport-proto/src rs/web-transport-quinn/src`）。
- 影响：CONNECT 流 ID=0（单会话首流）时两侧都编码 varint 0，**最小握手+单会话 datagram 测试不会暴露分歧**；
  ID≥4（同连接第二个 bi 流）时 quinn 发 4、rtx 期望 1，互判 `WrongSession`/`UnknownSession`。
- 这是 draft 代际差异（wt-quinn 响应头自带 `sec-webtransport-http3-draft: draft02`，proto connect.rs:334；
  rtx 跟 draft-15/RFC 9298，ids.rs:1-2、datagram.rs:1-2）。**做 datagram 互操作测试前必须先裁决口径**
  （限定 ID=0 单会话，或其中一侧改帧格式）；本步只汇报，不裁决、不实现。

**B3（实现缺口，WT 数据流；不阻塞最小握手）：rtx 侧没有 WT 流头 codec。**
- `0x54`（uni）/`0x41`（bi）+ session ID 前缀在 rtx-h3 与 rtx-webtransport 中均无常量/编解码
  （grep 无命中；rtx-webtransport 只有 ids/capsules/datagram 三模块，lib.rs:29-31）。
- 测试侧可用 `rtx_wire::varint::encode/decode` 手工构帧（等价于 wt-quinn session.rs:133-143 的行为），
  但这属于测试内私有逻辑；是否沉淀进 rtx-webtransport 是后续实现决策。

**B4（小缺口，注意项）：rtx 侧无 H3 流类型/帧类型常量、无 H3 错误码空间映射。**
- `CONTROL=0x00`、`SETTINGS=0x04`、`HEADERS=0x01`、`DATA=0x00` 等常量不在 rtx-h3/rtx-wire
  （rtx-h3 tests/settings.rs:47-57 已有"测试手写 0x04"的先例）；`error_to_http3` 等价物 rtx 侧没有，
  但 `web_transport_proto::error_to_http3/error_from_http3`（proto error.rs:5/:16）已在 dev-deps 里可直接用。
  仅影响关闭/reset 类测试，不影响最小握手。

**B5（时序约束，非缺失）：控制流必须是每条连接的第一条单向流。**
- wt-quinn `Settings::accept` 直接把 `conn.accept_uni()` 的第一条流当控制流读 SETTINGS（settings.rs:46-56）；
  若 rtx 侧驱动先开了别的单向流，会被当成控制流解析而失败。rtx 侧测试驱动同样应假设收到的第一条 uni 流
  是控制流（wt-quinn 除控制流外不开任何 uni 流——QPACK 流不开，见 1.4）。最小握手测试天然满足。

---

## 6. 结论

**H3 握手对接：可行。** 证据链（全部有文件+行号，见上文）：
1. ALPN `h3` 的 QUIC 握手已双向跑通（QUIC 层 #3/#7），H3 层完全复用该建连骨架。
2. QPACK 两侧是同一"静态表(99 项)+字面量、零动态表、前缀 00 00、非 Huffman 可互解"的 profile，
   三种字段行表示双向兼容（proto qpack.rs:54-235 ↔ rtx qpack.rs:261-389/:541-570）。
3. SETTINGS：quinn 侧 `enable_webtransport(1)` 发出的 6 项（含 legacy 0x2b603742/0xffd277/0x2b603743）
   rtx-h3 全部可解码（legacy 明确 decode-only）；rtx 侧用白名单 `0x08+0x33+0xc671706a` 编码即可让
   `supports_webtransport()` 判非零。判定口径两侧文档互证。
4. CONNECT：两侧编解码的伪头集合一致（`:method CONNECT/:scheme https/:authority/:path/:protocol webtransport`
   ↔ `:status`），rtx 解码容忍 proto 附带的 `sec-webtransport-http3-draft: draft02` 普通字段，
   proto 解码不要求 rtx 发该字段。Chrome 实捕 fixture 已证 rtx 解码器对真实浏览器字节流可用。
5. 会话关闭 capsule 类型（0x2843）与 payload 结构（u32 + UTF-8）两侧一致。

**第一步最小测试（第 4 节草图）的阻塞点：**
- **唯一硬前置 = B1**：`interop/m3/quinn/Cargo.toml` 需先加入 `rtx-h3`（传递 `rtx-wire`）路径依赖
  （若同时要做 SessionId 断言，再加 `rtx-webtransport`）。这是下一步的第一动作，本步按约束不改。
- B2（datagram 前缀口径冲突）、B3（WT 流头 codec 缺失）不阻塞最小握手测试，但分别阻塞
  "datagram 会话测试（ID≥4 场景）"与"WT 数据流测试"，进入那些测试前必须先裁决/补齐。
- B4/B5 为注意项，不构成阻塞。

除 B1 外，最小 H3 握手测试无其他卡点。
