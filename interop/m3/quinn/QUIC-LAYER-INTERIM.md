# QUIC 层中期小结（QUIC-LAYER-INTERIM）

> **状态：中期小结，不是 B4 通过结论。**
> 本文件只覆盖 QUIC 层单项测试（第 1–10 步产物 + 第 11 步全量跑）。
> **H3/WebTransport 层尚未做；矩阵组装尚未做；正式互操作报告尚未做。**
> B4 是否通过以正式报告为准，本文件不构成任何通过判定。

## 1. 全量跑记录（第 11 步）

| 项 | 值 |
| --- | --- |
| 日期 | 2026-11-04T06:55Z 前后（单次全量跑） |
| 位置 | `interop/m3/quinn/`（未提交），分支 `b4/quinn-interop-evidence` |
| 基线 | `ea870b607aeb2db26f2096f686c9061612c04190`（主线 merge 提交） |
| 工具链 | rustc 1.98.1 (48a229cea 2026-09-01) / cargo 1.98.1，Linux 5.15.0-139-generic x86_64 |
| 命令 | `cargo test`（一次全量，覆盖 tests/ 全部 10 个文件；另含 `unittests src/main.rs`，0 个测试） |
| 编译 | 先 `cargo test --no-run` 预热（依赖已缓存，0.56s）；全量跑编译 0.06s |
| 结果 | **10 个集成测试全部通过，0 失败，0 忽略**；全量跑总墙钟约 0.50s |
| 带时间戳完整日志 | `/tmp/opencode/b4-step11-cargo-test.log`（临时文件，格式 `epoch_ms|原始行`） |

干扰检查：cargo 按顺序逐个执行测试二进制；每个测试各自绑定 `127.0.0.1:0` 临时端口，互不复用。全量跑 10 项全过、耗时与单项规模相符（libtest 自报 0.00–0.03s），未观察到互相干扰。

## 2. 逐项测试明细

耗时两列：`libtest` 为测试函数自报耗时（cargo 输出 `finished in`）；`墙钟` 为该测试二进制从启动到出结果的毫秒数（由带时间戳日志计算，含进程启动开销）。

| # | 步骤 | 测试文件 / 函数 | 方向 | Payload | 结果 | libtest | 墙钟 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | `endpoint_smoke.rs` / `rtx_quic_endpoint_creates` | 无网络（仅构造 rtx-quic endpoint） | — | ok | 0.00s | 33ms |
| 2 | 2 | `dual_endpoint_smoke.rs` / `dual_endpoints_create` | 无网络（rtx-quic 与 quinn endpoint 各自构造） | — | ok | 0.00s | 30ms |
| 3 | 3 | `loopback_handshake.rs` / `loopback_handshake` | quinn 客户端 → rtx-quic 服务端（ALPN `h3`） | 无应用载荷（仅握手建立连接） | ok | 0.02s | 40ms |
| 4 | 4 | `datagram_once.rs` / `datagram_once` | quinn 客户端 → rtx-quic 服务端，DATAGRAM | `datagram-once-payload` | ok | 0.02s | 42ms |
| 5 | 5 | `uni_stream_once.rs` / `uni_stream_once` | quinn 客户端 → rtx-quic 服务端，单向流 | `uni-stream-once-payload` | ok | 0.03s | 44ms |
| 6 | 6 | `bi_stream_once.rs` / `bi_stream_once` | quinn 客户端 ⇄ rtx-quic 服务端，双向流（请求+应答） | 请求 `bi-stream-once-payload`，应答 `bi-stream-once-response` | ok | 0.03s | 56ms |
| 7 | 7 | `reverse_loopback_handshake.rs` / `reverse_loopback_handshake` | rtx-quic 客户端 → quinn 服务端（ALPN `h3`） | 无应用载荷（仅握手建立连接） | ok | 0.02s | 40ms |
| 8 | 8 | `reverse_datagram_once.rs` / `reverse_datagram_once` | rtx-quic 客户端 → quinn 服务端，DATAGRAM | `reverse-datagram-once` | ok | 0.02s | 38ms |
| 9 | 9 | `reverse_uni_stream_once.rs` / `reverse_uni_stream_once` | rtx-quic 客户端 → quinn 服务端，单向流 | `reverse-uni-stream-once` | ok | 0.02s | 21ms |
| 10 | 10 | `reverse_bi_stream_once.rs` / `reverse_bi_stream_once` | rtx-quic 客户端 ⇄ quinn 服务端，双向流（请求+应答，客户端读到流结束） | 请求 `reverse-bi-stream-once`，应答 `reverse-bi-response` | ok | 0.02s | 19ms |

另：`unittests src/main.rs` 二进制含 0 个测试（`src/main.rs` 仅为占位 main），在全量跑中一并通过（无失败）。

## 3. 上游 revision

| 依赖 | 来源 | revision |
| --- | --- | --- |
| `quinn`（dev-dependency，features：`runtime-tokio`、`rustls-ring`） | `git+https://github.com/quinn-rs/quinn` | `9d729c1b6b7ad30d45d40265037eeeb9d98a7420` |
| `web-transport-proto`（dev-dependency） | `git+https://github.com/moq-dev/web-transport` | `d4e4e458da556ac3033c9b63f6db5110d3ab5adc` |

以上 revision 与 `Cargo.toml` 声明及 `Cargo.lock` 锁定值一致。注：`web-transport-proto` 目前仅为依赖声明，**尚未被任何测试引用**（H3/WebTransport 层测试未做）。

## 4. QUIC 层覆盖情况（截至本小结）

- 端点构造冒烟：rtx-quic 单端（#1）、rtx-quic + quinn 双端（#2）✔
- 正向（quinn → rtx-quic）：握手（#3）、DATAGRAM（#4）、单向流（#5）、双向流（#6）✔
- 反向（rtx-quic → quinn）：握手（#7）、DATAGRAM（#8）、单向流（#9）、双向流（#10）✔

QUIC 层单项至此已齐，且单次全量跑确认合在一起仍全过。

## 5. 尚未完成（明确声明）

- **H3/WebTransport 层：尚未做。** 本小结所有结果仅限 QUIC 传输层（握手、DATAGRAM、单向/双向流）。
- **矩阵组装：尚未做。** 尚无跨层/跨场景的组合矩阵。
- **正式互操作报告：尚未做。** B4 的通过与否以正式报告为准。
- 范围外（第 11 步明确不做）：多流并发、半关闭/reset。
- 本文件与 `interop/m3/quinn/` 全目录均处于未提交状态；本步不提交、不推分支、不开 PR。
