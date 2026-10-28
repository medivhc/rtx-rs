# RV-PR20 独立评审报告：rtx-rs PR #20（R6-1 quinn-proto 窄外观，M3-Q 代码单）

- **评审对象**：PR #20，`trae/agent-Nx43tj`，head `7feb7b22c42451726bce1ecfdf18dc3de4ce04f7`
- **评审基线**：`main` @ `4641cd5aed9ca375ac53b74061a68343197a5f5b`（P5-decision / PR #19 合并点）
- **评审方式**：全部结论由本人独立执行 `git` / `gh api` / `cargo` / 上游源码核对得出，未采信任务书转述的数值
- **合并基点核实**：`git merge-base 4641cd5 7feb7b2` = `4641cd5`（无漂移）；PR head 树 = `7feb7b2`，1 个 commit
- **评审环境**：Rust 1.92.0（另装 1.85.0 复核 MSRV）、`cargo-llvm-cov 0.9.1`、crates.io API、`gh` 2.45.0

---

## 一、结论

### **批准合并（0 阻塞项）**

R6-1 单元的验收边界——门禁 M3-0-1～M3-0-4 与 M3-Q0～M3-Q8 逐项有可复现证据、23 个门禁测试名与 `docs/m3-m4-gates.md` 逐字一致、diff 严格限于 25 个文件、版本差异书面记录真实可核查——全部独立复核通过。PR 描述 (a)(b)(c)(d) 四项齐全，无夸大、无越界塞项，无禁忌表述。

本单 **不合并**（PR 描述与任务书均声明「只建 PR，不合并」）；以下「建议合并」仅指**内容上具备合并条件**，实际合并动作与门禁勾选由协调者按流程在 xc 上执行。

---

## 二、验收逐项表

| # | 验收项 | 结论 | 证据（本人实测） |
|---|---|---|---|
| 1 | diff 范围 | **通过** | `git diff --shortstat 4641cd5 7feb7b2` = `25 files changed, 5699 insertions(+)`，与 `gh api .../pulls/20` 的 `changed_files=25 / additions=5699 / deletions=0` 一致；`--name-status` 显示 24 个 `A` + 1 个 `M`（根 `Cargo.toml`）；根 `Cargo.toml` diff 仅 +1 行成员；`git ls-tree -r 7feb7b2` 无 `examples/ benchmarks/ interop/ firmware/`，无 `.png/.jpg/.gif/.zip/.so` 等二进制，无 `.screenshots/`；`Cargo.lock` 为纯增量——与基线 `Cargo.lock` 包集合比对：**基线包无一被移除或降版**，新增 54 个包全部是 `quinn-proto`/`rustls`/`rcgen`/`time` 传递依赖，无既有成员解析版本被动改变 |
| 2 | M3-0-1 收录 + 版本固定 + 差异书面记录 | **通过** | `crates/rtx-quic/Cargo.toml:24` 声明 `quinn-proto = "=0.11.19"`；`Cargo.lock` 中 `quinn-proto 0.11.19` 带 checksum `0e750cca…`；`cargo tree -p rtx-quic -i quinn-proto --locked` 输出与归档 `measurements/m3/deps/quinn-tree.txt` **逐字节相同**；差异记录见 `src/lib.rs:121-152`（含上游 `9d729c1` 的 MSRV/edition/依赖事实，逐条已核实，见第 4 项） |
| 3 | M3-0-2 无 Tokio | **通过** | `cargo tree -p rtx-quic -e normal --locked` 全树（含 dev/build）`tokio` 计数 **0**；`cargo tree -p rtx-quic -e normal --locked` 与归档 `measurements/m3/deps/normal-tree.txt` 去除 ANSI 码后 **完全一致**（`diff` 无差异）；`Cargo.lock` 中 `name = "tokio"` 计数 0 |
| 4 | M3-0-3 公共外观清单 + 无上游类型泄漏 | **通过** | `src/lib.rs:27-101` 存在 `# 公共外观` 表（60 行，逐项列公开项 → 唯一消费者门禁 ID）；`grep` 全部 `pub fn/pub struct/pub enum/pub use` 无一处出现 `quinn_proto::` 路径；`cargo doc` 生成的 `target/doc/rtx_quic/` 中 `quinn_proto::` 符号链接 **0**；公开字段类型全为 facade 自有类型（`event.rs:10-43`、`metrics.rs:13-43`） |
| 5 | M3-0-4 无真实 socket / 无 sleep / 无 wall clock | **通过** | `grep -R "thread::sleep" crates/rtx-quic/tests` → 无匹配（exit 1）；全 crate 无 `std::net::UdpSocket/TcpListener/TcpStream`；测试用 `tests/common/mod.rs` 进程内双端点泵互喂 datagram，零 socket 零 sleep；时间仅由注入的 `rtx_core::Timestamp` 驱动，`src/time.rs:12-15` 的进程级 epoch 只在首次 `to_instant` 时取一次 `Instant::now()`（相对偏移量，之后不再读钟——符合 ARCH §8 的「禁协议逻辑直接读钟」，因为 `epoch` 只作基准，实际判定全用注入值） |
| 6 | M3-Q0 窄外观 / 无通用 passthrough | **通过** | `tests/api_surface.rs` 编译通过；`grep -R "use quinn_proto" crates/rtx-quic/tests/api_surface.rs` → 无匹配；`api_surface.rs:39-73` 以函数指针类型锁定 23 个公开方法的精确签名（可编译证明签名不含上游类型）；公开表面仅 25 个类型/方法，无 passthrough、无 re-export 上游运行时 |
| 7 | M3-Q1 endpoint 创建/连接/accept/refuse/配置 | **通过** | `facade_lifecycle.rs:11` `m3_q1_client_server_handshake_completes`、`:38` `m3_q1_server_accepts_and_refuses_incoming` 通过；`Endpoint::new/connect/accept/refuse` 存在（`endpoint.rs:111/151/201/258`）；配置覆盖 ALPN / transport / 证书 / 私钥 / 信任根（`config.rs:97/104/112/126`）；endpoint 不拥有 socket——`handle_datagram` 收、`poll_transmit` 出 |
| 8 | M3-Q2 握手事件子集 | **通过** | `facade_handshake.rs:11/69/104` 三个测试通过；`HandshakeComplete` 含协商 ALPN（`facade_lifecycle.rs:23,32` 断言 `Some(ALPN)`）、peer transport parameters（`:26,34` 断言非空）、DATAGRAM 标志（`:24,33` / `facade_handshake.rs:116-124`）；`HandshakeFailed` 区分证书/ALPN/TP/超时——`endpoint.rs:1069-1102` 分类映射 + 4 个分类单测（`endpoint.rs:1230-1263`）+ 端到端 ALPN 失败用例；事件不重复——`facade_handshake.rs:29-31` 重复投递同一 Initial 后 `server_events.len() == 1`，`:61-65` 重放后事件为空 |
| 9 | M3-Q3 uni/bi 流 | **通过** | `facade_streams.rs:86/126/183/270` 四个测试通过；打开/接受齐备（`endpoint.rs:413/425/436/450`）；流控阻塞后恢复——`:183` 用 256 B 窗口阻塞后恢复且 `offset == payload.len()`（不静默丢数据）；finish/reset/stop_sending 齐备（`:555/585/619`）；流 ID 方向与递增规则校验——`stream.rs:42-54` 解码方向/索引 + `endpoint.rs:979-991` `allows_send/allows_recv` 方向校验，测试断言 `stream.as_u64() & 0b11` 与 `index()` 递增 |
| 10 | M3-Q4 DATAGRAM | **通过** | `facade_datagram.rs:35/72/109` 三个测试通过；按协商上限——`endpoint.rs:666-669` 取 `datagrams.max_size()`；超限显式错误不截断——`endpoint.rs:672` `TooLarge { max_len }`，测试断言 `max_len < payload.len()` 且发送计数前后相等（`:82-105`）；对端不支持显式错误——`endpoint.rs:669` `UnsupportedByPeer`，`:125-128` 断言；不可靠语义写入文档——`src/lib.rs:180-191` `# DATAGRAM semantics` 段 |
| 11 | M3-Q5 transmit 轮询 | **通过** | `facade_transmit.rs:32/72` 两个测试通过；单次一 datagram（`endpoint.rs:340-370` 每次 `poll_transmit` 产出一个 `Transmit`）；连续轮询排空——`:61-68` 断言排空后返回 `None`；空闲返回 `None` 不忙等——`m3_q5_idle_poll_returns_none` |
| 12 | M3-Q6 超时 | **通过** | `facade_timeout.rs:8/40/77` 三个测试通过；返回绝对 `rtx_core::Timestamp`（`endpoint.rs:379-387` 返回 `Option<Timestamp>`，非 Duration）；`handle_timeout` 驱动 idle/PTO——`endpoint.rs:393-403`；只用注入时钟；同一 deadline 只触发一次——`facade_timeout.rs:68-71` 断言已处理 deadline 不再上报；关闭后 timer 被忽略——`:111-114` 断言关闭后 `poll_timeout()` 为 `None` |
| 13 | M3-Q7 关闭 | **通过** | `facade_close.rs:8/45/79` 三个测试通过；应用码+原因——`:20` 关闭并断言 `error_code: 42, reason: b"bye"` 在本地与远端双向一致；立即关闭——`endpoint.rs:731-746` 本地关闭事件同步入队；本地/远端关闭事件——`CloseOrigin::Local/Remote` 区分；draining——`endpoint.rs:953-965` `reap_drained`；**关闭幂等经本人独立探针验证**（额外写临时测试：二次/三次 `close` 均返回 `Ok(())`，`Closed` 事件计数恒为 **1**，探针已删除）；关闭后 open/send 显式错误非 panic——`facade_close.rs:103-136` 断言 `StreamError::Closed` / `DatagramError::Closed` |
| 14 | M3-Q8 metrics 快照 | **通过** | `facade_metrics.rs:8/47/157` 三个测试通过；快照含平滑/最新/min RTT、cwnd、in-flight、lost、DATAGRAM 收发计数、流字节数（`metrics.rs:13-43` 十二个字段）；pacing 不可得时给出上游源码位置依据——`src/lib.rs:246-253` 引 `quinn-proto-0.11.19/src/congestion.rs` L90-97 `pacing_rate: Option<u64>`、`src/congestion/cubic.rs` L226-232 与 `src/congestion/new_reno.rs` L115-121 均恒为 `None`、`src/connection/pacing.rs` L12-23 `pub(super) struct Pacer`——**本人逐条核对上游源码行号，全部命中**；`m3_q8_snapshot_allocations` 确覆盖「快照分配次数记录」契约——`metrics.rs:9` `Copy` 派生 + `endpoint.rs:776` 恒置 `0`，测试 1000 次断言为 0 |
| 15 | 版本与审计基线差异真实可核查 | **通过** | `src/lib.rs:121-152` 声称 0.11.19 与 `9d729c1` 的关系。**本人独立核对上游**：`gh api repos/quinn-rs/quinn/contents/Cargo.toml?ref=9d729c1…` 返回的 workspace manifest 确为 `rust-version = "1.88.0"`、`edition = "2024"`、`fastbloom = "0.17"`、`qlog = "0.18"`、`rcgen = "0.14"`、`rand = "0.10.1"`——与 PR 描述 (b) 逐项吻合；`quinn-proto-0.11.19` 本地 manifest 为 `edition = "2021"`、`rust-version = "1.85"`——吻合；依赖类别与 `DEPENDENCY_AUDIT.md` §5.2（`bytes/lru-slab/rustc-hash/rand/rand_pcg/slab/tinyvec/tracing` + 可选 `rustls/ring`）一致，多出 `thiserror` 与 `rand 0.10` 线——PR 描述已如实说明；`bloom/log/qlog/aws-lc-rs/platform-verifier` **未启用**——`Cargo.lock` 中 `fastbloom/qlog/aws-lc-rs/platform-verifier/log` 计数均为 **0**；`Cargo.toml:24-26` 仅 `features = ["rustls-ring"]`；**版本表述无夸大**：PR 未把 0.11.19 说成审计基线本身，而是明确称为「审计 head → 最新发行版的书面降级」（`src/lib.rs:149-150`）。另核实 crates.io 上 `quinn-proto` 非 yanked 最新版即 **0.11.19**（MSRV 1.85），即该选择同时是「最新且 MSRV 合规」的最优解 |
| 16 | TLS/crypto provider 与测试证书 | **通过** | `src/lib.rs:154-167` 与 PR 描述 (c) 一致声明 rustls 0.23 + ring、TLS 1.3 only、无客户端验证/0-RTT/会话复用/平台 verifier；代码侧核实 `config.rs:180-182`/`:199-201` 均 `with_protocol_versions(&[&rustls::version::TLS13])`，`:185` `with_no_client_auth()`；公共 API 只收 DER——`config.rs:112-123`（`Vec<Vec<u8>>` 证书链 + PKCS#8 私钥）、`:126-129`（信任根），无 `rustls`/`quinn-proto` 类型进入公开签名；测试证书确由 `rcgen 0.13` 在测试进程内生成——`tests/common/mod.rs:21-27` `generate_simple_self_signed`，DER 仅驻留内存，**全 crate 无任何 fixture/私钥落盘文件**（`git ls-tree` 确认）；`time = "=0.3.45"` 钉选理由**属实**——crates.io API 证实 `time` 0.3.46～0.3.55 全部 `rust_version = 1.88.0`、而 0.3.45 为 `1.83.0`，钉在 0.3.45 确实避开 1.88；且 1.85 下 `cargo +1.85.0 test -p rtx-quic --all-features` **42/42 全过**，`time` 为 dev-dependency 不影响 workspace MSRV 1.85 |
| 17 | 资源与 no_std 边界 | **通过** | `src/lib.rs:193-222` `# Resource budgets (ARCHITECTURE.md §16)` 明确区分「本 facade 显式限制」（并发流 100/100、单流重组窗口 1 250 000 B、连接接收窗口 16 MiB、DATAGRAM 收发队列 1 250 000 B / 1 MiB）与「上游承载、本单不再限制」（CID `LOC_CID_COUNT`、ACK 状态、包号空间、`max_incoming` 65 536 + 10 MiB/100 MiB、TLS 缓冲 16 KiB）——**上游数值已逐条核对**：`LOC_CID_COUNT: u64 = 8`（`src/lib.rs:327`）、`max_incoming: 1 << 16`、`incoming_buffer_size: 10 << 20`、`incoming_buffer_size_total: 100 << 20`、`crypto_buffer_size: 16 * 1024` 全部命中；**无界项也未沉默**——`:218-222` 明写「live 连接数」与「排队 Event 数」故意不设限并说明由调用方排空；no_std 边界与 `Cargo.toml` 一致——`:17` `std = ["dep:bytes", "dep:quinn-proto", "dep:rustls", "rtx-core/std"]`，三个依赖均 `optional`，`cargo tree -p rtx-quic --no-default-features` 确认树中**无 quinn-proto**；未宣称嵌入式 QUIC 可用——`src/lib.rs:23-25`「No embedded QUIC support is claimed」 |
| 18 | 作者自查数字复核 | **通过** | 「42 passed（18 unit + 24 integration）」**实测复核一致**：`cargo test -p rtx-quic --all-features` 得 18 + 1 + 3 + 3 + 3 + 2 + 3 + 4 + 3 + 2 = 42，0 failed；「workspace 全过」——`cargo test --workspace --features std`（EXIT 0）、`cargo test --workspace`（EXIT 0）、`cargo test --workspace --no-default-features`（EXIT 0）；**独立抽查（超出作者自查项）**：`cargo fmt --all -- --check` EXIT 0、`cargo clippy --workspace --all-targets --all-features -- -D warnings` EXIT 0、`cargo clippy --workspace --no-default-features -- -D warnings` EXIT 0、`RUSTDOCFLAGS="-D warnings -D rustdoc::private_intra_doc_links" cargo doc --workspace --all-features --no-deps` EXIT 0、`cargo check --workspace --no-default-features --target thumbv7em-none-eabihf` EXIT 0、CI 覆盖率门 `cargo llvm-cov --workspace --all-features --fail-under-lines 96.3` EXIT 0 —— **全部通过，无编造** |
| 19 | PR 描述 (a)(b)(c)(d) 齐全 + 无越界塞项 | **通过** | (a) 门禁逐项对应表（12 行 M3-0/M3-Q 映射含证据路径）；(b) 版本差异说明（已核实为真）；(c) TLS/provider/测试证书生成方式；(d) 未改动项（已有 11 crate、三份文档、CI、PR #2、RV-PR15/16/18-NB、P5 SCTP 决策）与未做项（H3/WebTransport、浏览器互通、基准、嵌入式移植、socket 所有权、连接池、自动重连、qlog、0-RTT、连接迁移、会话复用）齐全；**无塞项**——未把 CI-C1、R1-3/PR #2、SCTP 实现、H3、浏览器互通、基准、嵌入式移植塞进本单；**无夸大**——「42 passed」「workspace 全过」「MSRV 1.85 通过」三项均经本人独立复跑证实 |
| 20 | 禁忌表述扫描 | **通过** | PR body 全文检索「浏览器已互通 / 已验证浏览器可用 / H3 已实现 / 嵌入式 QUIC 已可用 / SCTP/DataChannel 已覆盖 / 完整 Quinn / 镜像 / 全部自查通过」→ 命中数均为 **0**；唯一「SCTP」出现在 (d) 否定句「P5 SCTP 决策」未改动项中，属明确否定范围，不反向暗示；crate 源码侧检索同类表述 → 仅 `src/lib.rs:6-8`（明确否定「does **not** mirror the entire Quinn API」）与 `:23`、`:259-260`（否定句「No embedded QUIC support is claimed」/「Not implemented」），无反向暗示；`b"h3"` 仅作为 ALPN 协议串出现在测试中，不构成「H3 已实现」的声明 |

---

## 三、问题清单

### 阻塞项（blocking）

**0 阻塞。**

---

### 非阻塞意见（non-blocking）

以下 6 项均不违反门禁、不要求作者改动已有 crate / 已有文档 / CI，供协调者或后续单元参考。**均不需要在本单内修复。**

| # | 位置 | 现状 | 建议 |
|---|---|---|---|
| N1 | 会话 widget（PR 描述之外） | widget 显示「22 个文件 +4462/-0」，与 git/API 的 25 文件 +5699/-0 不一致。**本人已独立解释该差异**：`git diff --numstat` 排除 `Cargo.lock`、根 `Cargo.toml`、`crates/rtx-quic/Cargo.toml` 三者后恰为 **22 文件 / 4468 行**，与 widget 的 22 文件口径吻合——widget 系未计入三个 manifest/锁文件的中间口径，且行数相差 6 行属快照时点差异。**git 与 GitHub API 均为 25/+5699，以 git 为准** | 无需补 widget 数字；仅点明口径差异，不影响验收（25 个文件全部落在 R6-1 授权范围内，见下） |
| N2 | `crates/rtx-quic/src/error.rs`（整个文件） | 覆盖率报告中 `rtx-quic/src/error.rs` 为 **0.00%**（111 行未覆盖），因 7 个错误枚举的 `Display`/`Error` impl 无任何测试触及。**不影响 CI**：覆盖率门实测按 **line coverage** 计（`--fail-under-lines 96.0` 仍 EXIT 0、`97.5` 才 EXIT 1），PR head 行覆盖率 **97.02%**（基线 98.00%），高于 CI 阈值 96.3，`cargo llvm-cov ... --fail-under-lines 96.3` 实测 EXIT 0 | 可选：后续单元补 `Display` 文案断言（属测试增强，不属本单门禁） |
| N3 | `crates/rtx-quic/src/addr.rs` | 行覆盖率 48.39%，IPv6/异常地址映射分支未覆盖；同 N2，不影响 CI 门（97.02% > 96.3%） | 同上，可选 |
| N4 | `src/lib.rs:173-177`「Time model」 | facade 需 `std::time::Instant`（上游要求），实现取进程级 epoch 后以 `epoch + micros` 映射。该映射是**单点、一次性**取钟，且文档已如实披露（`time.rs:12-15` `OnceLock`）。已核实不违反 ARCH §8（协议判定全用注入值）。仅提示：此映射使 `Timestamp` 与真实单调钟之间存在一个进程级常数偏移，属设计取舍而非缺陷 | 无需改动；如后续单元要求跨进程可复现，需另立决策（不在本单） |
| N5 | `.gitignore:6` 含 `Cargo.lock` | PR 用 `git add -f` 提交了 `Cargo.lock`（PR 描述已如实说明「`.gitignore` 仍忽略该文件，本次以 `git add -f` 提交」）。`.gitignore` **未被本 PR 修改**（`git diff --name-only` 无 `.gitignore`），属基线既有状态。后果：后续 `cargo` 若因 manifest 变动需重解析 `Cargo.lock`，git 不会自动纳入变更 | 不要求本单改 `.gitignore`（会触及已有文件，超出 R6-1 授权）。提示协调者：后续依赖变更单需留意 `Cargo.lock` 需 `git add -f` |
| N6 | 作者终结总结「PR 的 GitHub CI 在 0 秒失败」 | **本人 API 实测：PR head 的 check-runs 总数为 0，commit statuses 亦为空**（`gh api .../commits/7feb7b2/check-runs` → `total_count: 0`）。即 **0 次运行 ≠ 一次失败运行**，该总结表述不准确。**按已知口径，此为既往 CI-C1 模式，不是本 PR 缺陷** | 不得据此判 CI 失败；不得要求本 PR 修 CI（CI-C1 的 fuzz job `uses` + `run` 拆分是独立单）。门禁由协调者在 xc 上另跑 CI-exact |

---

## 四、两处作者说法 / 协调者转述的独立复核结论

### 4.1 作者称「`suite (msrv)` 在 1.85 上因既有 dev-dependency `proptest 1.12.0` 在 main @ 4641cd5 干净 worktree 上同样失败」

**属实，且确为基线既有问题，非本 PR 引入。** 复现过程：

1. `crates/rtx-crypto/Cargo.toml:16` 有 `proptest = "1"`（dev-dependency，本 PR **未改动**该文件，diff 中不含 `crates/rtx-crypto/Cargo.toml`）。
2. 基线 `4641cd5` 干净 worktree 解析出的 `Cargo.lock` 中 `proptest` 即为 **1.12.0**（与 PR head 相同版本）。
3. `proptest 1.12.0` 的 `Cargo.toml:14` 声明 `rust-version = "1.88"`。
4. 在**基线干净 worktree**（非 PR head）执行 `cargo +1.85.0 test --workspace`，实测报错：
   `error: rustc 1.85.0 is not supported by the following package: proptest@1.12.0 requires rustc 1.88`（EXIT 101）。

**结论**：该 MSRV 失败在 `main @ 4641cd5` 上独立复现，与 PR #20 无关；本 PR 未触碰 `rtx-crypto` 依赖与 CI。**不构成本单阻塞，也不得要求本单修 CI。** 补充核实：PR head 的 `cargo +1.85.0 test -p rtx-quic --all-features` 实测 **42/42 全过**，即本单新增 crate 自身在 MSRV 1.85 上是绿的。

### 4.2 会话 widget「22 个文件 +4462/-0」与 git/API「25 文件 +5699/-0」

**以 git 与 GitHub API 为准，两者相互印证**（`git diff --shortstat` 与 `gh api .../pulls/20` 的 `changed_files/additions/deletions` 完全一致）。差异**不影响验收**，理由：

- 25 个文件逐个分类后全部落在 R6-1 授权范围内：`Cargo.lock`（新增，PR 描述已声明）、根 `Cargo.toml`（+1 行成员）、`crates/rtx-quic/Cargo.toml`（新增）、src 10 文件、tests 10 文件、`measurements/m3/deps/` 2 文件——**无任何越界文件**。
- 排除三个 manifest/锁文件后的口径恰为 22 文件（见 N1），说明 widget 数字来自同一工作树的中间口径快照，**不是另一份 diff**。
- **无文件遗漏、无文件多计**，验收结论不受影响。

---

## 五、独立复核的补充发现（超出任务书要求，均为正面结论）

1. **CI 覆盖率门实测通过**（任务书未要求）。`cargo llvm-cov --workspace --all-features --fail-under-lines 96.3` EXIT 0。PR head 行覆盖率 97.02%（基线 98.00%，阈值 96.3），新增 crate 未击穿覆盖率下限；且经阈值二分实测确认 `--fail-under-lines` 作用于**行覆盖率**而非区域覆盖率（95.52%）。
2. **M3-Q7「关闭幂等」经独立探针实测**（门禁文档未单列该测试名）。临时测试确认重复 `close` 返回 `Ok(())` 且 `Closed` 事件恒为 1 个；探针文件已删除，工作树复核干净（`git status --short` 为空）。
3. **M3-Q8 上游源码行号逐条核对**（任务书要求「上游源码位置依据」可核查）。`src/lib.rs:246-253` 引用的 `congestion.rs` L90-97、`cubic.rs` L226-232、`new_reno.rs` L115-121、`pacing.rs` L12-23、`stats.rs` L136-166、`paths.rs` L291-300 **全部命中真实代码**，无杜撰。
4. **ARCH §16 资源数值逐条核对上游**：CID 上限 8、`max_incoming` 65 536、incoming 缓冲 10 MiB / 100 MiB、TLS 缓冲 16 KiB、`STREAM_RWND` = 1 250 000 B —— 与 `src/lib.rs:196-216` 所述一致。
5. **上游审计基线一手取证**：`gh api repos/quinn-rs/quinn/contents/Cargo.toml?ref=9d729c1…` 证实该 revision 的 workspace manifest 为 `rust-version = "1.88.0"` / `edition = "2024"` / `fastbloom 0.17` / `qlog 0.18` / `rcgen 0.14` / `rand 0.10.1`，PR 描述 (b) 的每一条事实均属实。
6. **`Cargo.lock` 纯增量性证明**：与基线 lock 做包集合双向差分，**基线包无一移除或降版**；新增 54 包全部可归因于 `quinn-proto` / `rustls` / `rcgen` / `time` 传递依赖——不存在「顺带改动既有成员解析版本而未说明」的情形（该项在任务书中为明确核查点）。

---

## 六、评审结论与签署

- **评审对象**：PR **#20**，分支 `trae/agent-Nx43tj`，head SHA **`7feb7b22c42451726bce1ecfdf18dc3de4ce04f7`**
- **评审所用基线**：`main` 头 **`4641cd5aed9ca375ac53b74061a68343197a5f5b`**（`git merge-base` 确认 = 合并前 main 头，无漂移）
- **阻塞项数**：**0**
- **是否建议合并**：**建议合并（内容具备合并条件）**。本单不合并；实际合并与门禁勾选由协调者按流程执行。
- **不要求作者**：改已有 crate、改已有文档、改 CI（CI-C1 为独立单）、修 PR #2（R1-3）、做 H3（R6-2）/浏览器互通（R6-3）/基准（P7）/嵌入式移植、实现 SCTP、改已合并的 PR 描述文本、补 widget 数字。
- **门禁 CI 说明**：本 PR head 的 check-runs 为 0（既往 CI-C1 模式），**不据此判 CI 失败**；M3-0/M3-Q 门禁证据已由本评审以 CI 等价命令独立跑通（test / fmt / clippy 双模式 / doc / thumbv7em / coverage 均 EXIT 0）。

---

### 附：本人实测命令清单（可复现）

```bash
git fetch origin refs/pull/20/head:refs/remotes/origin/pr20
git diff --shortstat 4641cd5 7feb7b2            # 25 files, 5699 insertions(+)
git diff --name-status 4641cd5 7feb7b2          # 24A + 1M
gh api repos/medivhc/rtx-rs/pulls/20 --jq '{changed_files,additions,deletions,mergeable_state,head_sha:.head.sha}'
gh api repos/medivhc/rtx-rs/commits/7feb7b2/check-runs --jq '.total_count'   # 0
cargo test -p rtx-quic --all-features                                     # 42 passed
cargo test --workspace --features std ; cargo test --workspace ; cargo test --workspace --no-default-features
cargo +1.85.0 test -p rtx-quic --all-features                            # 42 passed (MSRV)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --no-default-features -- -D warnings
RUSTDOCFLAGS="-D warnings -D rustdoc::private_intra_doc_links" cargo doc --workspace --all-features --no-deps
cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
cargo tree -p rtx-quic -e normal --locked            # 无 tokio；与归档 normal-tree.txt 一致
cargo tree -p rtx-quic -i quinn-proto --locked        # 与归档 quinn-tree.txt 一致
cargo tree -p rtx-quic --no-default-features --locked # 树中无 quinn-proto
cargo llvm-cov --workspace --all-features --fail-under-lines 96.3   # EXIT 0
```
