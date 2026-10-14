# M1-2 实现纪要：RTCP RFC 4585 反馈包 codec

> 工程师：寇豆码（Kou）｜团队：software-rtx-m0｜任务：M1-2
> 基线：M1-1 commit `078e6dd`（rtx-rtp / rtx-rtcp 核心包，178 测试）
> 上游参考：webrtc-rs @ `5573fe50`（只读），路径
> `/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d48-47908dd72000/upstream/rtc/rtc-rtcp/src/`

## 1. 模块清单（7 个新文件 + 3 个改动文件）

| 文件 | PT / FMT | 结构 | 测试数 |
|---|---|---|---|
| `crates/rtx-rtcp/src/nack.rs` | 205 / 1 | `Nack<'a>{sender_ssrc, media_ssrc, nacks: &[u8]}` + `NackPair{packet_id, lost_packets}` | 7 |
| `crates/rtx-rtcp/src/rapid_resync.rs` | 205 / 5 | `RapidResync{sender_ssrc, media_ssrc}`（Copy，无 FCI） | 5 |
| `crates/rtx-rtcp/src/twcc.rs` | 205 / 15 | `Twcc<'a>` + `RunLengthChunk` / `StatusVectorChunk` / `PacketStatusChunk` / `TwccStatusIter` / `TwccPacketStatus` / `TwccRunLengthReport` + `write_run_length_report()` | 19 |
| `crates/rtx-rtcp/src/pli.rs` | 206 / 1 | `Pli{sender_ssrc, media_ssrc}`（Copy，无 FCI） | 5 |
| `crates/rtx-rtcp/src/sli.rs` | 206 / 2 | `SliEntry{first, number, picture}` + `Sli<'a>{sender_ssrc, media_ssrc, entries: &[u8]}` | 7 |
| `crates/rtx-rtcp/src/fir.rs` | 206 / 4 | `FirEntry{ssrc, sequence_number}` + `Fir<'a>{sender_ssrc, media_ssrc, entries: &[u8]}` | 8 |
| `crates/rtx-rtcp/src/remb.rs` | 206 / 15 | `Remb<'a>{sender_ssrc, bitrate_bits: u32, ssrcs: &[u8]}`（bitrate 以 f32 位存储保 `Eq`） | 11 |
| `packet.rs`（改） | — | `RtcpPacket` 新增 7 个变体 + FMT 分发 + `Raw` 兜底 | +3 |
| `lib.rs`（改） | — | 模块注册、re-export、crate doc 增补 RFC 4585 清单 | — |
| `compound.rs`（改，仅测试） | — | CPD-001 / CPD-004 断言随分发更新 | — |

新增测试合计 **65 个**（模块 62 + packet 3），命名规则 `rtcp_<模块>_NNN_<场景>`，全部带
`文件:行号` 级上游向量来源注释。工作区测试总数 **178 → 243**。

## 2. TWCC 设计决策（重点模块）

1. **Borrowed 全程零拷贝**：`Twcc<'a>` 只持 `chunks: &[u8]` 与 `recv_deltas: &[u8]`
   两个裸区，`Decode` 的 `consumed` 取 `input.len()`（与 M1-1 子包解码风格一致）；
   per-packet 视图由 `status_iter()`（`TwccStatusIter`，无堆状态机）现场重建
   `(seq, status, delta)`，序号从 `base_sequence_number` 起按 2^16 回绕。
2. **位布局经上游向量逐位手工核验**：
   - run-length chunk：`T=b0>>7`，symbol=`(b0>>5)&3`，run=`(b0&0x1F)<<8|b1`（13 位）；
   - status-vector chunk：`T=1`，`S=(b0>>6)&1`（1-bit 14 符号 / 2-bit 7 符号）；
   - recv delta 单位 250µs：small=1B u8、large=2B 有符号 i16、无 delta。
   核验向量：`[0,0xDD]`→NotReceived×221；`[0x60,0x18]`→WithoutDelta×24；
   `[0x9F,0x1C]`→1-bit×14；`[0xCD,0x50]`→2-bit×7。
3. **StatusVectorChunk 隐藏尾陷阱**：2-bit 块的 14 槽数组中后 7 槽无语义。
   解法：`from_bytes` 把隐藏尾归一化为 `PacketNotReceived`，并手写 `PartialEq`
   只比可见前缀（`impl Eq`），防止隐藏位泄漏进比较/往返。
4. **decode 走查算法与上游一致**（`processed < packet_status_count` 时逐块读、
   delta 区紧跟被消耗的块），外加两处**硬化**：
   - `run_length == 0` → `InvalidValue`（上游会死循环）；
   - delta 区必须落在 `length` 字段界内（上游只查每个 delta 首字节，可读进 padding）。
5. **encode 重新 padding 到 32-bit 边界**（`padding_size`），与上游一致；
   `header()` 的 P 标志反映该 padding。
6. **最小构造路径**：`write_run_length_report(writer, &TwccRunLengthReport{..})`
   ——9 个平铺参数会触发 clippy pedantic `too_many_arguments`，故收敛为参数结构体
   （可扩展、自文档）。`packet_status_count` 由 `run_length` 派生；
   `run_length==0 / >0x1FFF`、`reference_time > 0xFFFFFF`、delta 字节数不符均拒绝。

## 3. 上游向量来源统计

| 模块 | 上游测试文件 | 向量类型 |
|---|---|---|
| nack | `payload_feedbacks/transport_layer_nack/nack_test.rs` | valid/round-trip/error-path |
| rapid_resync | `payload_feedbacks/rapid_resynchronization_request/*_test.rs` | valid/error-path |
| twcc | `transport_feedbacks/transport_layer_cc/transport_layer_cc_test.rs`（926 行） | unmarshal example1-5 + empty report、marshal example1-6、RecvDelta 3 例、chunk 3.1.3/3.1.4 例子 |
| pli | `payload_feedbacks/picture_loss_indication/*_test.rs` | valid/error-path |
| sli | `payload_feedbacks/slice_loss_indication/*_test.rs` | valid/round-trip/error-path |
| fir | `payload_feedbacks/full_intra_request/*_test.rs` | valid/round-trip/error-path |
| remb | `payload_feedbacks/receiver_estimated_maximum_bitrate/*_test.rs` | marshal、Chrome、truncate、overflow、zero-mantissa |

所有差分向量在测试内以 `文件:行号` 注释标注；TWCC/REMB 按要求覆盖：
run-length/status-vector 往返、small/large/无 delta、截断 + 非法 chunk 错误、
上游真实 report 向量、已知比特率往返、bit/s↔exp/mantissa 换算、坏 magic 拒绝。

## 4. 验收命令结果（实跑）

```
$ cargo test --workspace --features std
   15 + 23 + 17 + 124 + 42 + 22 = 243 passed; 0 failed   # rtx-rtcp 124（M1-1 62 + 新增 62）

$ cargo test --workspace
   编译通过，0 tests（std feature 关闭时测试整体 cfg 掉）

$ cargo check --workspace --no-default-features
   Finished（宿主）✓
$ cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
   Finished ✓

$ cargo clippy --workspace --all-targets --all-features
   0 warning（含 -W clippy::pedantic；曾报 69 条，已全部修复，见 §6）

$ cargo fmt --all -- --check
   clean（已先执行 cargo fmt --all）
```

## 5. 语义歧义取舍（RFC / 任务书 / 上游三方冲突时）

1. **SLI FCI 格式**：任务书写 `[SSRC(4) first(1) number(1) picture(1)]*`（8 字节/条），
   但 RFC 4585 §6.3.2.2 与上游实现均为 **4 字节/条**（First 13b | Number 13b |
   PictureID 6b，无逐条 SSRC）。**取 RFC + 上游**，任务书格式未采纳；已在
   `sli.rs` 模块 doc 记录。
2. **SLI 的 PT**：上游向量头部字节为 `0xcd`（PT=205/TSFB）——这是上游 bug，
   SLI 按 RFC 4585 属 PSFB。**本实现用 0xce（PSFB）+ 上游 body 字节**，
   模块 doc 已注明；因此对上游原向量的字节级往返不成立（仅字段级成立），
   测试按"上游 body + 修正后的头"构造差分向量。
3. **TWCC padding 宽容**：上游若干 unmarshal 向量声称的 padding 字节数比实际多
   （如 example2 尾字节 `0x03` 但 delta 区后仅 1 字节）。**解码忽略尾部字节、
   编码总是重 padding**，与上游宽容度一致；`encode(decode(v))` 对 marshal 向量
   字节级精确、对 unmarshal 向量字段级精确。
4. **上游 TWCC marshal example2 自相矛盾**：`packet_status_count=2` 但携带两个
   7 符号 2-bit 块。本实现按上游走查语义差分（decode 结果与上游 unmarshal 一致：
   60000µs / -12000µs），测试 011 已文档化该不一致，并用自洽的 count=14
   unmarshal 向量验证重编码除伪 padding 计数字节外字节级一致。
5. **REMB 零 mantissa 怪癖**：编码 0 bit/s 得 mantissa=0/exp=0，解码时上游对
   mantissa=0 跳过归一化 → 得 2^23 = 8388608.0，**0 无法往返**。为与上游比特级
   一致，原样复刻该怪癖（测试 006 显式断言 8388608.0 并注释原因）。
6. **REMB 比特率表示**：`Remb` 以 `bitrate_bits: u32`（f32 原始位）存储而非
   `f32` 字段——否则 `f32` 破坏 `Eq`，`RtcpPacket` 枚举将无法 derive `Eq`。
7. **REMB SSRC 条数上限**：`Num SSRC` 仅 1 字节，>255 条时上游静默截断；
   本实现返回 `InvalidValue`（严于上游），模块 doc 已注明。
8. **FIR 至少 1 条 FCI**：`FIR_MIN_OCTET_COUNT=20`（RFC 5104），空条目区在
   encode 时拒绝（与上游一致）；decode 不强制 `media_ssrc==0`（上游亦不强制）。
9. **FMT 分发兜底**：已建模 FMT 但子包畸形 → 传播错误（不静默降级 `Raw`）；
   未建模 FMT（如 RFC 8888 CCFB FMT=11）→ `RawPacket` 原样保留。
   `packet.rs` doc 已注明该策略。

## 6. Clippy 整改记录（69 → 0）

- `unreadable_literal` ×34：测试向量长十进制/十六进制字面量加 `_` 分组；
- `unusual_byte_groupings` ×3：`0x67FFFF_C0`→`0x67FF_FFC0`、`0x1234_56`→`0x0012_3456`；
- `cast_possible_truncation/sign_loss` ×14：常量派生值改具名 `u16/u8` 常量或
  `u16/u8::try_from(..).map_err(WireError::Overflow)`；REMB 的 `f32→u32` mantissa
  转换不变量（循环后 `0 ≤ v < 2^24`）以行内 `#[allow]` + 注释固定；
- `cast_precision_loss` ×1：`(1<<18) as f32` 改为具名常量 `REMB_MANTISSA_THRESHOLD`；
- `trivially_copy_pass_by_ref` ×2：`Pli/RapidResync::write_to(&self)` 改 `self`
  （二者均 `Copy`，与 M1-1 `Header::write_to(self)` 风格一致）；
- `missing_must_use` ×4：TWCC 纯查询方法补 `#[must_use]`；
- `too_many_arguments` ×1：`write_run_length_report` 改参数结构体（见 §2.6）；
- `needless_lifetimes` ×1：`impl<'a> TwccStatusIter<'a>` → `impl TwccStatusIter<'_>`；
- `filter_map_bool_then` ×1：`filter_map(..then(..))` → `filter().map()`；
- `doc_lazy_continuation` ×3：lib.rs crate doc 列表续行改独立条目。

整改后复跑：`cargo test --workspace --features std` 243 passed / 0 failed
（过程中 `RunLengthChunk::to_bytes` 改 `to_be_bytes` 写法时曾漏 `<<8`，
被测试 001/015/016 立即捕获并修复——差分向量对 codec 回归有效）。

## 7. no_std 合规

- 全部新模块 `#![cfg_attr(not(feature = "std"), no_std)]` 生效，std feature 默认关；
- 非测试源码零 `Vec/String/Box/unwrap/expect/panic!/std::`（已脚本扫描确认）；
- 借用类型 + 定长数组 + `core::iter` 完成全部可变长区域遍历；
- `f32::floor` 在本工具链 no_std 不可用（E0599，实测复核），REMB 以
  `value - value % 1.0` 精确替代（循环保证 `value < 2^24`）；
- 宿主 + `thumbv7em-none-eabihf` 双目标 `--no-default-features` 编译通过。
