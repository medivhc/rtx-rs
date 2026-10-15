# M1-3 差分向量计划（test set）

> 里程碑：M1-3 STUN wire codec｜基线：M1-2 commit `8d1abe9`（243 测试）
> 上游参考：webrtc-rs/rtc @ `5573fe50`（只读），路径
> `/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d4b-06e3a3db6000/upstream/rtc/rtc-stun/`
> 本文件是 darwin-skill Phase 0.5 的 test set 产物：每个模块的验收向量来源与预期行为。
> 实施日志见 `m1-3-darwin-log.tsv`。

## 1. 模块划分与向量映射

| 轮次 | 模块 | 文件 | 测试命名 | 上游向量来源（文件:行号） |
|---|---|---|---|---|
| R1 | message 层 | `crates/rtx-stun/src/message.rs` | `stun_msg_NNN_*` | `message/message_test.rs:31-134`（type value/read_value）、`:161-263`（cookie/length 错误）、`:574-614`（is_stun_message/contains） |
| R1 | attribute TLV | `crates/rtx-stun/src/attributes.rs` | `stun_attr_NNN_*` | `attributes/attributes_test.rs:44-85`（padding/range）、`message/message_test.rs:299-324`（AttrType stringer） |
| R2 | MAPPED-ADDRESS | `crates/rtx-stun/src/addr.rs` | `stun_addr_NNN_*` | `addr/addr_test.rs:5-103`（v4/v6 往返、错误路径） |
| R2 | XOR-MAPPED-ADDRESS | `crates/rtx-stun/src/xoraddr.rs` | `stun_xor_NNN_*` | `xoraddr/xoraddr_test.rs:8-35`（xor helper）、`:38-203`（base64 tx 向量、v4/v6 往返、错误路径） |
| R2 | 文本属性 | `crates/rtx-stun/src/textattrs.rs` | `stun_text_NNN_*` | `textattrs/textattrs_test.rs:8-307`（SOFTWARE/USERNAME/REALM/NONCE） |
| R2 | UNKNOWN-ATTRIBUTES | `crates/rtx-stun/src/uattrs.rs` | `stun_unk_NNN_*` | `uattrs/uattrs_test.rs:4-36` |
| R2 | ERROR-CODE | `crates/rtx-stun/src/error_code.rs` | `stun_err_NNN_*` | `error_code/error_code_test.rs:4-20` + `error_code.rs:50-71`（class/number 编码） |
| R3 | FINGERPRINT | `crates/rtx-stun/src/fingerprint.rs` | `stun_fp_NNN_*` | `fingerprint/fingerprint_test.rs:7-74`（整包字节向量 + check 路径） |
| R3 | MESSAGE-INTEGRITY | `crates/rtx-stun/src/integrity.rs` | `stun_int_NNN_*` | `integrity/integrity_test.rs:147-294`（framing/长度调整/顺序规则；真实 HMAC 向量延至 M2，见 §3） |

## 2. 与上游的设计差异（差分前先约定）

| # | 差异 | 上游行为 | rtx-stun 行为 | 理由 |
|---|---|---|---|---|
| 1 | 消息模型 | `Message` 持有 `Vec<u8>` raw（allocating builder） | `Message<'a>` 借用输入，属性零拷贝；`MessageWriter` 写调用方缓冲 | ARCHITECTURE §11 wire-codec 模型 + no_std |
| 2 | MAPPED-ADDRESS 长度 | `min(ip.len(), v[4..].len())` 静默截断，长值不报错 | 值长必须恰为 family 尺寸（4/16），否则 `InvalidValue` | 严于上游（同 M1-2 REMB >255 先例），模块 doc 注明 |
| 3 | XOR-MAPPED 短 IPv6 | 不足 16 字节按 min 补零接受 | 同样拒绝（必须恰 16） | 同上 |
| 4 | 错误类型 | `shared::error::Error` 数十变体 | 统一 `rtx_wire::WireError`（语义错误映射 `InvalidValue`） | rtx 全簇约定（rtx-rtp/rtx-rtcp 先例） |
| 5 | 文本属性上限 | USERNAME 513 / REALM 763 / SOFTWARE 763 / NONCE 763，超限 `ErrAttributeSizeOverflow` | 同限值，超限 `InvalidValue` | 差分对齐 |
| 6 | ERROR-CODE reason | `String::from_utf8_lossy`（std） | `core::str::Utf8Chunks` 手写 lossy（no_std） | 字节级 parity |
| 7 | MESSAGE-INTEGRITY 长期密钥 | MD5(user:realm:password)（上游 crypto crate 提供 Md5） | 仅支持 raw/short-term key；长期密钥派生延至 M2 | `rtx-crypto` `HashAlgorithm` 无 Md5（M0 冻结契约），不新造原语 |
| 8 | padding 字节 | 解码忽略、可非零 | 同；重编码归一化为零 padding（规范消息字节级往返） | 同 M1-2 TWCC padding 宽容先例 |
| 9 | `compat_attr_type` | 0x8020 → XOR-MAPPED-ADDRESS | 同（仅解码侧） | draft 兼容 |
| 10 | 地址 Display | `IpAddr` Display | 不实现（断言字段值代替字符串） | rtx-core M0 冻结不扩；ICE 需要时再加 |

## 3. MESSAGE-INTEGRITY 的实测策略

上游 RFC 5389 HMAC-SHA1 向量依赖真实 crypto provider（`integrity_test.rs:179-204`）。
rtx-crypto 只冻结契约（M2 才有 Linux provider），因此 R3 用**确定性 mock provider**
（FNV 混合，同 rtx-crypto 测试 mock 策略）验证 framing 语义：

- 长度字段调整（sign 时 +24、check 时扣除 integrity 之后属性的 padded 尺寸）；
- HMAC 输入区间 = 头部（长度已调整）+ integrity 之前的属性；
- FINGERPRINT 先于 MESSAGE-INTEGRITY → 拒绝；
- 截断 tag / 篡改字节 / 换 key → `InvalidValue`。

mock 向量标注 `provider=mock`；真实 HMAC 向量在 M2 provider 落地后补 `full_test` 行。

## 4. 验收命令（每轮 ratchet 前必跑）

```bash
cargo test --workspace --features std          # 全量测试
cargo check --workspace --no-default-features  # 宿主 no_std
cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
cargo clippy --workspace --all-targets --all-features   # pedantic 0 warning
cargo fmt --all -- --check
```
