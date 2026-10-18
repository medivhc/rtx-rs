# M1-3 实现纪要：rtx-stun wire codec

> 工程师：寇豆码（Kou）｜团队：software-rtx-m0｜任务：M1-3 STUN wire codec
> 基线：M1-2 commit `8d1abe9`（243 测试）
> 上游参考：webrtc-rs/rtc @ `5573fe50`（只读），路径
> `/root/.codebuddy/artifact/2f8a7d30-9c21-4f0b-1d4b-06e3a3db6000/upstream/rtc/rtc-stun/`
> 实施日志：`docs/m1-3-darwin-log.tsv`（4 行：baseline + R1/R2/R3 全 keep）
> 差分向量计划：`docs/m1-3-test-vectors.md`（R1-R3 模块 → 上游 `文件:行号` 映射）

## 1. 里程碑结果

| 轮次 | commit | 交付 | 测试增量 | 工作区测试 |
|---|---|---|---|---|
| baseline | `8d1abe9` | M1-2 RTCP 反馈 codec | — | 243 |
| R1 | `10979ba` | message 层 + attribute TLV 框架 + `MessageWriter` | +28 | 271 |
| R2 | `96ebeb0` | 五个 typed 属性模块 + `push_with` 流式写 | +37 | 308 |
| R3 | `53767e5` | FINGERPRINT + MESSAGE-INTEGRITY（trailer 属性） | +19 | **327** |

验收（每轮 ratchet 前 + 终验均执行）：

```text
cargo test --workspace --features std                    → 327 passed, 0 failed
cargo check --workspace --no-default-features            → 宿主 no_std OK
cargo check ... --target thumbv7em-none-eabihf           → 嵌入式 no_std OK
cargo clippy --workspace --all-targets --all-features    → 0 warning（pedantic）
cargo fmt --all -- --check                               → clean
```

## 2. 模块清单（10 个文件，3885 行）

| 文件 | 内容 | 测试数 |
|---|---|---|
| `message.rs` | `Message<'a>` 零拷贝解码/eager 验证/逐字重编码；`MessageType`（RFC 5389 Figure 3 位打包）、`Method`/`MessageClass`、`TransactionId`；`MessageWriter`（写调用方缓冲、`push`/`push_with`、u16 累积溢出拒绝）；`is_stun_message` | 17 |
| `attributes.rs` | `AttrType`（required/optional + Display）、`RawAttribute` TLV 编解码、32-bit padding 归一化、`compat_attr_type`（0x8020 兼容）、全部 30+ 属性常量、`find_attribute`（crate 内步进查找） | 11 |
| `addr.rs` | `MappedAddress` + `ALTERNATE-SERVER`/`RESPONSE-ORIGIN`/`OTHER-ADDRESS` 别名；严格长度（差异 #2） | 7 |
| `xoraddr.rs` | `XorMappedAddress`（`typ` 参数覆盖 XOR-PEER/RELAYED）；cookie‖tx 掩码、端口 XOR cookie 高 16 位；`xor_bytes`（上游 `safe_xor_bytes` 可读版） | 9 |
| `textattrs.rs` | `Username`/`Realm`/`Nonce`/`Software` 统一 `TextAttribute<'a>`（借用 `&str`）；编码侧 513/763 上限 | 10 |
| `uattrs.rs` | `UnknownAttributes<'a>` 借用值 + `push_to` 经 `push_with` 流式写任意多类型 | 4 |
| `error_code.rs` | `ErrorCode`（17 常量 + `default_reason` const 表，替代上游 `lazy_static`）；`ErrorCodeAttribute<'a>` reason 借字节 + `Utf8Chunks` lossy Display | 7 |
| `fingerprint.rs` | `fingerprint_value`（CRC-32/ISO-HDLC，const 表）；`push_fingerprint`/`check` | 9 |
| `integrity.rs` | `MessageIntegrity<'a>` + `MacFn` 注入式 MAC；长度调整/输入区间/顺序规则/常量时间比较 | 10 |
| `lib.rs` | 模块注册 + 重导出 + crate doc（RFC 5389/5766/8445/5780 + 消息布局图） | — |

## 3. 关键设计决策

1. **零拷贝读 + 调用方缓冲写**（差异 #1）：`Message<'a>` 只持 `attribute_region: &'a [u8]`，
   解码时 eager 走完全部 TLV；重编码逐字还原（含非零 padding）。`MessageWriter<'a>`
   写调用方 `&mut [u8]`，头部在 `new` 时落盘，`push` 后即完整消息。全程无 `alloc`。
2. **`push_with` 回调式流式写属性**（R2 新增，R3 前定稿）：`UNKNOWN-ATTRIBUTES`
   可含任意多类型码，无固定缓冲可容；`push(typ, value)` 现委托
   `push_with(typ, len, |region| region.copy_from_slice(value))`，先清零 padding 再填值区，
   杜绝缓冲残留泄漏进消息。
3. **trailer 属性支撑**（R3）：`MessageWriter::with_trailer_length(extra, f)` 临时把头部
   length 字段 `+extra` 后回调、再还原——`FINGERPRINT`（RFC 5389 §15.5：CRC 覆盖含自身
   TLV 的头部）与 `MESSAGE-INTEGRITY`（§15.4：HMAC 覆盖长度含自身 TLV、但不含其后属性
   的头部）两种语义共用该机制；`check` 侧用 `header_bytes(typ, adjusted_length, tx)`
   重建头部 + `find_attribute` 定位属性偏移，两段输入喂 CRC/MAC，无拼接缓冲。
4. **MAC 注入而非内置**（差异 #7）：`MacFn = fn(key, input, output)` 函数指针，
   no_std 无 `dyn` 无 alloc。M1-3 只支持 raw/short-term key；长期密钥
   （`MD5(user:realm:password)`）与 RFC 5389 真实 HMAC-SHA1 向量延至 M2
   `rtx-crypto` provider 落地——R3 用确定性 mock（XOR fold，与上游 `TestMac` 同构）
   钉死 framing 语义（长度调整 / 输入区间 / FINGERPRINT 先于 integrity 拒绝 /
   截断 tag / 换 key / 常量时间比较）。
5. **CRC-32 无外部 crate**：`const fn` 构建 ISO-HDLC 反射表（poly `0xEDB88320`，
   init/xorout `0xFFFFFFFF`），经典 check 值 `crc32("123456789") = 0xCBF43926` 自测；
   上游整包向量（SOFTWARE "software" + FINGERPRINT，`fingerprint_test.rs:7-25`）
   字节级复刻，末 4 字节 `e44c33d9`。
6. **地址模型不含 std::net**（ARCHITECTURE §9）：`rtx_core::IpAddr::V4/V6`；
   不实现 `Display`（差异 #10），测试断言字段值。
7. **ERROR-CODE reason 表**：上游 `lazy_static` HashMap → `const ERROR_REASONS: [(ErrorCode, &[u8]); 17]`
   线性查找（no_std）；Display 用 `core::str::Utf8Chunks` 手写 lossy（每段无效序列一个
   U+FFFD），与 `String::from_utf8_lossy` 字节级 parity（差异 #6）。

## 4. 与上游的差异（`docs/m1-3-test-vectors.md` §2，共 10 条，全部落地）

| # | 领域 | 摘要 |
|---|---|---|
| 1 | 消息模型 | 借用/零拷贝 vs 上游 `Vec<u8>` builder |
| 2 | MAPPED-ADDRESS 长度 | 严于上游：值长必须恰为 family 尺寸 |
| 3 | XOR-MAPPED 短 IPv6 | 同上，拒绝补零容忍 |
| 4 | 错误类型 | 统一 `rtx_wire::WireError`（4 变体） |
| 5 | 文本属性上限 | 同限值，错误映射 `InvalidValue` |
| 6 | ERROR-CODE reason | `Utf8Chunks` lossy 替代 std |
| 7 | MESSAGE-INTEGRITY 长期密钥 | 延至 M2（不新造 MD5 原语） |
| 8 | padding 字节 | 解码宽容、重编码归一化为零 |
| 9 | `compat_attr_type` | 同上游（仅解码侧） |
| 10 | 地址 Display | 不实现，断言字段 |

## 5. 遗留事项（移交 M2 / 后续里程碑）

| 事项 | 依赖 | 说明 |
|---|---|---|
| RFC 5389 §10.2 HMAC-SHA1 真实向量 | M2 `rtx-crypto` provider | `integrity.rs` 的 `MacFn` 已留好注入点，补 `full_test` 向量行 |
| 长期密钥 MD5 派生 | M2 `HashAlgorithm::Md5` | `MessageIntegrity::new_long_term` 构造函数 |
| ICE agent 层（优先级/候选/连通性检查） | 本 codec + M2 crypto | `ATTR_PRIORITY`/`USE-CANDIDATE`/`ICE-CONTROLLED/ING` 常量已就绪，TLV 由 `MessageWriter::push` 直接承载 |
| TURN 客户端语义（Allocate/ChannelData 生命周期） | 后续里程碑 | 属性常量已齐；`DATA`/`CHANNEL-NUMBER` 无专门 typed 模块（与上游架构一致） |

## 6. 复现命令

```bash
cd /workspace/rtx-rs
cargo test --workspace --features std                    # 327 tests
cargo check --workspace --no-default-features            # no_std 宿主
cargo check --workspace --no-default-features --target thumbv7em-none-eabihf
cargo clippy --workspace --all-targets --all-features    # pedantic 0 warning
cargo fmt --all -- --check
git log --oneline 8d1abe9..HEAD                          # M1-3a/b/c 三个提交
```
