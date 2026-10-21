# rtx-rs 项目进度报告（M0 → M2）

日期：2026-10-22（更新至 M2）
HEAD：`da34ad6` feat(crypto): M2 — real RustCrypto backend verified against published vectors
分支：`main` = `dev/m1-3-stun` = `da34ad6`（工作区 clean）

## 1. 里程碑总览

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | 7 个基础 crate 骨架 + 77 条契约测试，clippy-clean，no_std 验证 | ✅ 完成 |
| M1-1 | rtx-rtp + rtx-rtcp wire codec（上游差分向量） | ✅ 完成 |
| M1-2 | RTCP RFC 4585 feedback codec（NACK/TWCC/RRR/PLI/SLI/FIR/REMB） | ✅ 完成 |
| M1-3a | rtx-stun message 层 | ✅ 完成 |
| M1-3b | rtx-stun typed attributes（addr/xoraddr/text/uattr/error_code） | ✅ 完成 |
| M1-3c | rtx-stun trailer（FINGERPRINT + MESSAGE-INTEGRITY） | ✅ 完成 |
| M1-3 | 实现笔记 + 测试向量文档 | ✅ 完成 |
| M1-4 | 五层分层集成测试套件（120 条，4 crate） | ✅ 完成 |
| M1-5 | rtx-crypto 分层集成测试套件（96 条，五层） | ✅ 完成 |
| M2-0 | proptest L5 不变式 + fuzz targets + CI/覆盖率门禁 | ✅ 完成 |
| M2-0' | **fuzz 发现并修复 6 处真实解码缺陷**（RTCP×5 / STUN×1） | ✅ 完成 |
| M2 | 真实密码学后端 `rtx-crypto-rustcrypto`（18 条，公开向量验收） | ✅ 完成 |

## 2. 代码规模

- crates：8 个（rtx-buffer / core / crypto / crypto-rustcrypto / wire / stun / rtp / rtcp）
- 总行数：25,506 行 Rust
- 测试代码：9,527 行（`crates/*/tests/`），另有约 6,700 行内嵌 `#[cfg(test)]`

## 3. 测试现状

| 维度 | 数量 |
|---|---|
| M1-4 分层集成测试 | 120 |
| M1-5 分层集成测试（rtx-crypto） | 96 |
| M2 新增（rtx-crypto-rustcrypto） | 18 |
| **合计（--all-features）** | **583 passed / 0 failed** |
| 其中 proptest 性质 | 14 |

### M1-4 分层测试分布（五层）

| 层 | 含义 | 位置 | 数量 |
|---|---|---|---|
| L1 | public API 管线（decode → mutate → encode） | message_pipeline / header_pipeline / extension_pipeline / compound_pipeline | 42 |
| L2 | 跨 crate 协作 | addr_core_bridge / twcc_rtp_cross / codec_contract | 23 |
| L3 | 协议场景（ICE / TURN / RTCP 反馈） | ice_scenarios / turn_scenarios / feedback_reports | 35 |
| L4 | 健壮性与畸形输入 | 3× robustness.rs | 20 |
| L5 | 不变式与字节级往返 | `assert_verbatim` 家族 / crypto invariants.rs | 内嵌各层 + 17 |

### 按 crate 分布

| crate | 主要测试文件 | 数量 |
|---|---|---|
| rtx-rtcp | goodbye/pli/rrr/remb/twcc 回归 + compound_pipeline / feedback_reports / twcc_rtp_cross / robustness | **161** |
| rtx-stun | message_pipeline / turn_scenarios / ice_scenarios / robustness / addr_core_bridge | **147** |
| rtx-crypto | capability_pipeline / robustness / invariants / handshake_scenarios / buffer_core_bridge / properties | **127** |
| rtx-rtp | header_pipeline / extension_pipeline / robustness | 60 |
| rtx-wire | codec_contract | 32 |
| rtx-crypto-rustcrypto | published_vectors 7 / contracts 11 | **18** |

## 4. 质量门禁（当前全绿）

| 门禁 | 结果 |
|---|---|
| `cargo test --workspace --all-features` | **583 passed / 0 failed** |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 warnings |
| `cargo clippy --workspace --no-default-features -- -D warnings` | 0 warnings |
| `cargo fmt --check` | clean |
| `cargo check --workspace --no-default-features --target thumbv7em-none-eabihf` | 通过（no_std 裸机） |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::private_intra_doc_links" cargo doc` | 通过 |
| `cargo llvm-cov --workspace --all-features` | **96.38% 行 / 97.45% 区域 / 97.89% 函数** |
| 4 个 fuzz target（nightly + ASAN） | 零 crash，合计约 2,000 万次执行 |

### CI 门禁（6 个 job）

| Job | 作用 |
|---|---|
| `test` | stable 构建 / lint / fmt / doc（含 no_std 与裸机交叉编译） |
| `suite` | MSRV 1.85 + stable 双 profile 的 nextest 全量 |
| `coverage` | 覆盖率下限 **96.3%**（实测基线 96.38%） |
| `crypto-vectors` | 公开密码学向量 + 无 OS RNG 的裸机构建 |
| `proptest` | `PROPTEST_CASES=4096` 深度性质扫描 |
| `fuzz` | nightly 下 4 个 target 各 smoke 20 秒 + crash artifact 上传 |

## 5. 测试工程手法（借鉴 EasyTier）

- 每个 crate 一个 `tests/common/mod.rs` testkit，提供 `assert_verbatim`、`encode_msg`、确定性 xorshift64\* LCG（零 `rand` 依赖）
- 主题化测试目录 + 编号测试 ID，便于定位与统计
- 全部向量来自上游实现差分，非人工臆造
- `Box::leak` 构造 `&'static [u8]` 以测试需要生命周期的 API

## 6. fuzz 发现并修复的 6 处真实缺陷

这一节是本轮最重要的产出。fuzz 靶标不是「跑通就算」，它们把
`encode(decode(bytes)) == bytes` 这条不变式变成了断言——而这条不变式正是
MESSAGE-INTEGRITY / FINGERPRINT 校验所依赖的。6 个 crash 中 3 个是库的
真实缺陷，且**都是自洽但错误**：现有 543 条测试全绿，因为它们只测合法输入。

| # | crate | 根因 | 后果 |
|---|---|---|---|
| 1 | `rtx-rtcp` Goodbye | `raw_len()` 未做 32-bit 对齐，`length` 字段与实际写入字节数不自洽 | 3 字节 reason → 声称 8 字节、实写 11 字节；接收端按 length 切片会丢失尾部 |
| 2 | `rtx-rtcp` Goodbye | decode 接受 reason 之后的多余尾部，模型无处存放 | re-encode 静默丢字节 |
| 3 | `rtx-rtcp` PLI / RRR | 无 FCI 的定长包只做下限校验 | length 谎报的 24 字节包能解出，re-encode 截断成 12 字节 |
| 4 | `rtx-rtcp` REMB | 边界检查用 `input.len()` 而非 length 字段算出的 total | length 与 `ssrc_count` 矛盾时模型长度与 consumed 不符 |
| 5 | `rtx-rtcp` TWCC | delta 区之后的剩余字节未校验 | 多余整字被丢弃 / 缺失 padding 字节被凭空补上 |
| 6 | `rtx-stun` MessageType | `read_value` 丢弃 type 字段最高 2 位 | re-encode 把 `0x40..` 静默归一化成 `0x00..`；按 RFC 5389 §6，`01` 段是 TURN ChannelData 的标记，等于允许伪造跨复用边界的 type |

共同根因：**decoder 校验的是「输入够不够长」，而不是「输入是否恰好等于模型能表示的长度」**。
前者的包会被静默接受，后者的契约才是字节级往返。

修复后 4 个 target 累计约 2,000 万次执行零 crash。

## 7. 下一步建议

1. **DTLS 引擎** — M2 的真实 provider 就是为它准备的。现在已有能跑公开向量、能通过 trait object 使用、在裸机可编译的后端
2. **Ed25519 / X25519 provider** — 需要审计常数时间性；建议走 `curve25519-dalek` 的 `constant_time` feature 或独立 crate
3. **proptest 参数化到真实后端** — 目前 property 测试只跑确定性参考后端，真实后端只被固定向量覆盖；随机化能覆盖固定向量到不了的组合
4. **fuzz 语料库常驻** — 目前 smoke 跑 20 秒无持久语料；把历史 crash 输入固化为 regression 语料
5. **no_std 深化** — `rtx-rtp` / `rtx-rtcp` 的内嵌测试目前在 `--no-default-features` 下不运行，只验证可编译