# rtx-rs 项目进度报告

日期：2026-10-22
HEAD：`e5cdba2` M1-4: layered integration suite (120 tests, 4 crates, 5 levels)
分支：`main` = `dev/m1-3-stun` = `e5cdba2`（工作区 clean，已同步 origin）

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

## 2. 代码规模

- crates：7 个（rtx-buffer / core / crypto / wire / stun / rtp / rtcp）
- 总行数：20,245 行 Rust
- 测试代码：约 6,900 行（23 个文件，M1-4/5 新增）

## 3. 测试现状

| 维度 | 数量 |
|---|---|
| 单元 + 契约测试（src） | 327 |
| 新增分层集成测试（M1-4） | 120 |
| M1-5 新增（rtx-crypto） | 96 |
| 合计（--all-features） | **543 passed / 0 failed** |
| 默认 features 下 | 120 passed / 0 failed（集成层） |

### M1-4 分层测试分布（五层）

| 层 | 含义 | 位置 | 数量 |
|---|---|---|---|
| L1 | public API 管线（decode → mutate → encode） | message_pipeline / header_pipeline / extension_pipeline / compound_pipeline | 42 |
| L2 | 跨 crate 协作 | addr_core_bridge / twcc_rtp_cross / codec_contract | 23 |
| L3 | 协议场景（ICE / TURN / RTCP 反馈） | ice_scenarios / turn_scenarios / feedback_reports | 35 |
| L4 | 健壮性与畸形输入 | 3× robustness.rs | 20 |
| L5 | 不变式与字节级往返 | `assert_verbatim` 家族 / crypto invariants.rs | 内嵌各层 + 17 |

### 按 crate 分布

| crate | 测试文件 | 数量 |
|---|---|---|
| rtx-stun | message_pipeline 20 / turn_scenarios 16 / ice_scenarios 10 / robustness 9 / addr_core_bridge 7 | 62 |
| rtx-rtcp | compound_pipeline 10 / feedback_reports 9 / twcc_rtp_cross 6 / robustness 5 | 30 |
| rtx-rtp | header_pipeline 8 / extension_pipeline 4 / robustness 6 | 18 |
| rtx-wire | codec_contract 10 | 10 |
| rtx-crypto | capability_pipeline 30 / robustness 21 / invariants 17 / handshake_scenarios 15 / buffer_core_bridge 13 | 96 |

## 4. 质量门禁（当前全绿）

- `cargo test --workspace --all-features`：543 passed / 0 failed
- `cargo clippy --all-targets --all-features -- -D warnings`：0 warnings
- `cargo fmt --check`：clean
- `cargo build --workspace --no-default-features`：通过（no_std 兼容）
- `git status`：clean

## 5. 测试工程手法（借鉴 EasyTier）

- 每个 crate 一个 `tests/common/mod.rs` testkit，提供 `assert_verbatim`、`encode_msg`、确定性 xorshift64\* LCG（零 `rand` 依赖）
- 主题化测试目录 + 编号测试 ID，便于定位与统计
- 全部向量来自上游实现差分，非人工臆造
- `Box::leak` 构造 `&'static [u8]` 以测试需要生命周期的 API

## 6. 下一步建议

1. ✅ M1-5 已完成：rtx-crypto 补齐 96 条五层测试
2. **L5 深化**：把字节级不变式从内嵌断言提升为独立 property-based 测试（proptest / quickcheck）
3. **fuzz 常态化**：把 L4 的畸形输入样例沉淀为 `fuzz/` target，纳入 CI nightly
4. **no_std 深化**：rtx-rtp / rtx-rtcp 补 `#![no_std]` 单元测试覆盖（`--no-default-features` 下目前仅验证可编译）
5. **CI**：接入 `cargo nextest` + `cargo llvm-cov`，对覆盖率设门禁