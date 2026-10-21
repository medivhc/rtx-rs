# M2：真实密码学后端

> 状态：已落地（`rtx-crypto-rustcrypto`）
> 测试：18 条（7 条公开向量 + 11 条契约一致性），覆盖率 96.77%

## 1. 这一步解决什么问题

M1-5 给 `rtx-crypto` 补了 96 条五层测试，但那些测试全部跑在一个**确定性参考后端**（`RefCrypto`）上。它由确定性 LCG 驱动，长度与算法都是自己实现的。

这能证明一件事：**trait 契约是自洽的**。它证明不了另一件事：**真实后端是对的**。

一个自洽但错误的实���是完全可能的：

| 缺陷类型 | 参考后端能发现吗 |
|---|---|
| `seal` 在写 tag 前就改了 plaintext 区 | ✅ 能 |
| 被拒绝的调用污染了调用方缓冲 | ✅ 能 |
| AES-GCM 的 GHASH 多项式算错了 | ❌ **不能**——参考后端根本不做 GHASH |
| SHA-256 的第 63 轮常量抄错了 | ❌ **不能**——摘要长度对，内容错 |
| HMAC 的长密钥分支（key > block size）没做哈希 | ❌ **不能**——RFC 4231 case 6 才覆盖 |
| AES-256 悄悄复用了 AES-128 的密钥调度 | ❌ **不能** |

一旦接上真实后端、跑 DTLS 握手，这些缺陷会以「握手成功但双方解出的密钥不同」或者更糟的形式暴露。所以 M2 的目标很具体：**让真实后端对着公开的 FIPS / RFC / NIST 向量验收**。

## 2. 架构决策

### 2.1 为什么独立 crate

`rtx-crypto` 本身零依赖——它只定义六个能力 trait。加任何一个密码学库都会污染它。所以后端放在 `crates/rtx-crypto-rustcrypto`：

```
rtx-crypto            ← 只定义 trait，零依赖
    ▲
    │ 实现
rtx-crypto-rustcrypto ← aes-gcm / sha2 / sha1 / hmac / getrandom
```

这样做的三个后果：

1. **协议 crate 保持零依赖。** `rtx-rtcp` / `rtx-stun` / `rtx-rtp` 都不需要知道密码学实现存在。
2. **可以换provider 而不动协议层。** 硬件引擎（ATECC608、SE05）实现同样六个 trait 即可，DTLS 引擎无需改动。
3. **`no_std` 是可选的。** 依赖树里没有一个需要 C 工具链的 crate。

### 2.2 能力矩阵

| 能力 | trait | 实现 | 依据 |
|---|---|---|---|
| Hash | `HashProvider` | SHA-1 / SHA-256 / SHA-384 | `sha1`, `sha2` |
| HMAC | `HmacProvider` | HMAC-SHA1 / 256 / 384 | `hmac` |
| AEAD | `AeadProvider` | AES-128-GCM / AES-256-GCM | `aes-gcm` |
| Random | `RandomProvider` | OS CSPRNG（可选 feature） | `getrandom` |
| Signature | `SignatureProvider` | **未实现** → `Unsupported` | — |
| KeyExchange | `KeyExchangeProvider` | **未实现** → `Unsupported` | — |

签名与密钥交换**故意留空**。Ed25519 和 X25519 需要域运算，而本 crate 没有审计过那条路径的常数时间性。一个静默错的 DTLS 握手比一个明确拒绝糟糕得多——`CryptoError::Unsupported` 会让引擎在协商阶段就换 provider，而一个错误实现的握手会一路跑完然后解出垃圾。DTLS 引擎将来会带自己的 provider。

> `rtx_crypto::CryptoProvider` 这个聚合 trait 在这里**没有** impl：它的 `sign` / `generate_key` 关联类型是具体句柄类型，而本 provider 拒绝这些套件。取而代之的是一个编译期 trait 断言（`_AssertCapabilities`），列出真实实现的能力。

### 2.3 `getrandom` 为什么是可选依赖

`getrandom 0.2` 在没有注册熵后端的裸机 target 上会直接 `compile_error!`。这让 `--target thumbv7em-none-eabihf` 变成一个不可选项。

因此 `getrandom` 变成 optional dependency，由 `os-rng` feature 拉入：

| 构建 | `fill_random` 行为 |
|---|---|
| 主机（默认，`std` + `os-rng`） | 从 OS CSPRNG 取熵 |
| 固件（`no_std`，无 `os-rng`） | 返回 `CryptoError::Unsupported` |
| 固件（有硬件熵源） | 固件自带 provider，或自行启用后端 |

固件路径返回 `Unsupported` 而不是填零或用伪随机——DTLS 握手里一个可预测的 nonce 是灾难性的。

## 3. 验收向量

`tests/published_vectors.rs` 全部使用**公开规范**里的值，不是「跑一遍另一个实现看看」。

| 套件 | 来源 | 覆盖点 |
|---|---|---|
| SHA-1 / SHA-256 / SHA-384 | FIPS 180-4 B、FIPS 202 B.1 | `"abc"` 与空输入 |
| HMAC-SHA1 | RFC 2202 §2 | 20 字节 `0x0b` 密钥 |
| HMAC-SHA256 / SHA-384 | RFC 4231 §4 | 同上 |
| HMAC-SHA256 短密钥 / 长密钥 | RFC 4231 case 2 / case 6 | 131 字节密钥强制走「先哈希密钥」分支 |
| AES-128-GCM | NIST SP 800-38D case 3 / case 4 | 无 AAD / 有 AAD |
| AES-256-GCM | NIST SP 800-38D case 16 | 独立密钥调度 |

case 4 的存在尤其重要：它证明 AAD 真的被折进了 GHASH，而不是被忽略。DTLS 的 record 序号和握手transcript 都走这条路径。

`tests/contracts.rs` 覆盖 11 条契约，其中三条是 M1 发现的模式在真实后端上的复验：

1. **被拒绝的操作不改缓冲。** 尺寸不足、密钥长度错误、nonce 长度错误、认证失败——每一条都逐字节比对缓冲区。
2. **认证失败不解密。** 翻转 ciphertext 一个 bit、翻转 tag 一个 bit、截断、换 AAD、换密钥——五种都必须失败且缓冲不变。
3. **nonce 长度不对必须报错而不是截断。** 静默截断 nonce 是灾难性的，因为 GCM nonce 重用会泄漏密钥流。

## 4. 修掉的两个实现问题

写这个后端时暴露了两个与密码学无关的实现细节：

1. **`seal` 的溢出检查位置。** `plaintext_len.checked_add(TAG_LEN)` 必须先做，否则 `plaintext_len == usize::MAX` 会在分配前溢出。
2. **`open` 必须走 detached API。** `Aead::decrypt` 返回 `Vec<u8>`（一次堆分配，且失败时分配的内容不确定）；`decrypt_in_place_detached` 在**应用密钥流之前**就算好 tag 并常数时间比较，所以「认证失败不碰缓冲」这条契约是**由结构保证的**，不是靠测试观察出来的。这一点值得强调：如果换成 `decrypt` 的分配实现，测试仍然会通过，但契约就变成了运行时巧合而非类型保证。

## 5. CI 门禁

新增 `crypto-vectors` job（Gate 3b）：

- `cargo test -p rtx-crypto-rustcrypto --all-features` — 公开向量 + 契约
- `cargo check -p rtx-crypto-rustcrypto --no-default-features --target thumbv7em-none-eabihf` — 裸机无 OS RNG 仍可编译
- `cargo clippy -p rtx-crypto-rustcrypto --no-default-features -- -D warnings`

覆盖率基线从 96.32% 提到 96.38%（新 crate 96.77% 行覆盖 / 100% 函数覆盖，把总覆盖率**推高**了）。

## 6. 下一步

| 事项 | 说明 |
|---|---|
| DTLS 引擎 | 上面这层是为了它存在的。现在有了一个能跑真实向量、能通过 trait object 使用、且在裸机上可用的 provider |
| Ed25519 / X25519 provider | 需要审计常数时间性；建议独立 crate 或走 `curve25519-dalek` 的 `constant_time` feature |
| 硬件 provider | ATECC608 / SE05 等，实现同样六个 trait |
| `rtx-crypto` 的 proptest 扩展 | 目前 property 测试只跑参考后端，可以参数化到真实后端 |