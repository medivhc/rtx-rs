# M4 目标选择文档（门禁 §2.0 M4-0-1）

| 项 | 内容 |
|---|---|
| 文档编号 | P8-1 / M4-0-1 |
| 基线 | `main` @ `37a2a8a`（P7 合并点） |
| 交付形态 | 只新增本文档；不写固件、不改 CI、不移植、不做 M4-Q/R/M/S |
| 候选数量 | 3：STM32H723ZG / NUCLEO-H723ZG；STM32F767ZI / NUCLEO-F767ZI；MIMXRT1062DVL6A / MIMXRT1060-EVK |
| 结论 | **未选定**（无候选通过 V1–V10 全项；缺口 `GAP-M4-T-01` … `GAP-M4-T-08`） |
| 门禁条目 | `M4-T1`–`M4-T8`、`M4-V1`–`M4-V10`、`M4-0-1`–`M4-0-5`，见 [docs/m3-m4-gates.md §2.0](https://github.com/medivhc/rtx-rs/blob/37a2a8a/docs/m3-m4-gates.md) |

> **状态声明**：本文档合并 ≠ M4-0 通过。M4-0 仍需 `M4-0-2`（最小启动固件链接出 ELF）、`M4-0-3`（`embedded-build` CI 绿）、`M4-0-4`（板上最小固件启动输出）三项证据；`M4-0-5` 由本文档合并时间与后续 PR 时间线证明。M4-Q 决策、M4-R 预算、M4-M 内存、M4-S 移植范围均未开始。`rtx-quic` 的 Linux 外观不因本文档而获得任何嵌入式背书。

---

## 1. 范围与判定口径

### 1.1 本单范围

- 只新增 `docs/m4-target-selection.md`。不改任何 `crates/*` 源码、`benchmarks/*`、`interop/*`、CI、已有文档正文、门禁文档、根 `Cargo.toml`/`Cargo.lock`。
- 不新建 `firmware/`、不新建代码、脚本、CI 作业、图片、证书或二进制文件。
- 不做 M4-Q 决策、M4-R 预算、M4-M 内存报告、M4-S 移植范围；不移植/裁剪 `quinn-proto`；不写 HAL/抽象层；不提议新增密码学原语；不改门禁条文与复选框。

### 1.2 三态定义

| 状态 | 含义 | 允许的证据 |
|---|---|---|
| 通过 | 该要求已被可定位来源覆盖 | 数据手册 URL + 页码/章节；厂商文档 URL + 页码/章节；仓库文件路径；可复跑命令输出 |
| 未核实 | 来源不足，或所需实验尚未做 | 写明缺什么、到哪份手册/哪项实测去核实 |
| 否决 | 命中某个 V 条目 | V 条目号 + 证据指针 |

任何含糊措辞一律按“未核实”处理，不得计入通过。通过/未核实/否决不得混用。

### 1.3 门禁条目对照

| ID | 本文件对应位置 | 判定对象 |
|---|---|---|
| M4-T1 | §3 各候选 T1 行 | 具体型号、核心、主频、封装、开发板型号 + 数据手册页码 |
| M4-T2 | §3 各候选 T2 行 | 属于 ARCH §4 的 Tier B 或 Tier C |
| M4-T3 | §3 各候选 T3 行 | SRAM、Flash、外部 RAM、启动/RTOS 占用估算 |
| M4-T4 | §3 各候选 T4 行 | MAC/PHY、链路 MTU、网络栈路径与缓冲区所有权 |
| M4-T5 | §3.4 T5 映射表 + 各候选 T5 行 | 硬件加速器/软件性能、`rtx-crypto` provider 映射 |
| M4-T6 | §3.5 T6 映射表 + 各候选 T6 行 | 定时器存在性、分辨率、位宽、溢出、`Timestamp` 映射 |
| M4-T7 | §3 各候选 T7 行 | target triple、调试探针、CI 板卡、可链接性 |
| M4-T8 | §3 各候选 T8 行 | 可购买性、供应商 SDK/RTOS、生命周期 |
| M4-V1–M4-V10 | §4 各候选 V 表 | 逐条三态结论 |
| M4-0-1–M4-0-5 | §5.5、§6 | 本单只覆盖 M4-0-1；其余四项未做 |

### 1.4 基线现状证据（37a2a8a）

- 根 `Cargo.toml` 的 workspace 成员为 15 个；其中无 `rtx-smoltcp`、无 `firmware` 成员。来源：[Cargo.toml](https://github.com/medivhc/rtx-rs/blob/37a2a8a/Cargo.toml)。
- `crates/` 下无 `rtx-smoltcp` 目录；`rtx-smoltcp` 只是 ARCH §5 的规划名。来源：[ARCHITECTURE.md §5](https://github.com/medivhc/rtx-rs/blob/37a2a8a/ARCHITECTURE.md)、[crates 目录](https://github.com/medivhc/rtx-rs/tree/37a2a8a/crates)。
- `crates/rtx-quic/Cargo.toml` 明写该 crate 是 Tier D（`std`，Linux）外观；关闭默认特性时编译为空；`quinn-proto` 需要 `std`；不声称任何嵌入式 QUIC 支持。来源：[crates/rtx-quic/Cargo.toml](https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-quic/Cargo.toml)。
- 现有 CI 只有 `cargo check --target thumbv7em-none-eabihf`（`test` 作业第 4 步，另有 `crypto-vectors` 作业的同 target `cargo check`），没有 `embedded-build` / `embedded-lint` / `embedded-size` / `embedded-smoke` / `embedded-memory` 作业，也不链接、不产 ELF。来源：[.github/workflows/ci.yml](https://github.com/medivhc/rtx-rs/blob/37a2a8a/.github/workflows/ci.yml)、[门禁 §2.4](https://github.com/medivhc/rtx-rs/blob/37a2a8a/docs/m3-m4-gates.md)。
- 本文档起草前，`docs/`、`ARCHITECTURE.md`、`DEPENDENCY_AUDIT.md` 中没有已选定的 M4 目标型号/开发板记录；仓库内没有 `firmware/` 目录。本文档不把“已有 thumbv7em check”写成任何候选的 T7 通过证据。

### 1.5 证据边界

- 本文档的硬件数值只来自数据手册或板卡用户手册的指定页码；采购事实只来自厂商产品页/授权分销商页面；SDK/RTOS 只来自厂商文档链接；CI 板卡只认 runner 标签/资产编号。
- 沙箱内没有开发板、没有调试探针、没有采购订单；本文档不声称买过、跑过、烧录过任何板卡，也不声称联系过供应商。
- 本文档不做链接实验，不冒充 `M4-0-2`；不跑板，不冒充 `M4-0-4`；不建 `embedded-build`，不冒充 `M4-0-3`。

---

## 2. 候选与筛选方法

### 2.1 筛选规则

1. 只接受 ARCH §4 的 Tier B（`no_std + heapless`）或 Tier C（`no_std + alloc`）目标；Tier D 的 Linux/应用处理器目标按 `M4-V2` 直接排除，不进入候选表。
2. 候选表合计至少 2 个；落选候选保留在表中，附 V 条目，不删表凑数。
3. 先查数据手册与板卡手册，再谈 SDK/生态；无数据手册页码的数值不进入正文。
4. 不预选目标、不拍脑袋；不把“先 Linux 验证再移植”当作 M4 目标。
5. 被 V 否决的候选不以“可规避”“后续可解”“换一块板”保留在选中池；若未来换板，须作为新候选重新登记 T1–T8。

### 2.2 候选清单

| 编号 | MCU | 开发板 | Tier（ARCH §4） | 本文档状态 |
|---|---|---|---|---|
| A | STM32H723ZG（板载 STM32H723ZGT6） | NUCLEO-H723ZG | Tier C 上限；Tier B 子集未核实 | 未完成核实，保留候选 |
| B | STM32F767ZI（板载 STM32F767ZIT6） | NUCLEO-F767ZI | Tier C 上限；Tier B 子集未核实 | 未完成核实，保留候选 |
| C | MIMXRT1062DVL6A | MIMXRT1060-EVK | Tier C 上限 | `M4-V9` 否决，落选 |

> Tier 归属说明：ARCH §4 的 Tier B/C 描述的是软件能力边界（heapless vs alloc），不是芯片厂商的官方分类。本文档把三款 Cortex-M7 MCU 记为“Tier C 上限”，理由是它们可在 `no_std` 下运行且具备接受动态存储的 RAM 容量；是否真的能以 Tier B 的 heapless 方式承载目标组件，须由 M4-R/M4-S 逐组件核实，本文档不预判。

---

## 3. 候选表（T1–T8）

### 3.0 汇总矩阵

| 候选 | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 | 通过/未核实/否决 |
|---|---|---|---|---|---|---|---|---|---|
| A STM32H723ZG | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 2 / 6 / 0 |
| B STM32F767ZI | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 2 / 6 / 0 |
| C MIMXRT1062DVL6A | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 未核实 | 2 / 6 / 0 |

> 引用说明：本节用 DS13313、DS11532、IMXRT1060CEC、UM2407、UM1974、UM11151 的文档编号 + 页码引用；完整 URL、版本与页码映射见 §7.1 的 S1–S6。正文每个数值都可按“文档编号 + 页码”在来源清单反查；不在清单中的数值不进入正文。

### 3.1 候选 A：STM32H723ZG / NUCLEO-H723ZG

| 项 | 状态 | 证据与说明 |
|---|---|---|
| T1 具体型号 | 通过 | MCU 家族 STM32H723ZG；板载型号 STM32H723ZGT6（订购信息见 UM2407 第 8 页，[UM2407](https://www.st.com/resource/en/user_manual/um2407-stm32h7-nucleo144-boards-stmicroelectronics.pdf)）。核心 Arm Cortex-M7，最高 550 MHz；封装含 LQFP144（[DS13313 Rev 5 第 1–2 页](https://www.st.com/resource/en/datasheet/stm32h723zg.pdf)）。开发板 NUCLEO-H723ZG（UM2407 第 7–8 页；[ST 产品页](https://www.st.com/en/evaluation-tools/nucleo-h723zg.html)）。 |
| T2 capability tier | 通过 | 记为 Tier C 上限（`no_std + alloc`），对应 ARCH §4 Tier C；Tier B 的 heapless 子集是否可行，须由 M4-R/M4-S 核实，本文档不记通过。来源：[ARCHITECTURE.md §4](https://github.com/medivhc/rtx-rs/blob/37a2a8a/ARCHITECTURE.md)。 |
| T3 内存/Flash | 未核实 | 手册数值：片上 Flash 最高 1 MB；SRAM 总计 564 KB（128 KB DTCM + 432 KB system RAM + 4 KB backup）（DS13313 第 1 页；第 14 页给出 192 KB shared + 64 KB ITCM + 128 KB AXI + 128 KB DTCM + 48 KB AHB + 4 KB backup）。FMC 支持外部 SRAM/PSRAM/SDRAM（第 1 页），但板卡未在 UM2407 功能页列出外部 RAM，是否预留未核实。**缺**：启动/RTOS 占用估算、静态占用 + 最小栈 + 最小堆下界；未链接 ELF、无 map 文件。核实方法：`M4-0-2` 链接后读 `.text/.rodata/.data/.bss` 与 map，再按 M4-R 建预算。 |
| T4 网络 | 未核实 | MAC：Ethernet MAC with DMA controller（DS13313 第 2 页）；Ethernet interface（第 14 页）。板卡 PHY：LAN8742A-CZ-TR（U15）+ RJ45（CN14），RMII（UM2407 §7.6.7 第 30 页；§8.3 第 37 页）。**缺**：链路 MTU 数值未在数据手册/板卡手册给出；`rtx-smoltcp` 未实现（根 Cargo.toml 15 个成员中无该 crate）；厂商 TCP/IP 中间件路径的缓冲区所有权未评审。核实方法：接入 `rtx-smoltcp` + MAC/PHY 驱动后，以 RFC 9000 §3 的 1200 字节 UDP 负载实测，并记录缓冲区归属。 |
| T5 密码学 | 未核实 | 手册功能页列 TRNG、CRC、ROP/PC-ROP（DS13313 第 2 页）；未列 AES/HASH/CRYP。不能把“功能页未列”写成“硬件不存在”，需查参考手册逐节确认。软件路径：`rtx-crypto-rustcrypto` 为 `no_std + alloc`，覆盖 AES-128/256-GCM、SHA-1/256、HMAC，但未实现 Ed25519/X25519/ECDSA（[lib.rs](https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-crypto-rustcrypto/src/lib.rs)）。映射见 §3.4。**缺**：目标上的 provider adapter、TRNG 驱动、签名/KEX provider、性能与栈占用测量。 |
| T6 时间 | 未核实 | 定时器：24 个定时器，其中十七个 16 位、四个 32 位，另有 SysTick；RTC 具亚秒精度（DS13313 第 1–2 页）。**缺**：分辨率/分频、位宽使用方式、溢出扩展与 `Timestamp(u64)` 映射均无驱动与实测；数据手册未给固定 tick 频率。核实方法：在 `M4-0-2` 最小固件中把 32 位定时器配置为微秒 tick，验证 2^32 计数回绕后的 u64 扩展与饱和运算。 |
| T7 工具链/CI | 未核实 | target triple：`thumbv7em-none-eabihf` 在稳定版 Rust 目标列表（§7.1 命令输出）。调试探针：板载 STLINK-V3E（UM2407 第 7 页；§7.3 第 18 页）。**缺**：未做链接实验；CI 无 `embedded-build`；无 runner 标签/资产编号。核实方法：`M4-0-2` 链接 ELF + `M4-0-3` CI 作业 + 板卡资产登记。 |
| T8 可获得性 | 未核实 | 采购：Digi-Key `497-NUCLEO-H723ZG-ND`，Part Status Active、In-Stock（[Digi-Key](https://www.digikey.com/en/products/detail/stmicroelectronics/NUCLEO-H723ZG/13171214)）；ST 板卡页 Active / volume production。生命周期：STM32H723ZGT6 的 ST 产品页显示 Longevity Commitment 10 年、起始 2026-01-01；NUCLEO-H723ZG 板卡页的 Longevity Commitment 与 Longevity Starting Date 均为 `-`。SDK/RTOS：STM32CubeH7（HAL、RTOS、TCP/IP 等中间件）与 X-CUBE-AZRTOS-H7（含 NUCLEO-H723ZG 示例）。**缺**：板卡级 longevity 承诺、项目周期定义；无法判定“满足项目周期”。 |

### 3.2 候选 B：STM32F767ZI / NUCLEO-F767ZI

| 项 | 状态 | 证据与说明 |
|---|---|---|
| T1 具体型号 | 通过 | MCU 家族 STM32F767ZI；板载 STM32F767ZIT6（UM1974 第 7 页订购表，[UM1974](https://www.st.com/resource/en/user_manual/dm00244518-stm32-nucleo144-boards-mb1137-stmicroelectronics.pdf)）。核心 Arm Cortex-M7，最高 216 MHz；封装含 LQFP144；Flash 最高 2 MB；SRAM 512 KB + 16 KB ITCM + 4 KB backup（[DS11532 Rev 7 第 1–2 页](https://www.st.com/resource/en/datasheet/stm32f767zi.pdf)）。开发板 NUCLEO-F767ZI（UM1974 第 7 页；[ST 产品页](https://www.st.com/en/evaluation-tools/nucleo-f767zi.html)）。 |
| T2 capability tier | 通过 | 记为 Tier C 上限，对应 ARCH §4 Tier C；Tier B 子集未核实。来源：[ARCHITECTURE.md §4](https://github.com/medivhc/rtx-rs/blob/37a2a8a/ARCHITECTURE.md)。 |
| T3 内存/Flash | 未核实 | 手册数值：Flash 最高 2 MB；SRAM 512 KB（含 128 KB DTCM）+ 16 KB instruction TCM + 4 KB backup（DS11532 第 1 页）；FMC 支持外部 SRAM/PSRAM/SDRAM（第 1 页）。**缺**：启动/RTOS 占用估算、静态 + 栈 + 堆下界；未链接 ELF、无 map。核实方法同 A。 |
| T4 网络 | 未核实 | MAC：10/100 Ethernet MAC with dedicated DMA，支持 IEEE 1588v2，MII/RMII（DS11532 第 1 页；§3.32 第 46 页）。板卡 PHY：LAN8742A-CZ-TR（U9）+ RJ45（CN14），RMII（UM1974 §7.11 第 29 页）。**缺**：MTU 数值未在手册给出；`rtx-smoltcp` 未实现；厂商 TCP/IP 中间件缓冲区所有权未评审。核实方法同 A。 |
| T5 密码学 | 未核实 | 手册功能页仅列 True random number generator（DS11532 第 1 页；§3.39 第 49 页），未列 AES/HASH/CRYP；需查参考手册确认。软件路径同 A（`rtx-crypto-rustcrypto` 覆盖 AES-GCM/SHA/HMAC，未实现签名/KEX）。**缺**：provider adapter、TRNG 驱动、签名/KEX provider、性能测量。 |
| T6 时间 | 未核实 | 定时器：最多 18 个定时器，其中最多十三个 16 位、两个 32 位，另有 SysTick；RTC 亚秒精度（DS11532 第 1 页；§3.23 第 38 页）。**缺**：分辨率/分频、溢出扩展、`Timestamp(u64)` 映射的驱动与实测。核实方法同 A。 |
| T7 工具链/CI | 未核实 | target triple：`thumbv7em-none-eabihf` 在稳定版 Rust 目标列表（§7.1）。调试探针：板载 ST-LINK/V2-1（UM1974 第 6 页；§7.3 第 17 页）。**缺**：未做链接实验；CI 无 `embedded-build`；无 runner 标签/资产编号。 |
| T8 可获得性 | 未核实 | 采购：Digi-Key `497-16525-ND`，Part Status Active、In-Stock（[Digi-Key](https://www.digikey.com/en/products/detail/stmicroelectronics/NUCLEO-F767ZI/6004740)）；ST 板卡页 Active / volume production。生命周期：STM32F767ZIT6 的 ST 产品页显示 Longevity Commitment 10 年、起始 2026-01-01；NUCLEO-F767ZI 板卡页的 Longevity Commitment 与 Longevity Starting Date 均为 `-`。SDK/RTOS：STM32CubeF7（HAL/LL + RTOS/TCP-IP 中间件）。**缺**：板卡级 longevity 承诺、项目周期定义；无法判定“满足项目周期”。 |

### 3.3 候选 C：MIMXRT1062DVL6A / MIMXRT1060-EVK

| 项 | 状态 | 证据与说明 |
|---|---|---|
| T1 具体型号 | 通过 | MCU MIMXRT1062DVL6A，Arm Cortex-M7，最高 600 MHz，196-pin MAPBGA 10 × 10 mm、0.65 mm pitch；订购表见 DS 第 7 页（[IMXRT1060CEC Rev 4 第 1、7 页](https://cache.nxp.com/docs/en/nxp/data-sheets/IMXRT1060CEC.pdf)）。开发板 MIMXRT1060-EVK（板载 MIMXRT1062DVL6A，[UM11151 第 1 页](https://www.mouser.com/pdfdocs/NXP_MIMXRT1060-EVK_UG.pdf)）。 |
| T2 capability tier | 通过 | 记为 Tier C 上限，对应 ARCH §4 Tier C；Tier B 子集未核实。来源：[ARCHITECTURE.md §4](https://github.com/medivhc/rtx-rs/blob/37a2a8a/ARCHITECTURE.md)。 |
| T3 内存/Flash | 未核实 | 手册数值：1 MB on-chip RAM（512 KB OCRAM shared between ITCM/DTCM and OCRAM + 512 KB dedicated OCRAM）；128 KB boot ROM；数据手册功能页未列片上应用 Flash；外部接口含 8/16-bit SDRAM、SPI NOR/NAND、Quad SPI（DS 第 1–2 页）。板卡：64 Mbit QSPI NOR（默认板载 Flash）+ 256 Mbit SDRAM（UM11151 第 1、8–9 页）。**缺**：启动/RTOS 占用估算、静态 + 栈 + 堆下界；未链接 ELF、无 map。 |
| T4 网络 | 未核实 | MAC：两个 10/100 Ethernet controller，支持 IEEE 1588（DS 第 4 页）；ENET 模块支持 10/100 Mbit/s Ethernet/IEEE 802.3，需外部 transceiver（DS 第 14 页）。板卡：KSZ8081RNB 10/100 Ethernet Transceiver（U16）+ RJ45（J19）（UM11151 第 9 页）。**缺**：MTU 数值未在手册给出；`rtx-smoltcp` 未实现；厂商 SDK 网络驱动路径的缓冲区所有权未评审。 |
| T5 密码学 | 未核实 | 硬件：DCP 支持 AES-128 ECB/CBC、SHA-1/SHA-256、CRC-32；BEE 支持 AES-128 ECB/CTR；TRNG（DS 第 4 页）。DCP 列表未列 AES-GCM/ECC/X25519。软件路径同 A；`rtx-crypto-rustcrypto` 覆盖 AES-GCM/SHA/HMAC，未实现签名/KEX。**缺**：provider adapter、DCP 映射、性能测量。 |
| T6 时间 | 未核实 | 定时器：2 × GPT（4-channel generic 32-bit resolution timer）、4 × PIT（generic 32-bit resolution timer）、4 × QTimer（16-bit）（DS 第 2 页；§4.10 第 83 页）。**缺**：分辨率/分频、溢出扩展、`Timestamp(u64)` 映射的驱动与实测。 |
| T7 工具链/CI | 未核实 | target triple：`thumbv7em-none-eabihf` 在稳定版 Rust 目标列表（§7.1）。调试探针：OpenSDA with DAP-Link / CMSIS-DAP（UM11151 第 9 页），另有 JTAG 20-pin（第 10 页）。**缺**：未做链接实验；CI 无 `embedded-build`；无 runner 标签/资产编号；板卡已停产（见 T8/V9）。 |
| T8 可获得性 | 未核实 | 采购：NXP 产品页标注 **No Longer Manufactured**，Buy Options 为 **No items available**（[NXP MIMXRT1060-EVK](https://www.nxp.com/part/MIMXRT1060-EVK)）；MCU MIMXRT1062DVL6A 标注 **Not Recommended for New Designs**，替代为 MIMXRT1062DVL6B（[NXP MIMXRT1062DVL6A](https://www.nxp.com/part/MIMXRT1062DVL6A)）。SDK：MCUXpresso SDK 文档页为 MIMXRT1060-EVKB（DVL6B），显示 FreeRTOS/lwIP 支持（[vendor docs](https://docs.mcuxpresso.nxp.com/mcuxsdk/latest/boards/RT/evkbmimxrt1060/index.html)）；这是家族 SDK 证据，不是候选 C 的 EVK/DVL6A 板级支持证据。**判定**：可购买性与生命周期不成立，T8 未核实，V9 否决（§4.3）。 |

### 3.4 T5 密码学 provider 映射（三候选共用）

`rtx-crypto` 现有 trait：[RandomProvider、HashProvider、HmacProvider、Aes128BlockProvider、AeadProvider、SignatureProvider、KeyExchangeProvider、CryptoProvider](https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-crypto/src/lib.rs)。算法枚举含 AES-128/256-GCM、SHA-1/256/384、ECDSA P-256/P-384、Ed25519、P-256/P-384/X25519。没有新增原语。

| trait | 候选 A（H723） | 候选 B（F767） | 候选 C（RT1060） |
|---|---|---|---|
| `RandomProvider` | 硬件 TRNG（DS13313 p2）；驱动未实现 | 硬件 TRNG（DS11532 p1）；驱动未实现 | 硬件 TRNG（IMXRT1060CEC p4）；驱动未实现 |
| `HashProvider` | 功能页未列 SHA 加速；软件 | 功能页未列 SHA 加速；软件 | DCP SHA-1/SHA-256（p4）；SHA-384 软件 |
| `HmacProvider` | 软件（基于 SHA） | 软件 | 软件（DCP 未列 HMAC） |
| `Aes128BlockProvider` | 功能页未列 AES 加速；软件 | 功能页未列 AES 加速；软件 | DCP AES-128 ECB（p4） |
| `AeadProvider` | 软件 AES-GCM | 软件 AES-GCM | DCP 未列 GCM；软件 AES-GCM |
| `SignatureProvider` | 功能页未列 ECDSA/Ed25519 硬件；无 provider 实现 | 功能页未列 ECDSA/Ed25519 硬件；无 provider 实现 | DCP 未列 ECDSA/Ed25519；无 provider 实现 |
| `KeyExchangeProvider` | 功能页未列 P-256/P-384/X25519 硬件；无 provider 实现 | 功能页未列 P-256/P-384/X25519 硬件；无 provider 实现 | DCP 未列 P-256/P-384/X25519；无 provider 实现 |

**结论**：三候选都能通过现有 trait 表达 `rtx-crypto` 已定义的算法集合，不需要新增原语（`M4-V7` 接口层面通过）；但 T5 要的“硬件加速器/可测软件性能 + provider 映射可得”没有闭环——`rtx-crypto-rustcrypto` 只覆盖 AES-GCM/SHA/HMAC，签名与 KEX 没有 provider 实现，三候选也都没有目标上的 adapter 与性能记录。因此 T5 一律记“未核实”。

### 3.5 T6 时间映射（三候选共用）

`rtx_core::Timestamp(u64)` 是单调微秒，提供 `from_micros`、饱和 `saturating_duration_since` 等操作（[rtx-core/src/lib.rs](https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-core/src/lib.rs)；ARCH §8）。

| 候选 | 定时器硬件（手册页码） | 位宽/溢出 | 到 `Timestamp` 的映射 | 状态 |
|---|---|---|---|---|
| A | 4 × 32-bit + 17 × 16-bit + SysTick（DS13313 p1–2） | 32 位计数器在 2^32 个计数后回绕（计算值）；需软件扩展高 32 位 | 微秒 tick → `Timestamp::from_micros`；溢出时高字递增；饱和算术 | 未核实：分频/tick 频率、驱动、溢出测试均未做 |
| B | 2 × 32-bit + 最多 13 × 16-bit + SysTick（DS11532 p1） | 同上 | 同上 | 未核实 |
| C | 2 × GPT 32-bit + 4 × PIT 32-bit（IMXRT1060CEC p2） | 同上 | 同上 | 未核实 |

> “微秒 tick”是设计假设，不是数据手册给出的固定频率；具体分频值必须在 `M4-0-2` 的最小固件里配置并实测。本文档不把该假设写成已核实。

---

## 4. 否决结论表（V1–V10）

### 4.0 汇总矩阵

| 候选 | V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 | 通过/未核实/否决 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A STM32H723ZG | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 通过 | 通过 | 通过 | 通过 | 6 / 4 / 0 |
| B STM32F767ZI | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 通过 | 通过 | 通过 | 通过 | 6 / 4 / 0 |
| C MIMXRT1062DVL6A | 通过 | 通过 | 未核实 | 未核实 | 未核实 | 未核实 | 通过 | 通过 | 否决 | 通过 | 5 / 4 / 1 |

### 4.1 候选 A：STM32H723ZG / NUCLEO-H723ZG

| V | 状态 | 结论与证据/核实方法 |
|---|---|---|
| V1 | 通过 | 具体 MCU/板/封装/主频齐全（§3.1 T1；DS13313 p1–2；UM2407 p7–8）。 |
| V2 | 通过 | Tier C（`no_std + alloc`），对应 ARCH §4 Tier C；不是 Tier D（§3.1 T2）。 |
| V3 | 未核实 | 条件性否决依赖 M4-Q 结论，M4-Q 未开始；链路 MTU 数值未在手册给出。核实方法：完成 M4-Q 的 QC1–QC10 与应用画像，冻结 QUIC required/optional/absent；若 required，再以 1200 字节 UDP 负载实测。 |
| V4 | 未核实 | “数据手册资源上限低于静态 + 最小栈 + 最小堆下界”无法判定：M4-R 预算未开始，T3 占用估算未做。核实方法：M4-R + `M4-0-2` ELF/map。 |
| V5 | 未核实 | `thumbv7em-none-eabihf` 在稳定版目标列表，但未做链接实验；CI 无 `embedded-build`。核实方法：`M4-0-2` 链接 ELF + `M4-0-3` CI 绿。 |
| V6 | 未核实 | 仓库无 `rtx-smoltcp`；厂商 TCP/IP 中间件路径的缓冲区所有权与 Sans-I/O 边界未评审。核实方法：实现/接入 `rtx-smoltcp` + MAC/PHY 驱动，评审缓冲区归属（ARCH §7）。 |
| V7 | 通过 | `rtx-crypto` 现有 trait 覆盖 Random/Hash/HMAC/AES block/AEAD/Signature/KEX；不新增原语；软件 provider 为 `no_std + alloc`。实现与性能缺口记在 T5，不改变 V7 的接口判定。 |
| V8 | 通过 | 32 位定时器 + SysTick 存在（DS13313 p1–2）；32 位宽度加软件扩展可提供单调 u64 微秒模型（ARCH §8）。驱动/分频缺口记在 T6。 |
| V9 | 通过 | 开发板可购买：Digi-Key `497-NUCLEO-H723ZG-ND`，Part Status Active、In-Stock；ST 产品页 Active/volume production。CI 实物资产缺失按 T7 未核实登记，不把“尚未采购”写成“不可购买”。 |
| V10 | 通过 | STM32CubeH7 为裸机 C HAL + RTOS 中间件，不存在动态链接/非 Rust 异常模型的运行前提；具体 Rust 集成路径（Rust HAL 或 FFI）属后续单。 |

**结果**：V1/V2/V7/V8/V9/V10 通过；V3/V4/V5/V6 未核实。未达到 V1–V10 全项通过，不能进入选中池。

### 4.2 候选 B：STM32F767ZI / NUCLEO-F767ZI

| V | 状态 | 结论与证据/核实方法 |
|---|---|---|
| V1 | 通过 | 具体 MCU/板/封装/主频齐全（§3.2 T1；DS11532 p1–2；UM1974 p7）。 |
| V2 | 通过 | Tier C（`no_std + alloc`），对应 ARCH §4 Tier C；不是 Tier D。 |
| V3 | 未核实 | 同 A：M4-Q 未开始；MTU 数值未在手册给出。 |
| V4 | 未核实 | 同 A：M4-R 预算与 T3 占用估算未做。 |
| V5 | 未核实 | target 在稳定版列表；未做链接实验；CI 无 `embedded-build`。 |
| V6 | 未核实 | 无 `rtx-smoltcp`；厂商 TCP/IP 中间件缓冲区所有权未评审。 |
| V7 | 通过 | 同 A：现有 provider trait 足够，不新增原语；T5 实现缺口另记。 |
| V8 | 通过 | 2 × 32-bit + SysTick（DS11532 p1）；映射设计可行；T6 驱动缺口另记。 |
| V9 | 通过 | Digi-Key `497-16525-ND`，Part Status Active、In-Stock；ST 产品页 Active/volume production。CI 实物资产缺失按 T7 未核实。 |
| V10 | 通过 | STM32CubeF7 为裸机 C HAL/LL + RTOS 中间件；无动态链接/非 Rust 异常模型前提。 |

**结果**：V1/V2/V7/V8/V9/V10 通过；V3/V4/V5/V6 未核实。未达到 V1–V10 全项通过，不能进入选中池。

### 4.3 候选 C：MIMXRT1062DVL6A / MIMXRT1060-EVK

| V | 状态 | 结论与证据/核实方法 |
|---|---|---|
| V1 | 通过 | 具体 MCU/板/封装/主频齐全（§3.3 T1；IMXRT1060CEC p1、p7；UM11151 p1）。 |
| V2 | 通过 | Tier C（`no_std + alloc`），对应 ARCH §4 Tier C；不是 Tier D。 |
| V3 | 未核实 | M4-Q 未开始；MTU 数值未在手册给出。 |
| V4 | 未核实 | M4-R 预算与 T3 占用估算未做。 |
| V5 | 未核实 | target 在稳定版列表；未做链接实验；CI 无 `embedded-build`。 |
| V6 | 未核实 | 无 `rtx-smoltcp`；厂商 SDK 网络驱动路径的缓冲区所有权未评审。 |
| V7 | 通过 | 现有 provider trait 覆盖算法，不新增原语；DCP 只覆盖部分硬件路径，软件 provider 补足，T5 仍记未核实。 |
| V8 | 通过 | 2 × GPT 32-bit + 4 × PIT 32-bit（IMXRT1060CEC p2）；映射设计可行；T6 驱动缺口另记。 |
| **V9** | **否决** | **NXP 产品页标注 MIMXRT1060-EVK 为 No Longer Manufactured，Buy Options 为 No items available；MCU MIMXRT1062DVL6A 标注 Not Recommended for New Designs，替代为 DVL6B。无法满足 M4-M 的板上实测与长期 CI 实物要求。** 不以 EVKB/EVKC 替换来规避该否决；若未来采用新板，须作为新候选重新登记 T1–T8。 |
| V10 | 通过 | MCUXpresso SDK 为裸机 C + FreeRTOS，无动态链接/非 Rust 异常模型前提。 |

**结果**：V9 否决，候选 C 出局。V3–V6 的未核实不再影响该候选的落选结论，但仍保留在表中作为证据链完整性的一部分。

---

## 5. 结论

### 5.1 结论：未选定

调研后没有任何候选通过 V1–V10 全项：

- **候选 C（MIMXRT1060-EVK）** 被 `M4-V9` 否决（板卡 No Longer Manufactured、无购买选项；MCU NRND）。
- **候选 A（NUCLEO-H723ZG）与候选 B（NUCLEO-F767ZI）** 未触发 V 否决，但 V3（M4-Q 未开始）、V4（M4-R 未开始）、V5（未链接/无 `embedded-build`）、V6（无 `rtx-smoltcp`/缓冲区所有权未评审）均为未核实。按本任务书的执行口径，不能把“未核实”写成“通过”，也不能为了交出一个目标而放宽 V 条件，因此结论写 **未选定**。

| 候选 | T1–T8（通过/未核实/否决） | V1–V10（通过/未核实/否决） | 结论 |
|---|---|---|---|
| A STM32H723ZG / NUCLEO-H723ZG | 2 / 6 / 0 | 6 / 4 / 0 | 未完成核实，保留候选；不选中 |
| B STM32F767ZI / NUCLEO-F767ZI | 2 / 6 / 0 | 6 / 4 / 0 | 未完成核实，保留候选；不选中 |
| C MIMXRT1062DVL6A / MIMXRT1060-EVK | 2 / 6 / 0 | 5 / 4 / 1 | `M4-V9` 否决，落选 |

### 5.2 落选候选理由

- **C：`M4-V9`**。NXP 产品页明确 MIMXRT1060-EVK 为 “No Longer Manufactured”，购买选项为空；MIMXRT1062DVL6A 为 “Not Recommended for New Designs”（替代 DVL6B）。这不是“后续可解”的价格/库存问题，而是板卡与器件生命周期不成立。

A、B 不是“落选”，也没有被选中：它们没有 V 否决，但证据不足以通过 V1–V10 全项，保留在候选表中等待缺口关闭。

### 5.3 未核实项清单（按候选）

| 候选 | 未核实的 T 项 | 未核实的 V 项 | 缺什么 |
|---|---|---|---|
| A | T3、T4、T5、T6、T7、T8 | V3、V4、V5、V6 | 启动/RTOS 占用与预算；MTU/`rtx-smoltcp`/缓冲区所有权；TRNG/软件 provider/签名-KEX adapter 与性能；定时器驱动/分频/溢出映射；ELF 链接与 CI 板卡；板卡级 longevity 覆盖 |
| B | T3、T4、T5、T6、T7、T8 | V3、V4、V5、V6 | 同上；另：ST 产品页 Longevity Commitment 为 `-` |
| C | T3、T4、T5、T6、T7、T8 | V3、V4、V5、V6 | 同 A/B；另：V9 已否决，生命周期与可购买性不成立 |

### 5.4 下一步复测条件

1. 先关闭 `GAP-M4-T-01`（M4-R 预算 + `M4-0-2` ELF/map），否则 V4 无法判定。
2. 关闭 `GAP-M4-T-02`（`M4-0-2` 链接 ELF + `M4-0-3` `embedded-build` CI 绿），否则 V5 无法判定。
3. 关闭 `GAP-M4-T-03`（`rtx-smoltcp` + MAC/PHY 驱动 + 1200 字节 UDP 负载实测 + 缓冲区所有权文档），否则 V6/T4 无法判定。
4. 关闭 `GAP-M4-T-04`（M4-Q 决策文档冻结 QC1–QC10 与应用画像），否则 V3 无法判定。
5. 关闭 `GAP-M4-T-05`/`06`/`07`/`08`（provider adapter 与性能、定时器驱动与溢出、CI 板卡资产、生命周期/SDK 集成评审）。
6. 只有在一个候选的 V1–V10 全项为“通过”后，才可在后续单中写“选中目标”；若所有候选仍有关键 V 未核实，则重新开候选方向（不沿用本文档的“保留候选”作为默认答案）。

### 5.5 状态边界

- 本文档合并后仍需 `M4-0-2`（最小启动固件链接出 ELF）、`M4-0-3`（`embedded-build` CI 绿）、`M4-0-4`（板上最小固件启动输出）三项证据，M4-0 才可能成立；本文档本身不构成 M4-0 的通过证据。
- M4-Q 决策、M4-R 预算、M4-M 内存、M4-S 移植范围均未开始；本文档没有 QUIC 需求结论，也没有 E6 回答。
- `rtx-quic` 的 Tier D Linux 外观不因本文档改变；本文档不给它任何嵌入式背书。
- 本文档不勾选 `docs/m3-m4-gates.md` 的任何复选框，也不改门禁条文；门禁 §5 的缺口同步由里程碑验收 PR 处理。

---

## 6. 缺口登记（GAP-M4-T-01 … GAP-M4-T-08）

> 格式按门禁 §4；这些缺口只登记在本文档，未写入 `docs/m3-m4-gates.md` §5。所有缺口类型均为**阻塞**，因为在下一次复测前没有候选能通过 M4-0-1 的“选中目标”要求。

| ID | 类型 | 场景与复现/核查步骤 | 期望依据 | 实际证据 | 影响 | 处置 | 责任与复核 | 状态 |
|---|---|---|---|---|---|---|---|---|
| GAP-M4-T-01 | 阻塞 | 按 M4-R 建“静态占用 + 最小栈 + 最小堆”保守下界；与 DS13313 p1/p14（564 KB）、DS11532 p1（512+16+4 KB）、IMXRT1060CEC p1–2（1 MB）逐项比较；再用 `M4-0-2` ELF 的 `.text/.rodata/.data/.bss` 与 map 校核。 | M4-T3、M4-V4、M4-R1–R12、ARCH §16 | 本文档 §3 T3 行；仓库无 `docs/m4-resource-budget.md`、无 `firmware/`、无 ELF/map | 无法判定 V4；M4-0-1 无选中目标；阻塞 M4-0/M4 出口 | defer；重测日期 2026-11-30（暂定，协调者确认） | owner：M4-R 单责任人（待协调者指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-02 | 阻塞 | 为候选 A/B 建 `firmware/m4-smoke`，执行 `cargo build --no-default-features --release --target thumbv7em-none-eabihf`，确认链接出 ELF；在 CI 增加 `embedded-build` 作业并为绿。 | M4-0-2、M4-0-3、M4-V5、M4-C1 | 仓库无 `firmware/`；CI 仅 `cargo check --target thumbv7em-none-eabihf` 两处，无 `embedded-build`；未做链接实验 | V5 不能记通过；T7 未核实；阻塞 M4-0 | defer；重测日期 2026-11-30（暂定） | owner：M4-0-2/0-3 责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-03 | 阻塞 | 为选定候选实现/接入 `rtx-smoltcp` + Ethernet MAC/PHY 驱动；以 RFC 9000 §3 的 1200 字节 UDP 负载实测；记录缓冲区归属（谁分配、谁持有、何时释放）与 Sans-I/O 边界。 | M4-T4、M4-V6、ARCH §7、RFC 9000 §3 | 根 Cargo.toml 的 15 个 workspace 成员中无 `rtx-smoltcp`；无以太网驱动/缓冲区所有权文档；MTU 数值未在手册给出 | T4/V6 未核实；无法证明 1200 字节负载路径；阻塞 M4-0/M4-Q | defer；重测日期 2026-11-30（暂定） | owner：网络栈/驱动责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-04 | 阻塞 | 按门禁 §2.1 完成 M4-Q 的 QC1–QC10 矩阵、应用画像、替代性分析和 E6 五问；冻结 required/optional/absent；若 required，核对链路 MTU ≥ 1200 字节路径。 | M4-Q1–Q6、M4-QC1–QC10、M4-V3、DEPENDENCY_AUDIT §11 E6 | 仓库无 `docs/m4-quic-decision.md`；本文档未做 QUIC 需求结论 | V3 条件无法判定；候选不能全项通过；阻塞 M4-0-1 选中 | defer；重测日期 2026-11-30（暂定） | owner：M4-Q 单责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-05 | 阻塞 | 为候选 A/B 写 `rtx-crypto` provider：TRNG → `RandomProvider`；软件 AES-GCM/SHA/HMAC → `AeadProvider`/`HashProvider`/`HmacProvider`；确认 `SignatureProvider`/`KeyExchangeProvider` 的可用实现（不得新增原语）；测 AES-GCM/SHA 吞吐与栈占用。 | M4-T5、M4-V7、ARCH §3/§12、M4-S3 | `rtx-crypto` 仅定义 trait；`rtx-crypto-rustcrypto` 覆盖 AES-GCM/SHA/HMAC，未实现 Ed25519/X25519/ECDSA；无目标 provider/性能记录 | T5 未核实；无法证明 provider 边界和性能；阻塞 M4-0/M4-S | defer；重测日期 2026-11-30（暂定） | owner：密码学 provider 责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-06 | 阻塞 | 为候选 A/B 配置 32 位硬件定时器为微秒 tick（分频值待定），实现溢出扩展为 u64 单调计数；验证 `rtx_core::Timestamp::from_micros` 映射、长于 2^32 tick 的运行和饱和运算。 | M4-T6、M4-V8、ARCH §8 | 数据手册确认 32 位定时器/SysTick 存在（DS13313 p1–2；DS11532 p1），但无驱动/无溢出测试；分频未定 | T6 未核实；阻塞 M4-0/M4-M 时间基线 | defer；重测日期 2026-11-30（暂定） | owner：时间/驱动责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-07 | 阻塞 | 采购/登记至少一块候选板（资产编号/订单号），配置可长期使用的 runner 标签或远程访问；跑 `embedded-smoke` 串口/探针输出；归档 runner 标签和资产编号。 | M4-T7、M4-C4、M4-V9、M4-0-4 | 仓库无板卡资产编号/runner 标签；CI 仅 `ubuntu-latest`；本文档未购买/未跑板 | T7 的 CI 板卡子项未核实；M4-0-4/M4-M 无法完成；阻塞 M4 | defer；重测日期 2026-11-30（暂定） | owner：硬件/CI 责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |
| GAP-M4-T-08 | 阻塞 | 核对项目周期与 ST longevity 名单是否覆盖 NUCLEO-H723ZG/NUCLEO-F767ZI 及对应 MCU；核对板卡产品页 `Longevity Commitment` 字段；评审 STM32CubeH7/F7 与 Rust 的集成路径（FFI 或 Rust HAL），确认不使用不兼容运行时。 | M4-T8、M4-V10、ARCH §7 | ST 产品页显示两款 MCU（H723ZGT6/F767ZIT6）均为 10 年（起始 2026-01-01），板卡均 Active；但两款板卡（NUCLEO-H723ZG / NUCLEO-F767ZI）的 Longevity Commitment 均为 `-`；项目周期未定义；未做 SDK 集成评审 | T8 未核实；生命周期是否覆盖项目周期无法判定；阻塞 M4-0 选中 | defer；重测日期 2026-11-30（暂定） | owner：可获得性/SDK 责任人（待指派）；复核：架构评审；issue：本 PR 讨论 | OPEN |

---

## 7. 来源清单

### 7.1 手册/文档/厂商页面

| 编号 | 来源标题 | URL | 查阅页码/章节 | 用于 |
|---|---|---|---|---|
| S1 | ST DS13313 Rev 5（May 2025）STM32H723xE/G datasheet | https://www.st.com/resource/en/datasheet/stm32h723zg.pdf | 第 1–2 页功能；第 14 页描述/内存；第 16 页框图 | 候选 A T1–T7 |
| S2 | ST DS11532 Rev 7（Feb 2021）STM32F765xx/F767xx/F768Ax/F769xx datasheet | https://www.st.com/resource/en/datasheet/stm32f767zi.pdf | 第 1–2 页功能/器件表；§3.23 第 38 页；§3.32 第 46 页；§3.39 第 49 页；Table 2 第 17 页 | 候选 B T1–T7 |
| S3 | NXP IMXRT1060CEC Rev 4（04/2024）i.MX RT1060 Crossover Processors for Consumer Products | https://cache.nxp.com/docs/en/nxp/data-sheets/IMXRT1060CEC.pdf | 第 1–2 页功能/内存；第 4 页安全；第 7 页订购表；第 14 页 ENET 模块；第 83 页定时器 | 候选 C T1–T7 |
| S4 | ST UM2407 Rev 6（April 2026）STM32H7 Nucleo-144 boards (MB1364) | https://www.st.com/resource/en/user_manual/um2407-stm32h7-nucleo144-boards-stmicroelectronics.pdf | 第 7 页功能；第 8 页订购；第 18 页 STLINK-V3E；第 30 页 §7.6.7 Ethernet；第 37 页 §8.3 RJ45 | 候选 A T1/T4/T7/T8 |
| S5 | ST UM1974 Rev 11（August 2025）STM32 Nucleo-144 boards (MB1137) | https://www.st.com/resource/en/user_manual/dm00244518-stm32-nucleo144-boards-mb1137-stmicroelectronics.pdf | 第 6 页功能；第 7 页订购表；第 17 页 §7.3 ST-LINK；第 29 页 §7.11 Ethernet | 候选 B T1/T4/T7/T8 |
| S6 | NXP UM11151 Rev 0（September 2018）MIMXRT1060 Evaluation Kit Board Hardware User's Guide | https://www.mouser.com/pdfdocs/NXP_MIMXRT1060-EVK_UG.pdf | 第 1 页板卡特性表；第 8–9 页 SDRAM/QSPI/Ethernet/DAP-Link；第 10 页 JTAG | 候选 C T1/T3/T4/T7/T8 |
| S7 | ST NUCLEO-H723ZG 产品页 | https://www.st.com/en/evaluation-tools/nucleo-h723zg.html | Active / volume production；Order Direct；Quality 表 Longevity Commitment 为 `-` | 候选 A T8/V9 |
| S8 | ST NUCLEO-F767ZI 产品页 | https://www.st.com/en/evaluation-tools/nucleo-f767zi.html | Active / volume production；Quality 表 Longevity Commitment 为 `-` | 候选 B T8/V9 |
| S9 | ST STM32H723ZG 产品页 | https://www.st.com/en/microcontrollers-microprocessors/stm32h723zg.html | Active / volume production；STM32H723ZGT6 Longevity Commitment 10 年（起始 2026-01-01） | 候选 A T8 |
| S10 | ST STM32F767ZI 产品页 | https://www.st.com/en/microcontrollers-microprocessors/stm32f767zi.html | Active / volume production；STM32F767ZIT6 Longevity Commitment 10 年（起始 2026-01-01） | 候选 B T8 |
| S11 | ST Product longevity 页面 | https://www.st.com/content/st_com/en/about/quality-and-reliability/product-longevity.html | 7/10/15/20 年档 longevity commitment；10 年档说明 | 候选 A/B T8 |
| S12 | ST STM32CubeH7 页面 | https://www.st.com/en/embedded-software/stm32cubeh7.html | HAL + RTOS/TCP-IP 等中间件 | 候选 A T8/V10 |
| S13 | ST X-CUBE-AZRTOS-H7 页面 | https://www.st.com/en/embedded-software/x-cube-azrtos-h7.html | Azure RTOS 集成；NUCLEO-H723ZG 示例 | 候选 A T8 |
| S14 | ST STM32CubeF7 页面 | https://www.st.com/en/embedded-software/stm32cubef7.html | HAL/LL + RTOS/TCP-IP 中间件 | 候选 B T8/V10 |
| S15 | Digi-Key NUCLEO-H723ZG 采购页 | https://www.digikey.com/en/products/detail/stmicroelectronics/NUCLEO-H723ZG/13171214 | `497-NUCLEO-H723ZG-ND`；Part Status Active；In-Stock | 候选 A T8/V9 |
| S16 | Digi-Key NUCLEO-F767ZI 采购页 | https://www.digikey.com/en/products/detail/stmicroelectronics/NUCLEO-F767ZI/6004740 | `497-16525-ND`；Part Status Active；In-Stock | 候选 B T8/V9 |
| S17 | NXP MIMXRT1062DVL6A 产品页 | https://www.nxp.com/part/MIMXRT1062DVL6A | Not Recommended for New Designs；替代 DVL6B | 候选 C T8/V9 |
| S18 | NXP MIMXRT1060-EVK 产品页 | https://www.nxp.com/part/MIMXRT1060-EVK | No Longer Manufactured；Buy Options: No items available | 候选 C T8/V9 |
| S19 | NXP MCUXpresso SDK 文档（MIMXRT1060-EVKB） | https://docs.mcuxpresso.nxp.com/mcuxsdk/latest/boards/RT/evkbmimxrt1060/index.html | FreeRTOS/lwIP 支持；器件 MIMXRT1062DVL6B | 候选 C T8/V10（家族 SDK 证据，非 EVK/DVL6A 板级证据） |
| S20 | NXP 产品生命周期页面 | https://www.nxp.com.cn/support/sample-and-buy/product-lifecycle:PRDLIFCYC | 产品状态定义（Active/NRND/EOL 等） | 候选 C T8/V9 |
| S21 | 门禁文档 `docs/m3-m4-gates.md` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/docs/m3-m4-gates.md | §2.0–§2.5、§4 | 全部 T/V/缺口格式 |
| S22 | `ARCHITECTURE.md` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/ARCHITECTURE.md | §4、§5、§7、§8、§12、§16 | T2/T4/T5/T6/V2/V6/V7/V8/V10 |
| S23 | `crates/rtx-crypto/src/lib.rs` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-crypto/src/lib.rs | trait/算法枚举定义 | T5/V7 |
| S24 | `crates/rtx-crypto-rustcrypto/src/lib.rs` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-crypto-rustcrypto/src/lib.rs | no_std + alloc 姿态；AES-GCM/SHA/HMAC；未实现签名/KEX | T5 |
| S25 | `crates/rtx-quic/Cargo.toml` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-quic/Cargo.toml | Tier D（std/Linux）注释；无嵌入式 QUIC 声称 | §1.4/§5.5 |
| S26 | `.github/workflows/ci.yml` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/.github/workflows/ci.yml | `cargo check --target thumbv7em-none-eabihf`；无 `embedded-*` 作业 | T7/V5 |
| S27 | 根 `Cargo.toml` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/Cargo.toml | 15 个 workspace 成员；无 `rtx-smoltcp` | T4/V6/§1.4 |
| S28 | RFC 9000 §3 | https://www.rfc-editor.org/rfc/rfc9000.html#section-3 | UDP 负载最小 1200 字节 | T4/V3 的待验证负载 |
| S29 | `crates/rtx-core/src/lib.rs` @37a2a8a | https://github.com/medivhc/rtx-rs/blob/37a2a8a/crates/rtx-core/src/lib.rs | `Timestamp(u64)`、`Duration`、饱和运算 | T6/§3.5 |

### 7.2 本地命令证据

在本仓库基线 `37a2a8a` 的工作树、默认 stable 工具链上执行（2026-10-30）：

```text
$ rustc --version
rustc 1.92.0 (ded5c06cf 2025-12-08)

$ rustup target list | grep thumbv7em
thumbv7em-none-eabi
thumbv7em-none-eabihf
```

该输出只证明稳定版 Rust 目标列表含 `thumbv7em-none-eabihf`，不证明可链接、不证明 CI 可构建。T7 的可链接性与 CI 板卡仍记未核实。

### 7.3 不作为通过证据的来源

- 电商/论坛摘要、搜索片段、ManualsLib 页面只用于定位官方文档，不作为 T/V 通过证据。
- 本文档未使用任何无 URL 的口头说明、聊天记录、未提交日志或截图。

---

## 8. 自查清单（PR 描述同文）

### (a) 新文件路径与章节清单

- 新文件：`docs/m4-target-selection.md`（唯一改动）。
- 章节：1 范围与判定口径；2 候选与筛选方法；3 候选表（T1–T8 + T5/T6 映射）；4 否决结论表（V1–V10）；5 结论；6 缺口登记；7 来源清单；8 自查清单。

### (b) 候选数量与 T1–T8 完成度

- 候选数量：3（A/B/C）。
- A：T1/T2 通过；T3–T8 未核实；T 否决 0。
- B：T1/T2 通过；T3–T8 未核实；T 否决 0。
- C：T1/T2 通过；T3–T8 未核实；T 否决 0（V9 否决记在 V 表）。

### (c) 结论与证据一致性

- 结论为“未选定”：A/B 有 V3–V6 未核实，C 有 V9 否决；没有候选 V1–V10 全项通过。
- 未把“数据手册有容量”写成 V4 通过；未把“target 在列表里”写成 V5 通过；未把“有以太网 MAC/PHY”写成 T4 通过；未把“有 TRNG/DCP”写成 T5 通过。
- 未把 C 的停产写成“后续可解”；C 保留在表中，附 V9 否决。

### (d) 未核实项与缺口复述

- 未核实集中在：T3 占用/预算、T4 MTU/栈路径/缓冲区所有权、T5 provider/性能、T6 驱动/溢出、T7 链接/CI 板卡、T8 生命周期；V3–V6 相应未核实。
- 缺口：`GAP-M4-T-01` … `GAP-M4-T-08`，均为阻塞、OPEN、defer（重测日期 2026-11-30 暂定）。
- 未写入 `docs/m3-m4-gates.md` §5；该表同步由里程碑验收 PR 处理。

### (e) 范围自查

- `git diff --stat` 预期只出现 `docs/m4-target-selection.md`（新建 1 文件）。
- 无 `crates/*`、`benchmarks/*`、`interop/*`、CI、已有文档正文、`docs/m3-m4-gates.md` 改动；无根 `Cargo.toml`/`Cargo.lock` 改动。
- 无 `firmware/`、无代码/脚本/CI 作业、无 PNG/PEM/DER/KEY/`.screenshots`/证书/二进制文件。
- 未做链接实验、未跑板、未购买、未联系供应商；未做 M4-Q/R/M/S。
