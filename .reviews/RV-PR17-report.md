# RV-PR17 独立评审报告：rtx-rs PR #17（R4-2-F3 调用方 relay 供给指南单）

评审人：独立评审（TraeCode）
评审对象：PR #17 `R4-2-F3: 调用方 relay 供给指南（docs-only）`
分支：`trae/p4-r4-2-f3-relay-caller-guide`
基线：`main` @ `4bce6f1`（R4-2-F2 / PR #16 合并点）

---

## 一、结论

**批准合并**（0 阻塞项）。

本单满足 F3 任务书的全部硬约束：diff 严格限定为 1 个新增文档文件、6 节齐全且各节写到实体内容、关键机制与 `4bce6f1` 代码逐条一致、无禁忌肯定表述、片段为伪代码且文首已作"非可编译示例"声明、PR 描述四项 (a)(b)(c)(d) 齐全且无夸大、独立复核的 `cargo test --workspace` 与 `cargo fmt --check` 均通过。

同时给出 8 条非阻塞意见（NB-1…NB-8），均为表述精度问题，建议在同一轮内顺手修正，但都不构成合并前置条件。

**门禁说明（不得据此要求本 PR 修 CI）**：本 PR head 的 check-runs 总数为 0（GitHub API 实测 `total_count=0`）。我复核了根因：`.github/workflows/ci.yml` 的 `fuzz` job 中 "Install nightly + cargo-fuzz" 步骤在同一 step 内同时写了 `uses:` 与 `run:`（工作流级非法组合），导致该工作流整体无法被 Actions 解析，因此不产生任何 check run。这是既往 CI-C1 模式，与本 PR 的 docs-only 变更无关，**不得要求本 PR 修复 CI**。CI-exact 门禁由协调者在 xc 上另跑。

---

## 二、验收逐项表

| # | 验收项 | 结论 | 证据 |
|---|---|---|---|
| 1 | diff 范围 | **通过** | `git diff --name-status 4bce6f1 4663db3` → 唯一一行 `A docs/ice-relay-caller-guide.md`；`git diff --numstat` → `225 0 docs/ice-relay-caller-guide.md`；`git diff --stat` → 1 file changed, 225 insertions(+)。`git ls-tree -r --name-only 4663db3` 全树扫描无 `.screenshots`/图片/新增 `examples/`；`crates/**`、根 `Cargo.toml`、`.github/workflows/**`、既有 `docs/ice-turn-decision.md` 均无 diff。merge-base = `4bce6f1`（`git merge-base origin/main refs/remotes/origin/pr17`），`gh pr view` 报 `mergeable=MERGEABLE, mergeStateStatus=CLEAN`，1 个 commit（`4663db3 docs: add R4-2-F3 caller relay provisioning guide`）。 |
| 2 | 6 节齐全性 | **通过** | §1 适用范围与非目标（1.1 适用 / 1.2 非目标，含 P6 不接 relay：guide:31）、§2 外部 TURN 分配供给流程（2.1 全在 `start` 前的供给时序、2.2 `start` 后拒绝 `AlreadyStarted` 与"无 remove/replace"、2.3 `start` 前分配失败）、§3 base 填法（3.1 正确填法、3.3 反例 A、3.4 反例 B、3.5 `raddr/rport` 易错点单列）、§4 `SendCheck` 封装与 Data indication 解封装（4.1/4.2 出站、4.3 入站双向）、§5 刷新失败与会话失败（5.1 谁负责刷新、5.2 失败表现表、5.3 会话级处理）、§6 检查清单（`grep -c "^- \[ \]"` = 12 项，逐项可勾选，非标题占位）。各节均为实体段落，无"只有标题"情形。 |
| 3 | 机制准确性 | **通过** | 逐条核对 `4bce6f1` 代码：<br>• `source = pair.local().base()` → `crates/rtx-ice/src/checklist.rs:807`（guide:88）✓<br>• 响应匹配 `pair.remote().address() == meta.source && pair.local().base() == meta.destination` → `checklist.rs:646`（guide:89、171）✓<br>• 入站本地候选查找以 `meta.destination` 为键 → `checklist.rs:541-544`（guide:90、170）✓<br>• Relay 缺 base → `IceError::MissingBaseAddress` → `crates/rtx-ice/src/candidate.rs:172-181`（guide:96、106）✓<br>• 填本地 socket 的双偏离论证 → `source` 变 `local_socket`（`checklist.rs:807`）、响应匹配要求 `meta.destination == local_socket` 而 TURN 实际投递 relayed（guide:98-99）✓<br>• consent 匹配规则 → `checklist.rs:688-700`（guide:92、172）✓<br>• add API `AlreadyStarted` → `checklist.rs:317-335`（guide:58）；`pub fn` 全量清单无 remove/replace（guide:59）✓<br>• 远端候选 `base` 不参与检查发送/响应匹配 → 全树 `.base()` 使用点仅 `checklist.rs:581/646/694/727/807`，均为 `local.base()`（guide:113）✓<br>• 名额 16/64 → `lib.rs:99-110`、`checklist.rs:28/39`（guide:61）✓<br>• 重传 7 次 → `lib.rs:129-135`、`checklist.rs:78`（guide:193）✓<br>• consent stale 严格大于 timeout → `checklist.rs:446-454`、`lib.rs:148-154`（guide:194）✓<br>行号偏差仅见于 NB-2（§3.3 bullet 3 的措辞）与 NB-8（§5.2 的 `ChecklistFailed` 触发点未在所引区间内），机制方向均未写反。 |
| 4 | 禁忌表述 | **通过** | 全文检索"树内已有/将有 TURN 客户端""自动换 relay/自动重分配""SDP raddr 可填 base"：<br>• guide:28「**树内没有 TURN 客户端。**」——否定式；guide:22 的 TURN 客户端明确限定为"在树外"调用方自备；guide:12「树内也不新增 TURN 客户端」——否定式。<br>• guide:203「这不是自动降级，而是调用方的新会话决策」、guide:206「**明确否定**：树内不会自动更换 relay 候选、不会自动重分配」、guide:223 checklist「未假设树内自动更换 relay 候选或自动重分配」——均为明确否定。<br>• guide:110/112/113/115/216 关于 `raddr/rport`：「它**不是** base」「不要填 `raddr/rport`」「决策 §2.B 明确禁止」——明确否定，无"可填 base"肯定表述。<br>否定句的反向暗示检查：唯一潜在点是 guide:28 关于 R4-2-F4 的条件性表述（见 NB-7），其条件与决策 §6 表一致，未构成"树内将有 TURN 客户端"的承诺；其余否定句无反向暗示。 |
| 5 | 示例收敛 | **通过** | 全文代码块仅 5 处，全部为 ` ```text ` 围栏（guide:45、75、133、144、161），无 `rust`/可编译围栏；文首 guide:12 已有「本文中的代码片段均为说明性伪代码 / 流程描述，**非可编译示例**，不对应任何新增 API、类型、crate 或测试；树内也不新增 TURN 客户端」。无 `examples/`、无 `tests/` 新增、无 Cargo 成员变更、无平台 crate 代码、无 API 签名承诺（guide:30 显式声明"不新增 API、事件、常量"，与决策 §2.B"对 `rtx-ice` API 的影响：零"一致）；未滑向实现 TURN 客户端/认证/SDP/P5/P6 决策（guide:32 显式排除）。 |
| 6 | 作者自查复核 | **通过（本人独立实跑）** | 在 PR head worktree（`git worktree add /tmp/pr17wt refs/remotes/origin/pr17`）执行：`cargo test --workspace` → exit 0，全部 `test result: ok`，0 failed；`cargo test -p rtx-ice` → `ice_checklist` 29 passed、`relay_passthrough` 4 passed、`resource_limits` 2 passed，与 PR 描述所写"rtx-ice 29 + 4 + 2 含 F2 用例"完全一致（结论取自我方实跑，非照抄）；`cargo fmt --all -- --check` → exit 0；额外跑了 `cargo clippy --workspace --all-targets --all-features -- -D warnings` → exit 0。基线侧 `cargo test --workspace` 同样 exit 0。docs-only 变更不引入代码回归。 |
| 7 | PR 描述四项 | **通过（1 处非阻塞引用瑕疵）** | (a) 指南↔决策条款对应 → PR 描述含 6 行对照表（§1–§6 逐节映射到决策 §1.4/§2.B/§3/§4.3/§5/§6）；(b) base 反例机制依据 → 列出 `checklist.rs:807`、`:646`、`:541-544`、`:688-700`、`candidate.rs:172-181`，与代码一致；(c) 示例收敛为说明性片段的理由 → 说明任务书把"示例可落在平台 crate 或 testkit"收敛为文档内片段、避免滑向实现单，并声明文首已作"非可编译示例"声明；(d) 未改动项清单 → `crates/**`、根 `Cargo.toml`、CI、既有文档、无 examples/tests/平台 crate、未写 TURN 客户端/认证/SDP/P5/P6。夸大与遗漏核查：PR 描述所称测试数字与我方实跑一致；"只建 PR，不合并"与本次评审口径一致。唯一瑕疵见 NB-6（对照表中一处条款号指错），不影响其余三项。 |

---

## 三、问题清单

### 3.1 阻塞项（blocking）

**0 阻塞。**

依据：无缺节、无"以标题代内容"、无机制写反、无禁忌肯定表述、示例未滑向实现单、PR 描述四项齐全。

### 3.2 非阻塞意见（non-blocking）

**NB-1｜`docs/ice-relay-caller-guide.md:14`｜锚点说明的出处描述与 git 事实不符（建议本 PR 内修正）**
- 现状：「本文引用的源码行号按 `c545331` 实测，并在 `4bce6f1` 复核无变」。实测 `git diff --stat c545331..4bce6f1` 显示 `crates/rtx-ice/src/lib.rs` 变更 `22 insertions(+), 10 deletions(-)`（R4-2-F1 措辞跟进），因此 `lib.rs` 在两提交间**并非**无变。
- 影响：文中 5 处 `lib.rs` 锚点（`:46-49`、`:55-58`、`:99-110`、`:129-135`、`:148-154`）我逐条核对**在 `4bce6f1` 上全部命中正确内容**，只是它们不属于 `c545331` 的行号；`checklist.rs` / `candidate.rs` 确为无变。
- 应改法：改为「行号以 `4bce6f1` 为准；`checklist.rs` / `candidate.rs` 自 `c545331` 起未变，`lib.rs` 因 R4-2-F1 措辞跟进已按 `4bce6f1` 重新核对」。

**NB-2｜`docs/ice-relay-caller-guide.md:100`（§3.3 第 3 点）｜入站查找实际按 `address` 比对，"伪造 destination"的表述与 §4.3 冲突（建议本 PR 内修正）**
- 现状：文中写「入站检查的本地候选查找同样以 `meta.destination` 为键……伪造 `destination` 才不至于返回 `IceError::UnknownLocalCandidate`」。
- 事实：本地候选表查找是**按候选 `address` 比对**，不是按 `base`——`crates/rtx-ice/src/checklist.rs:975-980`：`position(|slot| ... candidate.address() == address)`。因此在反例 A（`address = relayed`、`base = local_socket`）下，入站查找要命中必须 `destination = relayed`，而响应匹配（`checklist.rs:646`）与 consent 刷新（`checklist.rs:694`）比对的是 `local.base()`，要求 `destination = local_socket`——两个要求不可同时满足。同文档 guide:170 已给出正确表述（"填成本地 socket 地址会返回 `IceError::UnknownLocalCandidate`"）。
- 影响：结论（反例 A 非法）不变，且按正确字段表述后论证更强，但当前措辞把"查找键"与"base 比对"混在一起，可能让读者以为入站查找是 base 键。
- 应改法：把该点改写为「入站查找按候选 `address` 比对（`checklist.rs:975-980`），仍需 `destination = relayed`；而响应/consent 比对 `local.base()`，要求 `destination = local_socket`——两者不可同时满足，故 `base = local_socket` 无法通过任何单一 `destination` 成立」。

**NB-3｜`docs/ice-relay-caller-guide.md:195`（§5.2 表第 4 行）｜"重装权限/通道即可恢复"与 §5.3「已 `Failed` 的 pair 不会重启」冲突（建议本 PR 内修正）**
- 现状：同一行的"树内表现"写「检查无响应，表现同上」（即 pair 重传 7 次后 `Failed`，全部失败则 `ChecklistFailed`），"调用方动作"却写「在 TURN 侧重新安装权限 / 通道即可恢复（relayed 地址未变，`rtx-ice` 无需动作）」。
- 事实：`Failed` 的 pair 不会被重开——`checklist.rs:1079-1084` `first_waiting()` 只选 `Waiting`，`checklist.rs:769-770` 触发队列跳过 `Failed`，且树内无 remove/replace（`pub fn` 全量清单）。这与同节 guide:200「已 `Failed` 的 pair 不会重启……只能会话级处理」自相矛盾。
- 应改法：补条件——「仅当该 pair 尚未耗尽重传预算时，修复权限/通道才可能恢复；pair 一旦 `Failed` 只能会话级重建（见 §5.3）」。

**NB-4｜`docs/ice-relay-caller-guide.md:204`（§5.3 第 3 条）｜"也不检测"与同文档 `is_consent_stale` 表述不一致（建议本 PR 内修正）**
- 现状：写「`rtx-ice` 不发 keepalive，也不检测、不切换（`lib.rs:148-154`）」。
- 事实：树内**提供**检测查询接口 `Checklist::is_consent_stale`（`checklist.rs:446-454`），guide:194 与 guide:219 均引用了它；树内不做的是发 keepalive（`lib.rs:189` "Send consent keepalives | caller; the crate only records timestamps"）与自动切换候选。
- 应改法：改为「`rtx-ice` 不发 keepalive，也不自动切换候选；consent 是否过期由调用方用 `is_consent_stale` 查询判定」。

**NB-5｜`docs/ice-relay-caller-guide.md:130`、`:155`｜RFC 5766 子节号整体偏移一位（建议本 PR 内修正）**
- 现状：写「未绑通道用 Send indication（RFC 5766 §10.2…）」与「Data indication（RFC 5766 §10.3）」。
- 事实（RFC 5766 目录实测）：§10.1 Forming a Send Indication、§10.2 Receiving a Send Indication、§10.3 Receiving a UDP Datagram、§10.4 Receiving a Data Indication。客户端**发送** Send indication 对应 §10.1，客户端**接收** Data indication 对应 §10.4。
- 说明：guide:186 的 `§7.2`（Refresh）与 guide:42 的 `§5`（Allocate/分配寿命）与决策文档既有引用口径一致（`docs/ice-turn-decision.md:85` 即用 §5 与 §7.2），保留即可；本条只针对 §10.x。
- 应改法：§4.1 改 §10.1，§4.3 改 §10.4。

**NB-6｜PR 描述 (a) 对照表 §1 行｜条款号指错（建议在 PR 描述内修正，不需改分支）**
- 现状：对照表 §1 行写「§5.1（认证缺口不变）」。该表用「§5.N」表示决策 §5 一致性声明的第 N 条（同表 §3 行「§5.5（Candidate::new 规则不变）」即指第 5 条），而决策 §5 第 1 条是「relay 类型偏好 0 不变」（`docs/ice-turn-decision.md:281`），与认证缺口无关。
- 事实："认证缺口不变"的原文在决策 §4.4 责任表（`docs/ice-turn-decision.md:271`：`ICE 检查的 USERNAME / MESSAGE-INTEGRITY | 无人（R4-1 明确缺口）| 本决策不改变`）与 §3 执行摘要第 5 条（`:220` "B 不掩盖认证缺口"）。
- 影响：仅影响 PR 描述的条款映射表；指南正文引用的是 `lib.rs:55-58`（实测正确），未受牵连。
- 应改法：把该格改为「§4.4 / §3-5（认证缺口不变）」。

**NB-7｜`docs/ice-relay-caller-guide.md:28`（§1.2）｜R4-2-F4 表述宜补齐"条件触发、未排期"（建议本 PR 内修正）**
- 现状：写「完整 TURN 客户端评估只在出现真实部署证据时按决策 §6 的 `R4-2-F4` 另行立项」。
- 事实：决策 §6 表把 R4-2-F4 标注为「（条件触发，未排期）」，且前置为「`AUTH-1`（认证/凭证故事决策单，暂定名）先 merged；部署证据先入档」（`docs/ice-turn-decision.md:299`）。
- 判断：当前措辞已带"只在出现真实部署证据时"的条件，**不构成**"树内将有 TURN 客户端"的肯定表述，判定为合规；仅为避免被读成路线图承诺而建议补齐。
- 应改法：补为「……按决策 §6 的 `R4-2-F4` 另行立项（决策 §6 记为条件触发、未排期，前置为 `AUTH-1` 先 merged）」。

**NB-8｜`docs/ice-relay-caller-guide.md:193`（§5.2 表第 2 行）｜`ChecklistFailed` 触发点未落在所引行区间内（建议本 PR 内修正）**
- 现状：引用为「`lib.rs:129-135`、`checklist.rs:709-755`」，该区间覆盖重传与 pair `Failed`，但"全部 pair 失败 → `ChecklistFailed`"的实际触发在 `checklist.rs:785-787`（`drive()` → `all_failed()`）与 `checklist.rs:875-882`（`fail()` 推 `Event::ChecklistFailed`）。
- 应改法：引用补上 `checklist.rs:785-787`、`:875-882`；机制表述本身正确，无需改写。

---

## 四、评审元信息

- **评审对象**：PR #17 `R4-2-F3: 调用方 relay 供给指南（docs-only）`，分支 `trae/p4-r4-2-f3-relay-caller-guide`，**head SHA `4663db3e6d8f8783b2e036fe98da11f1d17f5e1d`**（1 commit，净 diff 1 文件 +225/-0）。
- **评审所用基线**：`main` 头 **`4bce6f1a9564a22019fdc5cd66003eb233bd8d14`**（merge-base 实测 = `4bce6f1`；`git diff 4bce6f1 4663db3` 净 1 文件 +225/-0）。
- **评审方式**：全部 git 一手核验（fetch PR head ref、`merge-base`、`diff --name-status/--numstat/--stat`、`ls-tree` 全树扫描、`show` 逐行比对锚点、`worktree` 在 head 上实跑 `cargo test --workspace` / `cargo test -p rtx-ice` / `cargo fmt --all -- --check` / `cargo clippy -D warnings`）+ GitHub API 复核 PR 元数据与 check-runs 计数；未采信协调者转述的结论与作者 UI 数字。
- **是否建议合并**：**建议合并**。阻塞项 0；NB-1…NB-8 为建议同轮顺手修正的表述精度项，均不要求改动生产代码、不新增示例 crate、不改 CI、不修既往跟进项（RV-PR12 P1/P2、CI-C1、R1-3/PR #2、RV-PR15-NB、RV-PR16-NB），不涉及 P5/P6 决策，也不要求实现 TURN 客户端。
