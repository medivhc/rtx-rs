# 独立评审报告：rtx-rs PR #45（RV-PR43-N2 closeout 刷新）

评审者：独立评审会话（MiniMax-M3.1-Flash），与作者会话不同模型、不同会话。
评审方式：自行 `git clone` 仓库 + `gh`/GitHub API 一手核验，未采用协调者核验结论或作者自述作为依据。
评审日期：2026-11-04（Asia/Shanghai）。

---

## 0. 评审基线（本次实测）

| 项 | 值 | 取证方式 |
|---|---|---|
| 仓库 | `https://github.com/medivhc/rtx-rs` | `git clone` 到 `/tmp/rev45/repo` |
| 评审所对的头 SHA | `2654ec306a52e36334597e19be5542b9ef820b1c` | `git rev-parse origin/pr45`；`gh pr view 45 --json headRefOid` 一致 |
| base 分支 / base SHA | `main` @ `33268ff2c5721e31e3a115fe8469d7869cd60dbc` | `git rev-parse origin/main`；PR API `base.sha` 一致 |
| merge-base | `33268ff2c5721e31e3a115fe8469d7869cd60dbc` = base 头 | `git merge-base origin/main origin/pr45` |
| commit 数 | 1（`2654ec3`），父提交 = `33268ff` | `git rev-list --count origin/main..origin/pr45`；`git rev-parse origin/pr45^` |
| mergeable | `mergeable=true` / `mergeable_state=clean`（gh: `MERGEABLE` / `CLEAN`） | PR API `pulls/45`；`gh pr view 45` 复核（评审前后两次一致） |
| 变更规模 | 1 文件，+2 / −2 | `git diff --numstat`；PR API `changed_files=1, additions=2, deletions=2` |
| PR 状态 | OPEN，未合并 | PR API `state=open, merged=false` |

### 头 check-runs 现状（本次实测，非照抄）

run `41796436619`（workflow `CI`，event `pull_request`，headSha `2654ec3`，createdAt `2026-11-04T08:02:15Z`）：

| Job | 结论 | 完成时间 (UTC) |
|---|---|---|
| build / lint (stable) | success | 08:02:49 |
| suite (msrv) | success | 08:03:41 |
| suite (stable) | success | 08:03:29 |
| coverage gate | success | 08:03:36 |
| crypto vectors (published) | success | 08:03:09 |
| property tests (deep sweep) | success | 08:03:15 |
| fuzz smoke (nightly) | success | 08:05:11 |

- 轮次：1 轮 `CI`（`pull_request` 事件），共 7 个 check-run，**7/7 success，0 个 failed/queued/pending/skipped job**。
- 失败步骤：无。
- skipped 项：仅 `fuzz smoke (nightly)` 内的条件步骤 "Upload any crash artifacts"（无崩溃时跳过上传，属正常条件分支），**不是 job 级 skipped**。
- 基线对照：`main` @ `33268ff` 同为 7/7 success。
- 补充实测：`GET /commits/2654ec3/status`（legacy status API）返回 `state=pending, total_count=0, statuses=[]` —— 这是 legacy 接口因无 status 条目而给出的默认态，**不代表有 pending 检查**；check-runs 接口与 `statusCheckRollup` 均显示全部成功。以 check-runs 为准。
- 与作者自述的差异：作者总结称“当前唯一 check build/lint 为 pending”。实测 `build / lint (stable)` 于 08:02:49Z 已 `completed/success`。该 pending 说法是 15:58（CI 尚未跑完时）的过期快照，**不成立**。作者 PR 描述本身写的是“未运行门禁，不声明 check-runs 结果”，未把未跑的门禁写成已跑（见第 5 项核验）。

**内容结论与 CI 结论分离声明**：以下 1–6 项为**文档内容**判定；CI 结论独立记录为“头 7/7 绿”。二者不互推：CI 全绿不构成内容通过依据，内容问题也不因 CI 全绿而降级。

---

## 1. 验收逐项表（6 项）

| # | 验收项 | 判定 | 证据（本次一手实测） |
|---|---|---|---|
| 1 | **范围**：diff 仅含任务书允许的 closeout 两处；无 gates §6 复选框/其他文档/代码/CI 改动；无顺带处理无关缺口；头树无新增二进制 | **通过** | `git diff --raw` 仅一条 `:100644 100644 9ab51e4 a28b5c7 M docs/m3-m4-closeout.md`；`git diff --numstat` = `2 2 docs/m3-m4-closeout.md`；`git diff origin/main origin/pr45 -- docs/m3-m4-gates.md` 空；gates blob SHA 两侧同为 `ae01056c18bf9c0fd358bf0831f6956ce14bc973`（`cmp` 结果 IDENTICAL）；`git ls-tree -r` 两侧文件集合完全相同（`diff` 输出 IDENTICAL FILE SETS），无新增文件；CI 配置 `.github/workflows/` 未进 diff；`.screenshots/` 在 base 与 head 均不存在（`git ls-tree -r \| grep -i screenshot` → none）；仓库内 4 个 `.bin`（`crates/rtx-h3/tests/fixtures/*.bin`、`interop/m3/chrome/.../capture/*.bin`）在 base 已存在，非本 PR 新增。无关缺口均未动：GAP-M4-T-01 预算内容未碰（`git ls-tree -r origin/main \| grep resource-budget` → none，PR #44 头 `2e637c8` 才有 `docs/m4-resource-budget.md`）、RV-PR40-N2 / RV-PR42-NB1 无改动、B3-01 判定未动（closeout:133 仍标 `OPEN`）、PR #2 语料未动（closeout:56、:135 原样）。 |
| 2 | **:117 改动准确性**：B0-02 确由 PR #43 合并关闭；gates :456 为 B0-02 已关闭行、:457 仍 B3-01 OPEN；证据栏与 :456 指针未被顺手改；措辞与 gates 一致 | **通过** | PR #43 API：`merged=true, merged_at=2026-11-04T07:30:35Z, merge_commit_sha=33268ff2c5721e31e3a115fe8469d7869cd60dbc`；`git show 33268ff` = 合并 `docs/m3-m4-gates.md` 1 行；`git show 4614539` 显示 PR #43 唯一实质改动即把 gates §5 B0-02 行状态由 `OPEN` 改为 `已关闭` 并追加 PR #29 重跑证据。gates 头树 `:456` = `GAP-M3-B0-02` 行且状态列为 `已关闭`；`:457` = `GAP-M3-B3-01`，状态列仍 `OPEN`。closeout:117 的证据栏（`docs/m3-m4-gates.md:456`；`interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md` 与同目录 `-baseline/report.md`）与 base 逐字节一致（diff 中仅状态列 `OPEN`→`已关闭`）。措辞：gates:456 用 `已关闭`，closeout:117 用 `已关闭`，完全一致。 |
| 3 | **:145 计数准确性**：阻塞 GAP 确为 T-01…T-08 共 8；PR #44 仍 OPEN 故 T-01 仍计入，无需重算为 7；新表述与 §5 表格一致；无重复计入/漏计 | **通过** | `git show origin/pr45:docs/m4-target-selection.md` §6 表（:284–:291）恰好 8 行 T-01…T-08，状态列全为 `OPEN`；`docs/m4-target-selection.md:376` 亦记 “T-01 … T-08，均为阻塞、OPEN”。PR #44 API：`state=OPEN, mergedAt=null, headRefOid=2e637c86bf7f2e3b873450ae06bae9c78bffe19b`，分支 `docs/m4-resource-budget-t01` 未合并；`docs/m4-resource-budget.md` 未进 main/head，故 T-01 仍为阻塞，应计入 → 计数 8 正确，无需重算 7。closeout §5 表：:117 B0-02 已关闭 + :118–:125 T-01…T-08 八行均 `OPEN`（`grep -o 'GAP-M4-T-[0-9]*'` 去重恰为 T-01…T-08，无第九个 T 项、无重复）；:145 新表述“8 个：T-01…T-08，均为 OPEN；B0-02 已关闭”与该表逐项吻合，B0-02 未重复计入、T 项无漏计。另 :146 的“另有 2 项未登记 GAP ID 的门禁前置缺失”未动，与 §5 表 :126/:127 两行一致。 |
| 4 | **历史与结论 preservation**：:46、:103 未动；“因此本单结论为 FAIL”句与 §6 结论未动；gates §6.1/6.2/6.3 复选框未动；无“M3 通过”类越权表述 | **通过** | base 与 head 逐行比对：`:46`（P6 登记表 IDENTICAL）、`:103`（§5 前言 discrepancy 注记 IDENTICAL）、`:135`（§5 附注 IDENTICAL）、`:141`（`**FAIL。**` IDENTICAL）、`:143`（FAIL 依据句 IDENTICAL）、`:146` IDENTICAL、`:148`（“因此本单结论为 FAIL；本单不填写 §6.1/§6.2/§6.3…”）IDENTICAL、`:150` IDENTICAL。gates 文件与 base **逐字节相同**（blob SHA 相同），§6.1 分组结论表 :467–480 全空、§6.2 附件表 :488–496 全空、§6.3 签署表 :502–507 全空，复选框未被触碰。越权表述扫描 `grep -E 'M3 *(通过|已完成|完成)|门禁通过|M3 PASS|已满足|判定通过'` → 无命中；:141 结论仍为 **FAIL**，:9 表头“结论 FAIL”未动，:13 免责声明“本文件是收尾盘点，不是完成宣告”未动。 |
| 5 | **PR 描述完整性**：含 (a) 改哪两处、(b) 派单时行号复核（基线 33268ff、:117/:145 未漂移、gates :456 未漂移、PR #44 仍 OPEN 故不重算）、(c) 明确不做三部分；各状态与依据与实测一致；无把未跑门禁写成已跑 | **通过**（含 1 处非阻塞措辞瑕疵） | (a) 描述“### (a) 改动两处”逐条写明 §5 :117 `OPEN`→`已关闭`、§6 :145 计数 9→8，与实测 diff 完全对应。(b) 描述“### (b) 派单时行号复核（2026-11-04，基线 main @ 33268ff）”四条子项逐条独立复核通过：base SHA = `33268ff2c5721e31e3a115fe8469d7869cd60dbc` ✓；closeout §5 目标行在 base 与 head 均落在 :117、§6 目标行均落在 :145（`sed -n '117p;145p'` base 命中目标两行）✓；gates :456 仍为 B0-02 已关闭行、:457 仍 B3-01 OPEN，未漂移 ✓；PR #44 仍 OPEN 未合并，故按 8 个表述未重算 ✓。(c) 描述“### (c) 明确不做”6 条与实测一致：:46/:103 未动、FAIL 结论不变、gates §6 复选框未碰、代码/CI/其他文档未改、`state.json`/`PIPELINE-LOG.md`/`ERROR-LOG.md` 不在仓库跟踪集（`git ls-tree` 无命中）、作者不合并。**门禁表述**：“验收自查”末句写“未运行门禁，不声明 check-runs 结果；头 check-runs 由评审与门禁阶段另行核查”——未把未跑门禁写成已跑，属如实声明。（措辞瑕疵见 P2。） |
| 6 | **CI 现状记录**：如实记录头 check-runs（轮次、失败步骤、skipped 项）；内容结论与 CI 结论分开；不把 CI 失败当内容通过，不把内容问题与 CI 失败混淆 | **通过** | 见第 0 节“头 check-runs 现状”：run `41796436619`，7 job 全 success，0 failed、0 job 级 skipped、0 pending；唯一 skipped 为 `fuzz smoke (nightly)` 内的条件上传步骤“Upload any crash artifacts”（无崩溃则跳过，正常分支）；失败步骤无。本报告 1–6 项为内容判定、CI 为独立事实记录，二者在第 0 节与第 2 节分开陈述。未把 CI 结果用于论证内容正确性。 |

**逐项小结**：6 项全部 **通过**（第 5 项含 1 处非阻塞措辞瑕疵，见 P2）。

---

## 2. file:line 问题清单

### 阻塞项（0）

无。

### 非阻塞项（2）

| ID | 位置 | 描述 | 处置建议 |
|---|---|---|---|
| **P1** | [docs/m3-m4-closeout.md:117](file:///workspace/docs/m3-m4-closeout.md#L117) | B0-02 状态列改为 `已关闭` 后，**证据栏仍只指向 PR #25 的失败期报告**（`interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md` 与同目录 `-baseline/report.md`），未指向 PR #29 的闭环重跑报告（`interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md`），而 gates:456 的证据列已含该闭环报告。单看 closeout 一行，“已关闭”的直接证据需跳转 gates:456 才能拿到。 | 任务书明确限定本单只改两处、证据栏不动，故**不构成本单阻塞**。建议后续单（RV-PR43-N3 或收尾单）在证据栏补 2026-11-02 闭环报告指针，与 gates:456 证据列对齐。 |
| **P2** | PR #45 描述“### 验收自查”末句 | 描述写“未运行门禁，不声明 check-runs 结果”，但同节“### (b)”把派单时的行号复核与 PR #44 状态一并写入自查，且作者对外总结称“当前唯一 check build/lint 为 pending”。这两处叠加易被读成“状态已全部自核并自证”。实测 `build / lint (stable)` 已 `completed/success`，作者所述 pending 为 15:58 的过期快照。 | 描述本身未越权（未把门禁写成已跑），仅建议后续 PR 描述区分“作者自查”与“CI 实测”，并更新过期 pending 表述。 |

### 记录性观察（不列入问题清单，供协调者参考）

| 观察 | 说明 |
|---|---|
| O1 | closeout:56 仍写 PR #2 “OPEN”，:135 附注写 PR #2 “已关闭未合并”。实测 PR #2 API `state=CLOSED, mergedAt=null`。该矛盾**在 base 中已存在**且两行本单均未动（逐字节 IDENTICAL），不在本单范围，不阻塞本 PR。 |
| O2 | `interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md` 内 :12/:32/:44/:240 仍写 “GAP-M3-B0-02 remains OPEN”。这是 PR #29 当时的报告快照（其自身声明“状态变更属里程碑验收 PR”），非本单文件，本单未动，属预期。 |
| O3 | closeout :7 表头“基线 `main` @ `4ba22ea`”、:50 “P0–P8 共 26 个已合并 PR” 均为 P9-1 单自身的历史基线，base 中已存在且本单未动。 |

---

## 3. 结论

**批准合并**（Approve to merge）。

理由：

1. **范围最小且精确**：净 diff 仅 `docs/m3-m4-closeout.md` 一个文件 +2/−2，逐字节验证只有 :117 与 :145 两个单元格变更；gates 文件 blob SHA 与 base 完全相同，文件集合两侧一致，无代码/CI/其他文档/二进制新增。
2. **事实基础成立**：B0-02 的关闭由 PR #43 合并（`33268ff`）在 gates §5 落地，:456 状态 `已关闭`、:457 仍 `OPEN`，措辞一致；阻塞计数经 T-01…T-08 全项核对与 PR #44 未合并核实，8 个准确，未重算为 7。
3. **保守性正确**：历史行 :46/:103、FAIL 结论句、gates §6.1/§6.2/§6.3 复选框全部未动；全文无“M3 通过”类越权表述；PR 描述如实声明未运行门禁、不声明 check-runs 结果。
4. **CI 现状健康**：头 `2654ec3` 的 `CI` run `41796436619` 7/7 success、0 failed、无 job 级 skipped；`mergeable=true` / `mergeable_state=clean`。
5. **无阻塞项**：两处非阻塞观察（P1 证据栏未指向闭环报告、P2 描述措辞）均属任务书明确排除的范围或表述层面，不影响本单结论成立，可在后续单处理。

本评审只出具报告，**未合并、未修改任何分支、未新建 PR**。合并动作与门禁定性由协调者按流程执行。

---

## 附：本次核验方法清单（可复现）

```
git clone https://github.com/medivhc/rtx-rs.git
git fetch origin '+refs/pull/45/head:refs/remotes/origin/pr45' '+refs/heads/main:refs/remotes/origin/main'
git merge-base origin/main origin/pr45                  # 33268ff2c5721e31e3a115fe8469d7869cd60dbc
git rev-list --count origin/main..origin/pr45           # 1
git diff --raw / --numstat / --stat <mb> origin/pr45     # 1 file, 2/2
git diff origin/main origin/pr45 -- docs/m3-m4-gates.md  # (empty)
git rev-parse origin/main:docs/m3-m4-gates.md origin/pr45:docs/m3-m4-gates.md   # 同 blob
git ls-tree -r --name-only origin/{main,pr45}           # 文件集合一致
gh pr view 45 --json headRefOid,mergeable,mergeStateStatus,body,files,statusCheckRollup
gh api repos/medivhc/rtx-rs/commits/2654ec3/check-runs
gh api repos/medivhc/rtx-rs/commits/33268ff/check-runs
gh run view 41796436619 --json jobs
gh pr view 44 --json state,mergedAt,headRefOid
gh pr view 43 --json state,merged,mergedAt,mergeCommitSha
```
