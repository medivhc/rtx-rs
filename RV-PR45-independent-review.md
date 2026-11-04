# RV-PR45 独立评审报告 — rtx-rs PR #45

- 评审者：独立评审会话（MiniMax-M3.1-Flash），与作者不同会话、不同模型
- 评审日期：2026-11-05（Asia/Shanghai）
- 评审对象：PR #45 `docs(rv-pr43-n2-closeout-refresh)`，标题「docs(closeout): RV-PR43-N2 刷新 GAP-M3-B0-02 状态与 §6 阻塞计数（只建 PR，不合并）」
- 评审方式：全新 `git clone https://github.com/medivhc/rtx-rs` 到 `/tmp/rv-review`，本地 git 实测 + GitHub API 实测（`gh api`），未采信协调者核验结论或作者自述
- 产出边界：只出本报告；**未**合并、**未**改分支、**未**新建 PR、**未**新建 issue/comment

## 0. 评审所对的对象与基线（均为本人实测）

| 项 | 实测值 | 取证方式 |
|---|---|---|
| PR | #45，state `OPEN`，`draft=false`，`merged=false` | `gh api repos/medivhc/rtx-rs/pulls/45` |
| 头 SHA | `2654ec306a52e36334597e19be5542b9ef820b1c`（`2654ec3`） | `gh pr view 45 --json headRefOid`；`git rev-parse origin/docs/rv-pr43-n2-closeout-refresh`；`git ls-remote` 一致 |
| base | `main` | `gh pr view 45 --json baseRefName` |
| base SHA（main 头） | `33268ff2c5721e31e3a115fe8469d7869cd60dbc`（`33268ff`） | `git ls-remote origin refs/heads/main`（评审时复核仍为 `33268ff`，无漂移） |
| merge-base | `33268ff2c5721e31e3a115fe8469d7869cd60dbc` = main 头（**等于 base，无分叉漂移**） | `git merge-base origin/main origin/docs/rv-pr43-n2-closeout-refresh` |
| 提交数 | 1 个：`2654ec3` `docs(closeout): RV-PR43-N2 sync GAP-M3-B0-02 closure and §6 blocking count`（作者 崔翔 `<xiangcui@geometricalpal.com>`，2026-11-04 16:01:41 +0800） | `git rev-list --count` / `git log --oneline` |
| 净 diff | 1 文件 / +2 / −2：`docs/m3-m4-closeout.md` | `git diff --stat origin/main...origin/...`；`gh api pulls/45/files` → `{"filename":"docs/m3-m4-closeout.md","additions":2,"deletions":2,"changes":4}` |
| mergeable | `MERGEABLE` | `gh pr view 45 --json mergeable` |
| mergeStateStatus | `CLEAN` | `gh pr view 45 --json mergeStateStatus` |
| potentialMergeCommit | `a5e160330709c72d1aa0622be51fe85fe0a3c060` | `gh pr view 45 --json potentialMergeCommit` |
| 合并冲突预检 | 无冲突（`git merge-tree --write-tree origin/main origin/…` 干净返回） | `git merge-tree` |
| 已有 review / issue comment | reviews = 0，comments = 0 | `gh api pulls/45/reviews`、`issues/45/comments` |

头 SHA 与任务书给定的 `2654ec3`、base `33268ff` 完全一致；**merge-base == main 头 == base**，说明该分支是在最新 main 上直接单提交建立，未落后、未分叉。

## 1. 结论

**批准合并（Approve）**

理由摘要：范围严格限定在任务书允许的 closeout 两处（`:117`、`:145`），`git diff --unified=0` 显示恰好 2 个 hunk（`@@ -117 +117 @@`、`@@ -145 +145 @@`），无第三个 hunk；gates 文档与 base **字节级相同**（`git diff --exit-code` 退出 0）；无代码/常量/CI/其他文档改动；头树无任何图片或二进制文件。两处改动的**事实依据**均经本人独立核实成立（PR #43 已合并并把 gates `:456` 状态改为 `已关闭`；PR #44 仍 OPEN，阻塞 GAP 实为 T-01…T-08 共 8 个）。历史行 `:46`、`:103`、`FAIL` 结论句、gates §6.1/§6.2/§6.3 复选框全部未动，无越权表述。头 check-runs 实测 7/7 success，无失败、无 job 级 skipped。文档改动与 CI 结论无关，内容层与 CI 层分别成立。

非阻塞观察项 4 条见 §4，均不构成合并阻塞，但建议在后续单处理。

## 2. 验收逐项表（6 项）

| # | 验收项 | 结论 | 证据（本人实测） |
|---|---|---|---|
| 1 | **范围**：diff 仅含任务书允许的 closeout 两处；无 gates §6 复选框 / 其他文档 / 代码 / CI 改动；无顺带处理无关缺口；头树无新增二进制 | **通过** | `git diff --stat origin/main...origin/docs/rv-pr43-n2-closeout-refresh` → `docs/m3-m4-closeout.md | 4 ++--`（1 file, +2/−2）；`git diff --unified=0` 仅 `@@ -117 +117 @@`、`@@ -145 +145 @@` 两个 hunk；`gh api pulls/45/files` 只 1 个文件；`git diff --exit-code origin/main origin/… -- docs/m3-m4-gates.md` 退出 0（**gates 文档字节级未变**，故 §6.1/§6.2/§6.3 复选框与表格必然未动，`awk NR>=461&&NR<=512` 实测 §6.1/§6.2/§6.3 表格仍全空白）；`git diff --name-status` 仅 `M docs/m3-m4-closeout.md` → 无代码/常量/`.github/workflows` 改动；无关缺口未触碰 —— GAP-M4-T-01 预算内容仍不在本 PR（`git ls-tree origin/main` 无 `docs/m4-resource-budget.md`，仅存在于 PR #44）、RV-PR40-N2/RV-PR42-NB1 无任何 diff、B3-01 判定未动（closeout `:133` 与 gates `:457` 均未变）、PR #2 语料未动（closeout `:56` base 与 head 逐字相同）；头树二进制/图片：`git ls-tree -r --name-only` 匹配 `\.screenshots/\|\.(png\|jpg\|gif\|webp\|ico\|pdf\|zip)$` 结果 **0**，`git diff --diff-filter=A` 新增文件列表为空，`git diff --raw` 显示唯一条目 mode `100644`（文本文件） |
| 2 | **`:117` 改动准确性**：B0-02 确由 PR #43（合并 `33268ff`）在门禁 §5 关闭；gates `:456` 确为 B0-02 已关闭行、`:457` 仍为 B3-01 `OPEN`；证据栏与 `:456` 指针未被顺手改动；措辞与 gates 一致 | **通过** | PR #43 状态实测 `state=MERGED`、`mergedAt=2026-11-04T07:30:35Z`、`mergeCommit.sha=33268ff2…`（即 base 头）；`git show 4614539 --word-diff=porcelain -- docs/m3-m4-gates.md` 仅 `-OPEN` / `+已关闭` 与证据追加，确认 gates `:456` 状态列为 `已关闭`；`awk NR==456` → 状态单元 `[ 已关闭 ]`，`awk NR==457` → `GAP-M3-B3-01` / 类型 `非阻塞（条件适用）` / 状态 `OPEN`（B3-01 未被顺带改动）；closeout `:117` 证据单元仍为 `` `docs/m3-m4-gates.md:456` `` + `interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md` 与同目录 `-baseline/report.md`，与 base 逐字相同（diff 仅动状态单元）；措辞 `已关闭` 与 gates `:456` 状态单元**逐字一致**；行号未漂移：base `:117`/`:145` 与 head `:117`/`:145` 为同一行（`git show origin/main:docs/m3-m4-closeout.md \| awk NR==117/145` 与 head 同行号内容对应） |
| 3 | **`:145` 计数准确性**：PR #43 后阻塞 GAP 确为 T-01…T-08 共 8 个；PR #44 仍 OPEN 故 T-01 仍计入、不需重算为 7；新表述与 §5 表格一致；无重复计入或漏计 | **通过** | PR #44 实测 `state=OPEN`、`mergedAt=null`、头 `2e637c86bf7f2e3b873450ae06bae9c78bffe19b`，`git ls-tree origin/main` 确认 `docs/m4-resource-budget.md` **不在 main**，故 T-01 仍为 `OPEN`，须计入 → 8 而非 7；`docs/m4-target-selection.md:284–291` 状态列实测 8 行**全为 `OPEN`**（`awk` 取末列 → 8 个 `OPEN`）；gates §5 实测仅 `:456`（阻塞·已关闭）与 `:457`（非阻塞·OPEN）两行，无第三个阻塞行；head `:145` 表述「已登记阻塞 GAP **8 个**：`GAP-M4-T-01`…`GAP-M4-T-08`（选型文档 §6，8 个），均为 `OPEN`；`GAP-M3-B0-02`（门禁 §5，1 个）已关闭」与 §5 表格逐行一致（`:117` B0-02 已关闭，`:118`–`:125` T-01…T-08 八行均 `OPEN`）；无重复计入（B0-02 只出现在「已关闭」分句）、无漏计（8 个 T 项以区间 `…T-08` 覆盖且与表格 8 行数吻合）；仓库内已无残留「9 个」阻塞计数（`grep -rn "9 个\|9个" docs/ README.md CHANGELOG.md` 仅命中 `docs/m1-2-implementation-notes.md:48` 的 clippy 参数说明，与缺口计数无关） |
| 4 | **历史与结论 preservation**：`:46`、`:103` 未动；`因此本单结论为 FAIL` 句与 §6 结论未动；gates §6.1/§6.2/§6.3 复选框未动；无「M3 通过」类越权表述 | **通过** | `git diff --unified=0` 仅 2 hunk（`:117`/`:145`），故 `:46`（P6 登记表）、`:103`（§5 前言 discrepancy 注记）**在结构上不可能被触及**，实测两者在 head 与 base 完全一致（`:46` = `| P6（R6 QUIC / WebTransport） | #25 | ddc43e4 | Chrome WebTransport 两阶段实测（B0 阻塞，登记 GAP-M3-B0-02） |`；`:103` = `| 4 | docs/m3-m4-gates.md:452 | … §5 前言称…未修：同上 |`）；结论句未动：head `:141` `**FAIL。**`、`:143` 依据句、`:148` `因此本单结论为 FAIL；本单不填写 docs/m3-m4-gates.md §6.1/§6.2/§6.3…` 与 base 一致；gates §6 复选框：`git diff --exit-code … -- docs/m3-m4-gates.md` 退出 0（文档完全未变），实测 `:467`–`:480` §6.1、`:488`–`:496` §6.2、`:503`–`:507` §6.3 仍全空白；越权表述：`grep -n "PASS\|通过" docs/m3-m4-closeout.md` 仅命中 `:13`（“不是完成宣告…不指门禁条目通过”）、`:127`（§6.2 附件缺失行）、`:143`（引用 gates 规则原文），diff 内无「M3 通过」字样 |
| 5 | **PR 描述完整性**：(a) 两处改动、(b) 派单时行号复核（基线 / `:117`/`:145` 未漂移 / gates `:456` 未漂移 / PR #44 仍 OPEN 故不重算）、(c) 明确不做，三部分齐备；各状态与依据与实测一致；未把未跑门禁写成已跑 | **通过** | `gh api pulls/45 --jq .body` 实测三部分齐备：(a) 列出 `:117` 状态 `OPEN`→`已关闭`（“措辞与 docs/m3-m4-gates.md:456 行一致”）与 `:145` 计数 9→8；(b) 基线 `33268ff2c5721e31e3a115fe8469d7869cd60dbc`、§5 目标行仍 `:117`、§6 目标行仍 `:145`、gates `:456` 仍为 B0-02 行且 `:457` 为 B3-01 `OPEN`、PR #44（头 `2e637c8`）仍 OPEN 故 T-01 仍计入、按 8 个表述未重算；(c) 不改 `:46`/`:103`、不改 FAIL 结论、不填不改 §6.1/§6.2/§6.3、不改代码/常量/CI/其他文档、不改协调者文件、作者不合并。逐条与本人实测吻合：基线 SHA 一致、`:117`/`:145` 行号一致（base 与 head 同号）、gates `:456`/`:457` 内容一致、PR #44 头 `2e637c86…`（描述中 `2e637c8` 前缀吻合）且 `OPEN` 未合并。门禁未虚报：描述明写「未运行门禁，不声明 check-runs 结果；头 check-runs 由评审与门禁阶段另行核查」 |
| 6 | **CI 现状记录**：头 check-runs 现状如实记录；内容结论与 CI 结论分开；不把 CI 失败当内容通过，也不把内容问题与 CI 失败混淆 | **通过** | 见 §3 独立实测：头 `2654ec3` **7/7 check-run 全部 `completed/success`**（run #135 `CI`，`head_sha=2654ec3…`，`run_attempt=1`，`event=pull_request`，整体 `conclusion=success`），无失败 check-run、无失败 step，唯一 skipped step 为 `fuzz smoke (nightly)` 的 `Upload any crash artifacts`（条件性 artifact 上传，非门禁步骤）；`main@33268ff` 同轮 7/7 success。作者总结「唯一 check build/lint 为 pending」为 15:58 旧状态（该 job 实测 `started_at=2026-11-04T08:02:19Z`/`completed_at=08:02:49Z` 已 success），本报告以实测现状为准。内容结论与 CI 结论在本文档中分列（§1 内容判定 vs §3 CI 现状），无互相代偿 |

## 3. 头 check-runs 现状（独立实测，非照抄）

评审时点（2026-11-05）拉取 `gh api repos/medivhc/rtx-rs/commits/2654ec3…/check-runs`，`total_count = 7`，全部 `status=completed` / `conclusion=success`：

| # | check-run 名 | 结论 | started_at (UTC) | completed_at (UTC) | run |
|---|---|---|---|---|---|
| 1 | build / lint (stable) | success | 08:02:19 | 08:02:49 | CI #135 |
| 2 | suite (stable) | success | 08:02:52 | 08:03:29 | CI #135 |
| 3 | suite (msrv) | success | 08:02:52 | 08:03:41 | CI #135 |
| 4 | coverage gate | success | 08:02:52 | 08:03:36 | CI #135 |
| 5 | crypto vectors (published) | success | 08:02:52 | 08:03:09 | CI #135 |
| 6 | fuzz smoke (nightly) | success | 08:02:52 | 08:05:11 | CI #135 |
| 7 | property tests (deep sweep) | success | 08:02:53 | 08:03:15 | CI #135 |

- 失败 check-run：**0**。失败 step：**0**。
- skipped step：仅 1 处 —— `fuzz smoke (nightly)` → `Upload any crash artifacts`（条件性 artifact 上传，非门禁判定步骤；该 job 自身结论为 success）。
- job 级 skipped：**0**（7 个 job 全部 `completed`）。
- 该 head SHA 的 workflow run 总数 = 1（`CI` #135，`run_attempt=1`），无重跑轮次。
- 对照基线：`main@33268ff` 同轮 check-runs 亦为 7/7 success。
- 判定说明：以上是 **CI 结论**。**内容结论**见 §1、§2，二者分开成立；本 PR 仅改 1 个 markdown 文件的 2 行文本，不涉及构建产物，因此 CI 全绿不替代内容审查——内容结论由 §2 六项逐项实测独立得出。

## 4. file:line 问题清单

### 阻塞项

**无。** 未发现任何阻塞合并的问题。

### 非阻塞项（建议后续单处理，不影响本次合并）

| # | 位置 | 现象 | 性质 | 说明 |
|---|---|---|---|---|
| N-1 | `docs/m3-m4-closeout.md:117` | 状态已改为 `已关闭`，但同行「影响」列仍完整保留失败叙述「Chrome 建立 WebTransport 会话失败…；B1/B2 因此 `not_run`」 | 历史叙述保留 | 任务书明确限定本单仅改状态单元与 `:145` 计数，「影响」列未在授权范围内；`:145` 与 §6.1 表格也仍按失败事实描述。读者若要精读需对照 gates `:456`。**属范围纪律正确的表现，不视为缺陷**；若后续单希望消除歧义，可单独立单把影响列改为「已由 PR #29 重跑关闭（历史失败叙述见 gates 证据）」 |
| N-2 | `docs/m3-m4-closeout.md:56` | 「仍 open 的 PR」表把 PR #2 状态写作 `OPEN`，但 API 实测 PR #2 为 `closed`（`closed_at=2026-11-03T11:35:21Z`，`merged=false`），且 head `74640b8` 与描述一致 | **基线既有陈旧项，非本 PR 引入** | base 与 head 该行逐字相同（`git show origin/main:docs/m3-m4-closeout.md \| awk NR==56` 与 head 完全一致）。同时本文件 `:135` 附注已正确记载「PR #2 已关闭未合并」，同文件内存在自相矛盾。任务书把 PR #2 语料列为本单**不处理**范围，作者未越权是正确的。**建议协调者另立单**修 `:56` 的状态单元（`OPEN`→`closed`），属 RV-PR43-N2 之外 |
| N-3 | `interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md:10-14,32-33,44,240,243` | 该报告多处写「`GAP-M3-B0-02` remains `OPEN` in `docs/m3-m4-gates.md` §5」「`GAP-M3-B0-02` is still `OPEN`」 | **PR #29 遗留的历史叙述，非本 PR 引入** | 该报告撰写于 PR #43 关闭 B0-02 之前，是 PR #29 提交当时的自述（“The GAP status is not changed by this PR”）。PR #43 只改了 gates 一行，未同步本报告；本 PR 范围不含 interop（`git diff --stat … -- interop/` 无输出）。属于跨单的陈旧叙述，**建议后续单统一刷新**，不阻塞本 PR |
| N-4 | `docs/m3-m4-closeout.md:143` | §6 依据句仍引用 `docs/m3-m4-gates.md:442`（§4 规则 1）与 `:509`（§6.3） | 无问题，仅记录 | 实测 gates `:442` = 「存在任一阻塞 GAP 时，§6 结论必须是 FAIL」，`:509` = 「结论只能是 PASS 或 FAIL」，指针与内容对得上，行号未漂移；**这正是 FAIL 结论仍然成立的依据**，登记为无问题项以示已核 |

## 5. 与协调者核验 / 作者自述的差异（以本人实测为准）

| 来源 | 说法 | 本人实测 | 结论 |
|---|---|---|---|
| 任务书转述的协调者核验 | merge-base = main 头 `33268ff`；1 commit `2654ec3`；diff 仅 `docs/m3-m4-closeout.md` +2/−2 | 完全一致 | 无差异 |
| 任务书转述的协调者核验 | 头树无 `.screenshots/` 或图片文件 | 一致（匹配计数 0，无新增文件） | 无差异 |
| 任务书转述的协调者核验 | 头 check-runs 7/7 success；PR `mergeable=true`/`mergeable_state=clean` | 一致（`MERGEABLE` / `CLEAN`，7/7 success） | 无差异 |
| 作者自述（转述） | 「当前唯一 check build/lint 为 pending」 | 该 check 实测 `success`（08:02:19→08:02:49 完成）；且 08:02:11 才创建 PR，pending 是创建瞬间的状态 | 作者自述为**过期快照**，本报告以实测为准 |
| 作者 PR 描述 (b) | 基线 `33268ff2c5721e31e3a115fe8469d7869cd60dbc`、`:117`/`:145` 未漂移、gates `:456` 未漂移、PR #44 仍 OPEN 故不重算 | 逐条实测吻合（PR #44 头 `2e637c86…`，`OPEN`，`mergedAt=null`，`docs/m4-resource-budget.md` 不在 main） | 无差异 |
| 任务书背景段 | 协调者称本轮实测头 7/7 success，评审「须独立再查」 | 本人独立拉取 API 复核，同为 7/7 success | 无差异 |

**唯一需要指出的事实出入**：作者总结所称「唯一 check build/lint 为 pending」与评审时点实测（该 job 及全部 7 个 job 均 `success`）不符，原因是该状态取自 PR 创建时刻（2026-11-04T08:02:11Z，CI 尚未完成），属时间切片差异而非误报；作者的 PR 描述本身并未宣称 check-runs 结果，并明确交由评审核查，处理方式恰当。

## 6. 遗留风险与合并后建议

1. 本单为**纯文档**刷新，不改变门禁判定结果：`docs/m3-m4-closeout.md:141` 仍为 `FAIL`，gates §6.1/§6.2/§6.3 仍全空白，M3/M4 均未完成，8 个阻塞 GAP（T-01…T-08）仍未处置。合并本 PR **不构成**任何里程碑完成宣告。
2. N-2（`:56` PR #2 状态陈旧）、N-3（interop 报告 `remains OPEN` 叙述）建议协调者另立单，不在本 PR 追改。
3. 门禁阶段仍应以 xc CI-exact 重跑为准做最终定性；本报告的 CI 结论来自 GitHub API 记录，属**评审时点快照**。

## 7. 评审操作声明

本评审仅执行读取类操作：`git clone`（至 `/tmp/rv-review`）、`git fetch`/`ls-remote`/`log`/`diff`/`show`/`merge-base`/`merge-tree`（只读查询）、`gh api` 只读查询。未执行任何 `push`、`merge`、`git commit`、PR 创建或 issue/comment，未修改远端或本地分支历史。
