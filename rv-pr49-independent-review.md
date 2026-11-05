# RV-PR49 独立评审报告 — rtx-rs PR #49

> 评审人：独立评审（MiniMax 模型，与作者不同会话、不同模型）
> 评审方式：一手 `git clone` + `git` 命令 + GitHub API（`gh api`）实测，未采信协调者核验结论或作者自述
> 评审日期：2026-11-05
> 结论：**批准合并（Approve merge）** — 5 项验收逐项通过，0 项阻塞问题，3 项非阻塞观察

---

## 0. 评审基准（本次评审所对的对象）

| 项 | 实测值 | 来源 |
|---|---|---|
| 仓库 | `https://github.com/medivhc/rtx-rs` | `git clone` 到 `/tmp/rv49`（全新克隆，未复用工作区已有 clone） |
| 评审所对的头 SHA | `56944ad2cdd402633a1b34a934fa6c33a2354df7` | `git rev-parse pr49`；PR API `head.sha` 一致 |
| 头分支 | `docs/rv-pr47-nb1-neutral-heading` | PR API `head.ref`；`refs/remotes/origin/docs/rv-pr47-nb1-neutral-heading` = `56944ad` |
| base | `main` | PR API `base.ref` = `main` |
| base SHA | `952703b4112314696e363470e9799ddc9cb17bb6` | `git rev-parse origin/main`；`git ls-remote origin refs/heads/main` 同值；PR API `base.sha` 同值；`git ref/heads/main` API 同值 |
| merge-base | `952703b4112314696e363470e9799ddc9cb17bb6` | `git merge-base origin/main pr49` — **等于 base 头**，即分支严格基于最新 main，无落后、无额外分叉 |
| commit 数 | 1 | `git rev-list --count origin/main..pr49` = 1；反向 `pr49..origin/main` = 0（未落后 main） |
| 提交信息 | `docs(closeout): neutralize :52 section heading (RV-PR47-NB1)` | `git show --format=%s`；作者时间 `2026-11-05T00:31:55Z`（= 08:31:55 CST），与任务书记述的巡检派单时序吻合 |
| mergeable | `mergeable: true` / `mergeable_state: clean`（PR 详情端 `mergeable=MERGEABLE`, `mergeStateStatus=CLEAN`） | `gh api repos/medivhc/rtx-rs/pulls/49` |
| 本地合并模拟 | 零冲突；合并后树 `284c1029…` 与 pr49 树**完全相同** | `git merge --no-ff pr49` onto `952703b`（`ort` 策略，无冲突提示） |
| PR 状态 | OPEN、非 draft、未合并（`mergedAt=null`, `closedAt=null`） | PR API |
| PR 创建时间 | `2026-11-05T00:32:32Z`（= 08:32:32 CST） | PR API `created_at` — 与任务书记述一致 |

### 头 check-runs（实测快照，非转述）

查询用**完整 SHA** `56944ad2cdd402633a1b34a934fa6c33a2354df7`（`gh api repos/medivhc/rtx-rs/commits/<sha>/check-runs`）。

**总数 7，全部 `completed` / `success`，0 失败、0 skipped job：**

| # | check name | status | conclusion | started | completed |
|---|---|---|---|---|---|
| 1 | `suite (stable)` | completed | success | 2026-11-05T00:33:33Z | 2026-11-05T00:34:08Z |
| 2 | `suite (msrv)` | completed | success | 2026-11-05T00:33:34Z | 2026-11-05T00:34:17Z |
| 3 | `fuzz smoke (nightly)` | completed | success | 2026-11-05T00:33:34Z | 2026-11-05T00:36:06Z |
| 4 | `property tests (deep sweep)` | completed | success | 2026-11-05T00:33:33Z | 2026-11-05T00:33:49Z |
| 5 | `coverage gate` | completed | success | 2026-11-05T00:33:33Z | 2026-11-05T00:34:15Z |
| 6 | `crypto vectors (published)` | completed | success | 2026-11-05T00:33:33Z | 2026-11-05T00:33:44Z |
| 7 | `build / lint (stable)` | completed | success | 2026-11-05T00:32:46Z | 2026-11-05T00:33:31Z |

补充实测：

- 关联 workflow run `41942108868`：`event=pull_request`、`run_attempt=1`、`head_sha` 与评审头一致、`created_at=2026-11-05T00:32:42Z`、`conclusion=success`。
- 该头 SHA 下 **仅此 1 个 workflow run**（`actions/runs?head_sha=…` → `total_count=1`），无重跑、无第二个 workflow。
- job 内部 step 级：**失败 step 0 个**；skipped step 仅 1 个 —— `fuzz smoke (nightly)` 的 `Upload any crash artifacts`（条件性步骤，正常）。
- 该 commit 的 legacy commit status（`/commits/<sha>/status`）为 `total_count=0`，无旧式 context 可被误读。
- 短 SHA `56944ad` 查询在本环境同样返回 7（`gh` 会解析短 SHA），但本次一律以完整 SHA 为准。

---

## 1. 验收逐项表（5 项逐项判定）

| # | 验收项 | 判定 | 独立实测证据 |
|---|---|---|---|
| 1 | **范围**：diff 确只含 :52 标题一行；无表格/附注/历史行/§6/其他文件/代码/CI 改动；无顺带处理无关缺口；头树无新增二进制；头文件无「仍 open」残留 | **通过** | 见 §2 逐条展开 |
| 2 | **NB-1 事实准确性**：PR #47 确已合并、合并提交确为 2ec9a26、:56 确为 closed_unmerged、:135 确记录 PR #2 已关闭未合并；新标题确不预设条目状态；未采用另一候选表述的理由成立、无夸大或偷换 | **通过** | 见 §3 逐条展开 |
| 3 | **一致性**：改后标题与 :56、:135 确无语义冲突；表格各格/附注/历史行/§6 FAIL 结论确逐字未动；未把标题中性化写成 PR #2 状态变更或 M3 结论变更 | **通过** | 见 §4 逐条展开 |
| 4 | **PR 描述与依据**：描述确含改动前后对照与选用理由；各状态与依据（头/基线/行号/合并提交）与实测一致；无「未跑门禁写成已跑」 | **通过** | 见 §5 逐条展开 |
| 5 | **CI 现状记录**：头 check-runs 现状如实记录；内容结论与 CI 结论分开表述；未把 CI 失败当内容通过、也未把内容问题与 CI 失败混为一谈 | **通过** | 见 §6 逐条展开 |

**5 项全部通过，0 项不通过。**

---

## 2. 第 1 项：范围 —— 通过

### 2.1 diff 范围：仅 :52 一行

```
$ git diff --stat origin/main...pr49
 docs/m3-m4-closeout.md | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

$ git diff --numstat origin/main...pr49
1	1	docs/m3-m4-closeout.md

$ git diff --name-status origin/main...pr49
M	docs/m3-m4-closeout.md
```

### 2.2 全文级证明：除 :52 外逐字未动（比 diff 更强的证据）

把 base 与 head 的该文件全文取出做**只显示差异行**的全文件比对：

```
$ diff --unchanged-line-format='' --old-line-format='BASE %dn: %L' \
       --new-line-format='HEAD %dn: %L' base.md head.md
BASE 52: ### 仍 open 的 PR（不属已合并清单）
HEAD 52: ### 不在已合并清单内的 PR
```

**全文 164 行中，只有第 52 行不同，其余 163 行逐字节相同**（`wc -l` base 164 / head 164）。

这直接证明：表格每格、`:135` 附注、历史行、`:46`/`:103`、§6 FAIL 结论全部未被触碰（它们都不在第 52 行）。

### 2.3 关键行逐行哈希核对（base vs head）

| 行 | 内容 | base md5 | head md5 | 结果 |
|---|---|---|---|---|
| 46 | `\| P6（R6 QUIC / WebTransport） \| #25 \| ddc43e4 \| …` | `1a729ec7…` | `1a729ec7…` | SAME |
| 56 | `\| #2 \| test/fuzz-regression-corpus \| 74640b8 \| closed_unmerged \| …` | `c84007c1…` | `c84007c1…` | SAME |
| 103 | `\| 4 \| docs/m3-m4-gates.md:452 \| §5 前言称…` | `39a36cc6…` | `39a36cc6…` | SAME |
| 135 | `附注（并行跟进项状态…）PR #2 … 已关闭未合并（closed_at 2026-11-03T11:35:21Z…）` | `7b9f661c…` | `7b9f661c…` | SAME |

### 2.4 代码 / CI / 其他文件零改动

```
$ git diff origin/main pr49 -- .github/workflows/ci.yml | wc -l        → 0
$ git diff origin/main pr49 -- crates/ interop/ benchmarks/ measurements/ fuzz/ \
                                Cargo.toml Cargo.lock | wc -l            → 0
```

### 2.5 头树无新增二进制文件

- `git diff --name-status --diff-filter=A origin/main...pr49` → **空**（无任何新增文件）。
- 头树与 base 树文件数相同：`git ls-tree -r` 均为 **266**。
- 头树全部对象类型均为 `blob`（`git ls-tree -r pr49 | cut -d' ' -f2 | sort -u` → 仅 `blob`，无 `commit`/`tree` 叶子异常）。
- 头树中仅有 4 个非文本文件（`crates/rtx-h3/tests/fixtures/chrome-*.bin` ×2、`interop/…/capture/*.bin` ×2），**这 4 个在 base 树中逐一存在且本 PR 未改动**（`git diff --name-only` 不含它们）。
- 头树无 `.screenshots/`、无 `.png`（评审产物分支上的截图文件未进入 PR 头）。

### 2.6 头文件内「仍 open」零残留

```
$ git grep -n "仍 open" pr49 -- .        → exit 1（无命中）
$ git grep -n "仍open"  pr49 -- .        → exit 1（无命中）
$ git grep -n "open 的 PR" pr49 -- .     → exit 1（无命中）
```

全仓所有 `open` 上下文命中均为 `GAP-*` 状态列的 `OPEN`（:92、:118–:127、:133、:145）与 `open_in_place` 等代码符号，与本节标题无关。

### 2.7 无顺带处理无关缺口

- 头树 `git grep "RV-PR47-NB1"` → 无命中（该编号只出现在 commit message 与 PR 描述中，未写入任何被跟踪文件），即 RV-PR48-NB1（interop 报告用词）、RV-PR40-N2、RV-PR42-NB1 均未被塞进本单。
- **PR #2 未重开**：`gh api pulls/2` → `state=closed`, `merged=false`, `merge_commit_sha=null`, `closed_at=2026-11-03T11:35:21Z`, `head=74640b8189daa3452497efa6e0b59d952cefa919`。
- **PR #31 未重开**：`gh api pulls/31` → `state=closed`, `merged=false`, `closed_at=2026-11-03T11:35:22Z`。
- 全仓开放 PR 仅 1 个：`gh pr list --state open` → `#49 docs/rv-pr47-nb1-neutral-heading`。
- PR #2 语料未进 `main`（`git merge-base --is-ancestor 74640b8 origin/main` 为否；本 PR diff 也不含 `crates/rtx-crypto/tests/fixtures/` 等语料路径）。

---

## 3. 第 2 项：NB-1 事实准确性 —— 通过

| 待核事实 | 实测 | 一致 |
|---|---|---|
| PR #47 确已合并 | `gh pr view 47` → `state=MERGED`, `mergedAt=2026-11-04T23:09:00Z` | 是 |
| 合并提交确为 `2ec9a26` | `mergeCommit.oid = 2ec9a26840baaeec022bef0147bb448f9a8ecb3d`；`git log --grep="PR #47"` → `2ec9a26 Merge PR #47: RV-PR45-N2 closeout PR #2 status`；父提交 `5b9e15a` + `e545036` | 是 |
| 该合并确在 main 上 | `git merge-base --is-ancestor 2ec9a26 origin/main` → 成立 | 是 |
| PR #47 的实际改动 | `git show e545036` → 唯一改动为 `:56` 状态格 `OPEN` → `closed_unmerged` | 是 |
| `:56` 状态格确为 `closed_unmerged` | base 与 head 均为 `closed_unmerged`（§2.3 哈希 SAME） | 是 |
| `:135` 附注确记录 PR #2 已关闭未合并 | `:135` 原文含「PR #2（`test/fuzz-regression-corpus`）已关闭未合并（closed_at `2026-11-03T11:35:21Z`，头 `74640b8` 未变，分支已从远端删除；语料未进 `main`）」 | 是 |
| `:135` 与 GitHub API 逐项吻合 | API PR #2：`state=closed`、`merged=false`、`closed_at=2026-11-03T11:35:21Z`、`head=74640b8…` — 与附注完全一致 | 是 |

### 3.1 新标题是否预设条目状态

新标题「### 不在已合并清单内的 PR」是对 **P0–P8 已合并清单的补集** 的集合归属陈述，句中不含任何状态谓词（无 open / closed / merged / 未合并 等状态词），只描述"这条记录放在哪个清单口径下"。因此：

- 对当前 `:56` 的 `closed_unmerged` 成立；
- 将来该节收录 open 条目、或收录其它状态条目，同样成立。

**结论：确不预设条目状态，NB-1 的原始语义张力（标题断言 open vs 表内 closed_unmerged）被解除。**

### 3.2 未采用另一候选表述的理由是否成立

作者未采用「### 已关闭、未合并的 PR（不属已合并清单）」，理由是：该表述把「已关闭、未合并」提升为**节级断言**，与表内「状态」列职责重复；将来收录其他状态条目时标题会再次失准；括号内容与主标题语义重复。

独立评估：

- 「已关闭、未合并」是**状态断言**而非归属断言，与本节已有的「状态」列确实重复（同一事实写两遍），一旦状态列取值变化而标题不变，就会产生第二重不一致 —— 理由成立。
- 「若将来收录其他状态条目，标题会再次失准」是**前瞻性论证**，成立。
- 未发现夸大：作者并未声称该表述「完全错误」，只说「不选它、且它会重复/失准」。
- 未发现偷换：作者给出的「选定理由」与「落选理由」指向同一个判准（标题层是否作状态断言），未把「落选」偷换成「更简洁」这类无关理由。

**该项要求（作者须在 PR 描述中写明选用表述的理由）已在 PR 描述「### 选用理由」两条中完整给出。**

### 3.3 与来源评审报告的关系（核对，不构成问题）

RV-PR47 独立评审报告（`rv-pr47-review-report.md`，分支 `trae/agent-rdFNZ8` 与 `0a36144` 两份副本逐字相同）的 §3 非阻塞项 **N-1** 指向的正是 `docs/m3-m4-closeout.md:52` 标题「仍 open 的 PR（不属已合并清单）」，并建议改为中性表述（该报告给的候选为「未合并清单（含已关闭未合并）」）。作者选用的是任务书给出的两个候选之一，与来源报告的建议意图一致。

---

## 4. 第 3 项：一致性 —— 通过

### 4.1 改后标题 vs `:56` 行

- `:56` 状态格 = `closed_unmerged`；新标题不再声称任何状态 → **无冲突**（原「仍 open」与该格直接矛盾，张力已消除）。

### 4.2 改后标题 vs `:135` 附注

- `:135` 记录 PR #2 已关闭未合并、`closed_at 2026-11-03T11:35:21Z`、分支已从远端删除、语料未进 `main`；新标题仅述归属 → **无冲突**。

### 4.3 表格各格 / 附注 / 历史行 / §6 FAIL 结论逐字未动

- 已由 §2.2 全文件级比对（仅第 52 行不同）+ §2.3 逐行哈希（:46/:56/:103/:135 SAME）双重证明。
- §6 现状复核：`:141` 仍为 `**FAIL。**`；`:143` 依据段、`:145` 「已登记阻塞 GAP **8 个**…均为 `OPEN`」、`:148` 「因此本单结论为 FAIL」全部原样。**M3 结论未被改动，也未被软化。**

### 4.4 未把标题中性化写成状态变更或结论变更

- commit message body 明写 "Table cells, the `:135` note, historical rows and the §6 FAIL conclusion are untouched." —— 与实测一致。
- PR 描述「## 一致性确认」「## 明确不做」两节均只谈标题中性化，未宣称 PR #2 状态变更、未宣称 M3 结论变化。
- §5.2 结论表 `:9` 的「| 结论 | **FAIL**（依据见 §6） |」未动。

### 4.5 跨文档引用未因改标题而失效

- `CHANGELOG.md:3` 以**位置**指代该节：「未合入的 PR（见 `docs/m3-m4-closeout.md` §1 末节）不在本文件」——新标题仍是 §1 的最后一个 `###` 子节（`:52`，其下紧接 `:60 ## 2. 版本与发布状态`），位置指代**仍然成立**。
- 全文无 markdown 锚点链接（`grep -n "](#"` → 无命中），不存在因标题文字变化导致的锚点断链。
- 头树内无任何其他文件按旧标题文字引用本节（`git grep "仍 open"` 零命中）。

---

## 5. 第 4 项：PR 描述与依据 —— 通过

### 5.1 任务书硬性要求项：改动前后对照 —— 存在

PR 描述含对照表：

| 位置 | 改动前 | 改动后 |
|---|---|---|
| `docs/m3-m4-closeout.md:52` | `### 仍 open 的 PR（不属已合并清单）` | `### 不在已合并清单内的 PR` |

与 `git diff` 实测逐字一致。

### 5.2 任务书硬性要求项：选用表述的理由 —— 存在

描述「### 选用理由」给出 2 条：选定理由（只描述组织口径、不对状态作预设、适用于当前与将来条目）+ 落选理由（落选表述把状态提升为节级断言、与状态列重复、将来会再次失准）。理由质量见 §3.2。

### 5.3 描述中各项依据与实测逐条比对

| 描述中的依据 | 我的实测 | 一致 |
|---|---|---|
| 基线 `main` 头 `952703b4112314696e363470e9799ddc9cb17bb6`（`git ls-remote` + `branches/main` API） | `git ls-remote origin refs/heads/main`、API `git/ref/heads/main`、PR `base.sha`、本地 `origin/main` 四者同值 | 是 |
| 分支基于此头创建 | merge-base = 该 SHA；`pr49^` = 该 SHA | 是 |
| 派单前 `:52` 仍为「### 仍 open 的 PR（不属已合并清单）」 | base `952703b` 的 `:52` 确为此串 | 是 |
| 该节表内仍仅 PR #2 一行（`:56`），状态 `closed_unmerged` | 确认 | 是 |
| `:135` 仍记录 PR #2 已关闭未合并 | 确认 | 是 |
| `git diff --numstat` 为 `1 1` | 确认 | 是 |
| PR #47 合并提交 `2ec9a26` | 确认 | 是 |
| 「已核对 `:56` 与 `:135` 的整行内容哈希与基线 `952703b` 完全相同」 | 我的独立行级 md5 比对：:46/:56/:103/:135 全部 SAME | 是 |

### 5.4 无「未跑门禁写成已跑」

- 描述全文对 CI 的唯一提及是「不动代码/CI/其他文档」——**声明的是不作为，而非已通过**。
- 描述中**没有任何**「门禁已跑 / CI 已通过 / 检查全绿」类断言，也未把 §6 FAIL 描述为已解决。
- 描述中无任何越界的门禁结论（对比 RV-PR47 报告：其 N-3 曾指出任务书不在仓库内、追溯链问题；本 PR 未新增同类问题）。

---

## 6. 第 5 项：CI 现状记录 —— 通过（且与内容结论严格分开）

### 6.1 头 check-runs 现状（如实记录）

- 轮次：workflow run `41942108868`，`run_attempt=1`（无重跑），`event=pull_request`，`head_sha` 与评审头一致。
- job 数 7，**全部 completed/success**；**失败 job 0 个**；**skipped job 0 个**。
- step 级：失败 step 0 个；skipped step 1 个（`fuzz smoke (nightly)` 的 `Upload any crash artifacts`，条件性上传步骤，无崩溃时跳过，属正常）。
- 该头 SHA 下无其它 workflow（`total_count=1`）。
- legacy commit status 为空（`total_count=0`），无旧式 context 混淆。

### 6.2 内容结论与 CI 结论分开表述

- **内容结论**：本 PR 只改一个文档标题；§2–§5 的范围、事实、一致性、描述四项判定**全部基于 git/API 实测**，与 CI 绿灯或红灯**无因果关系**。
- **CI 结论**：当前头 SHA 上 7/7 成功（快照）。CI 绿灯**不构成**对内容正确性的证明，仅说明该提交未破坏构建/测试。
- 反向亦然：文档类改动本身不影响 CI 判定，二者互不替代。

### 6.3 与 `:56` 内 PR #2 历史 CI 陈述的区分（避免混淆）

`:56` 说明格记载的是 **PR #2 当时**的 CI 状态，与 PR #49 自身的 CI 状态是两个不同对象。我独立核实 PR #2 头 `74640b8189daa3452497efa6e0b59d952cefa919` 的 check-runs：**6 条，其中 `build / lint (stable)` = failure，其余 5 条 = skipped** —— 与 `:56`「CI `build / lint (stable)` 失败，其余 5 个 job skipped」的陈述**完全吻合**。该陈述在本次改动后依然准确，本 PR 无需也未去动它。

### 6.4 门禁重跑说明

以上 CI 结论为评审时点的**实测快照**。按任务书，门禁阶段由协调者以 `xc CI-exact` 重跑定性；本报告不以当前绿灯替代该门禁，也不预判其结果。

---

## 7. file:line 问题清单

### 7.1 阻塞项 —— **无（0 项）**

无任何需要作者修改才能合并的问题。

### 7.2 非阻塞项 —— 3 项（均不要求本 PR 处理）

| # | 位置 | 描述 | 判定 |
|---|---|---|---|
| NB-A | `docs/m4-resource-budget.md:37` | 该行仍写「`#44` 是本 PR（OPEN）」，而 PR #44 已合并（其合并提交 `b26a83f` 已在 main 上）。**此为 base `952703b` 既有的陈旧表述，本 PR 未改动该文件**（`git diff --name-only origin/main pr49 -- docs/m4-resource-budget.md` 为空），亦不属于本单授权范围。 | 非阻塞 / 本 PR 引入之外；建议另立单，不应计入 PR #49 |
| NB-B | `docs/m3-m4-closeout.md:56` | 说明格保留 PR #2 的历史 CI 陈述「CI `build / lint (stable)` 失败，其余 5 个 job skipped」。经独立 API 核实**该陈述准确**（PR #2 头 `74640b8` 实测 1 failure + 5 skipped），本 PR 未动此格，符合任务书「不得改表格任何一格」。仅提示后续阅读勿将其与 PR #49 自身 7/7 success 混淆（沿用 RV-PR47 报告 N-2 的提醒）。 | 非阻塞 / 无需修改 |
| NB-C | `rv-pr47-review-report.md:125`（RV-PR47 报告，仓库内位于 `trae/agent-rdFNZ8` 等评审分支，未进 main） | **编号标签不一致**：任务书称来源项为「NB-1」，来源报告 §3 实际标注为「**N-1**」（同节另有 N-2、N-3）。所指事项**完全同一**（`:52` 标题「仍 open 的 PR（不属已合并清单）」），仅标签不同，不影响本 PR 的合规判定。另：来源报告建议的候选表述为「未合并清单（含已关闭未合并）」，与任务书给出的两个候选不同，但作者所选表述同样满足来源报告的意图（标题不作状态断言），不构成偏差。 | 非阻塞 / 仅为追溯链标签问题；沿用 RV-PR47 报告 N-3 的既有问题（本任务书亦不在仓库内），不应计入 PR #49 |

### 7.3 已核验为「无问题」的位置（留档）

| 位置 | 核验结论 |
|---|---|
| `docs/m3-m4-closeout.md:52` | 改动行本身：标题中性、无状态断言、无与 `:56`/`:135` 冲突；`###` 层级与 §1 嵌套关系与 base 一致（未引入新层级错位）。 |
| `docs/m3-m4-closeout.md:56` | 逐字未动（md5 SAME）。 |
| `docs/m3-m4-closeout.md:135` | 逐字未动（md5 SAME），且与 GitHub API 的 PR #2 事实逐项吻合。 |
| `docs/m3-m4-closeout.md:46` / `:103` | 历史行逐字未动（md5 SAME）。 |
| `docs/m3-m4-closeout.md:141`–`:148` | §6 FAIL 结论及其依据逐字未动。 |
| `CHANGELOG.md:3` | 以「§1 末节」位置指代本节，改标题后仍成立；无锚点断链。 |

---

## 8. 结论

### **批准合并（Approve merge）**

理由：

1. **范围严守**：净 diff 1 文件 / +1 / -1，且经全文件级比对证明**全文仅第 52 行不同**；表格各格、`:135` 附注、历史行、§6 FAIL 结论、代码、CI、其他文档全部逐字未动；头树无新增文件与新增二进制；「仍 open」全仓零残留；未夹带 RV-PR48-NB1 / RV-PR40-N2 / RV-PR42-NB1，PR #2 与 PR #31 均未重开。
2. **NB-1 事实成立**：PR #47 确已合并、合并提交确为 `2ec9a26`（且在 main 上）；`:56` 确为 `closed_unmerged`；`:135` 确记录 PR #2 已关闭未合并且与 API 吻合；新标题为纯归属陈述，确不预设状态；落选理由成立、无夸大或偷换。
3. **语义张力已消除**：新标题与 `:56`、`:135` 均无语义冲突，且未把标题改动包装成 PR #2 状态变更或 M3 结论变更；§6 仍为 FAIL。
4. **描述合规**：含改动前后对照与选用理由，各依据与实测逐项一致，无「未跑门禁写成已跑」类越界声明。
5. **CI 现状如实**：头 `56944ad2…` check-runs 7/7 success、0 失败、0 skipped job（仅 1 个条件性 step 跳过）、`run_attempt=1`、无其它 workflow；内容结论与 CI 结论在报告中严格分开表述。门禁定性仍以协调者 `xc CI-exact` 重跑为准。

**阻塞项 0 条**，非阻塞项 3 条（NB-A / NB-B / NB-C，均为既存或他人范围事项，明确不计入 PR #49）。

建议合并方式：常规 merge commit 即可（本地模拟合并零冲突，合并结果树与 PR 头树完全相同）。

---

*本报告仅供评审，未合并、未修改任何分支、未新建 PR。*
