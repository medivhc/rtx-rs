# RV-PR50 独立评审报告 — rtx-rs PR #50

评审对象：PR #50 `RV-PR48-NB1: unify B5 status wording to 'written' in Chrome report`
分支：`docs/rv-pr48-nb1-written-wording`
评审模型：MiniMax-M3.1-Flash（独立会话，与作者会话 6aebdc2c5b81a4d7cefcada9 不同模型、不同会话）
评审日期：2026-11-05（Asia/Shanghai）
评审方式：独立 `git clone` 到独立目录 `/tmp/rev/rtx-rs`，用 git 与 GitHub API 一手实测，未采信协调者核验结论或作者自述。

---

## 一、结论

**批准合并**（Approve / merge）。

本单为纯文档用词统一（1 个词），改动范围最小且可逐字复核；NB-1 事实依据全部实测成立；改后文件内四处 `written` 用词完全一致；PR 描述含改动前后对照与统一依据且与实测逐字相符；头 check-runs 7/7 success。**无阻塞项**，**无要求修改项**。

非阻塞观察 2 条见第五节，均不影响合并。

---

## 二、评审基准信息（评审实测，非照抄）

| 项 | 实测值 | 来源 |
|---|---|---|
| 仓库 | `https://github.com/medivhc/rtx-rs` | 独立 `git clone` |
| 评审所对头 SHA | `760f0b9d277cb3cc862382fbb4c29b07a70e3d90` | `git rev-parse pr50`；PR API `head.sha` 一致 |
| base ref / base SHA | `main` / `952703b4112314696e363470e9799ddc9cb17bb6` | PR API `base.ref` / `base.sha` |
| merge-base | `952703b4112314696e363470e9799ddc9cb17bb6` | `git merge-base pr50 origin/main` |
| base 是否等于 main 头 | 是，`origin/main` = `952703b4112314696e363470e9799ddc9cb17bb6` | `git rev-parse origin/main` |
| mergeable / mergeable_state | `true` / `clean` | PR API `mergeable` / `mergeable_state` |
| merge_commit_sha（预演） | `f739ad8597f623026544e50be85270a7d450ee04` | PR API |
| PR 状态 | `open`，`merged=false`，`merged_at=null`，`draft=false` | PR API |
| PR 创建时间 | `2026-11-05T01:32:39Z`（= 09:32:39 CST） | PR API `created_at` |
| commit 数 | 1（`git rev-list --count 952703b..pr50` → 1） | git |
| 净 diff | 1 文件 +1/−1 | `git diff --numstat` |
| 远端分支 | `refs/heads/docs/rv-pr48-nb1-written-wording` = `760f0b9d...`，与 PR head 一致 | `git ls-remote` |
| 合并冲突预演 | `git merge-tree --write-tree origin/main pr50` → 无冲突 | git |

**与协调者核验的差异**：无实质差异。协调者给出的 merge-base、头 SHA、base SHA、commit 数、净 diff、mergeable 状态、check-runs 结果与本轮独立实测**逐项一致**。

### 头 check-runs（完整 SHA 查询，`total_count=7`）

| check-run | status | conclusion | 起止 |
|---|---|---|---|
| build / lint (stable) | completed | **success** | 01:32:46 → 01:33:28 |
| coverage gate | completed | **success** | 01:33:30 → 01:34:16 |
| crypto vectors (published) | completed | **success** | 01:33:30 → 01:33:42 |
| fuzz smoke (nightly) | completed | **success** | 01:33:30 → 01:36:03 |
| suite (stable) | completed | **success** | 01:33:30 → 01:34:00 |
| property tests (deep sweep) | completed | **success** | 01:33:31 → 01:33:59 |
| suite (msrv) | completed | **success** | 01:33:31 → 01:34:11 |

- 唯一 workflow run：`CI`（run #147，attempt 1，run id 41949235053），`conclusion=success`。
- 唯一 skipped 步骤：`fuzz smoke (nightly)` 的 `Upload any crash artifacts`（无崩溃产物时正常跳过），job 整体 success。
- 无失败步骤，无 cancelled/neutral/skipped 的 job。
- 说明：按任务书要求使用**完整 SHA** 查询；`commits/<short-sha>/check-runs` 短 SHA 会返回空结果，不能据此判断 CI 未跑。另注：`/commits/<sha>/status`（旧式 status API）返回 `state=pending, total_count=0`，这是因为该仓库只使用 check-runs、未使用旧式 commit status，**不构成失败信号**。

---

## 三、验收逐项表

| # | 验收项 | 判定 | 证据 |
|---|---|---|---|
| 1 | **范围**：diff 仅含任务书允许的 :47 一词；未动 :12/:33/:243、:79、该行其余文字、其他文件、代码、CI；未顺带处理无关缺口；头树无新增二进制文件 | **通过** | `git diff --numstat 952703b..pr50` → `1  1  interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md`；`git diff --raw` 仅 1 条 `M` 记录，无 A/D；`git diff --word-diff` 显示改动仅 `-generated` → `+written`；`diff -U0` 整文件仅 `@@ -47 +47 @@` 一行；文件字节数 15799 → 15797（−2 = “generated”(9) − “written”(7)），行数 293 → 293 不变；`git ls-tree -r` base/head 均 266 条目，无新增 blob；`git diff --binary` 中 `GIT binary patch` 计数 0；文件模式 100644 → 100644 不变。:12/:33/:243 在 head 中仍为 `written`（`git show pr50:<file> \| grep -n written` → 12/33/47/243）；:79 `generated at run time by ../run-chrome.sh with openssl.` 逐字未动。无关缺口核对：RV-PR47-NB1 属并行 PR #49（分支 `docs/rv-pr47-nb1-neutral-heading`，改动 `docs/m3-m4-closeout.md`，与本 PR 无交集）；RV-PR40-N2 / RV-PR42-NB1 / PR #2 语料 / GAP 状态均未出现在本 PR diff 中（仓库内 `git grep RV-PR48\|RV-PR47\|RV-PR40\|RV-PR42` 命中 0，PR diff 也不含 `docs/m3-m4-gates.md`） |
| 2 | **NB-1 事实准确性**：PR #48 已合并且合并提交确为 f6028ca；:12/:33/:243 确均为 written；:47 改前确为唯一 generated 离群词；:79 排除理由成立、无偷换 | **通过** | PR #48 API：`state=closed, merged=true, merged_at=2026-11-04T23:09:40Z, merge_commit_sha=f6028ca1d98c7ac70534642c5edc9e079d30226b`；`git log -1 f6028ca` → `Merge PR #48: RV-PR45-N3 sync B0-02 status narrative`；`git rev-list --parents -n1 f6028ca` 显示为双亲 merge commit；`git merge-base --is-ancestor f6028ca origin/main` → 已在 main 上。base 版文件 `grep -n "generated"` → 仅 47 与 79 两处；head 版 → 仅 79；:12/:33/:243 在 base 版即已是 `written`（由 PR #48 引入，见 `git diff 46a03cb^..46a03cb -- <file>`：PR #48 同时写入 :12/:33/:243 的 `written` 与 :47 的 `generated`，故 :47 确为其自身引入的唯一离群词）。:79 排除理由成立：head 中 :76 段落标题为 `## Certificate handling`，:79 语义是“证书在运行时由 openssl 生成”，与“报告写于何时”无关，属不同语境，排除不构成偷换；PR 描述亦如实写明该理由 |
| 3 | **一致性**：改后 :47 与 :12/:33/:243 用词一致；该行 GAP、PR #43、33268ff、gates §5 :456 逐字未动；未把用词统一写成 GAP 状态/实测结论/M3 结论的变更 | **通过** | head 版 `git grep -n "when this report was" pr50` → 恰好 4 处（12/33/47/243），全部为 `was written`；`:47` 新行与 `:12`/`:33`/`:243` 用词同为 `written`（其中 :12/:33/:243 另有反引号包裹 `OPEN` 的原有格式差异，属既有格式、非本 PR 引入）。逐字比对用 `difflib.SequenceMatcher` 对 base/head 的 :47 行做 opcode 分析：唯一非 equal 区间为 `base[110:119]='generated'` → `head[110:117]='written'`；断言 token `GAP-M3-B0-02` / `PR #43` / `33268ff` / `gates §5 :456` / `| B5 | GAP closed |` 全部保留为 True。语义未被偷换：GAP 状态单元格仍为 `GAP closed`（非 OPEN），B0/B1/B2 结论、实测数值、SHA-256、版本日期均未改（整文件仅 1 行变化已证），M3 结论段落（:10–:16）未被触碰 |
| 4 | **PR 描述与依据**：描述含改动前后对照与统一依据；各状态/依据（头、基线、行号、合并提交）与实测一致；未把未跑的门禁写成已跑 | **通过** | PR body（`gh api .../pulls/50 --jq .body`）含 `## Before / after` 两段代码块与 `## Rationale for "written"`（列出 :12/:33/:243 三处依据并说明 :79 为不同语境）。逐字核对：body 的 Before 行与 base 实际 :47 **完全相等**（Python 字符串相等断言 → True），After 行与 head 实际 :47 **完全相等**（→ True）。body 中 `f6028ca` → 实测 merge commit 前缀一致；`952703b4112314696e363470e9799ddc9cb17bb6` → 与实测 base SHA 完全一致；行号 :12/:33/:47/:79/:243 → 与 head 实际行号全部对应（:12 在 “What this does not prove” 段、:33 在 “Registered GAP” 段、:243 在 `## B5 GAP table` 表内、:79 在 `## Certificate handling` 段）。body 另列 `git diff --numstat` 结果，实测完全相同。**未发现门禁夸大**：body 全文无 “CI passed / check-runs green / 门禁已跑” 类断言，仅在 Verification 段写 “No changes to `docs/m3-m4-gates.md`, closeout docs, code, or CI”，即描述改动面而非声称 CI 状态 |
| 5 | **CI 现状记录**：头 check-runs 现状如实记录；内容结论与 CI 结论分开表述；不把 CI 失败当内容通过，也不把内容问题与 CI 失败混谈 | **通过** | 本报告第一、二节已将“内容结论”（第一节）与“CI 现状”（第二节表格）分列，互不替代。头 check-runs 完整 SHA 查询 `total_count=7`，7/7 success，1 个 skipped 步骤（`Upload any crash artifacts`，无崩溃产物时正常），无失败步骤。本单不存在“CI 失败但内容通过”或反之的混淆情形；也未将 CI 结论用于替代内容判断。附注：PR #50 上 issue 评论 0 条、reviews 0 条，PR body 未对 CI 结果做任何主张，因此不存在“把未跑门禁写成已跑”的风险面 |

---

## 四、file:line 问题清单

### 阻塞项（必须修复才能合并）

**无。**

### 非阻塞项（不影响合并，建议记录）

| 编号 | 位置 | 观察 | 判定 |
|---|---|---|---|
| NB-a | `interop/m3/chrome-rtx/2026-11-02-chrome-155.0.8059.39/report.md:12`、`:33`、`:243` | 三处写作 `` `OPEN` when this report was written ``（反引号包裹 `OPEN`），而 :47 为裸 `OPEN`（无反引号）。该格式差异由 PR #48 引入并已存在于 base，本 PR 未触及，超出 RV-PR48-NB1 授权范围（该单只授权改 :47 一词），故**不应**在本单处理。如需统一反引号格式，应另开单据处理 | 非阻塞，且本单不应处理 |
| NB-b | `interop/m3/chrome-rtx/2026-10-29-chrome-155.0.8059.39/report.md:93`、`2026-10-29-chrome-155.0.8059.39-baseline/report.md:74` | 两份同族报告各自保留 `generated at run time by \`run-chrome.sh\`` 表述，与本文件 :79 属同一“证书运行时生成”语境，均不属于“报告写于何时”的语义域，因此**不构成** :47 原本的离群问题 | 非阻塞，无需处理；本 PR 未触碰这两处属正确取舍 |

（NB-a、NB-b 均为“确认无需处理”的观察记录，不构成修改要求。）

---

## 五、独立核验过程与关键实测记录

1. **独立克隆**：`git clone https://github.com/medivhc/rtx-rs.git` → `/tmp/rev/rtx-rs`（与工作区副本 `/workspace` 分离，避免既有工作区状态污染判断）。
2. **取 PR 引用**：`git fetch origin pull/50/head:pr50 pull/50/merge:pr50-merge`；两引用均可取。
3. **merge-base**：`git merge-base pr50 origin/main` = `952703b4112314696e363470e9799ddc9cb17bb6`，且等于 `origin/main` 当前头 → PR 基于最新 main，无落后、无分叉。
4. **diff 逐层复核**：`--stat` / `--numstat` / `--name-status` / `--raw` / `--word-diff=porcelain` / `--binary` 全部执行，结论一致：唯一文件唯一行唯一词。
5. **整文件字节级复核**：`git show <sha>:<file>` 导出 base/head 两版 → `diff -U0`（1 hunk）、`wc -c`（−2 字节）、`wc -l`（不变）、`cmp -l`（差异自第 2650 字节起呈位移式对齐，符合单词长度差 2 字节的预期）。
6. **行级 opcode**：`difflib.SequenceMatcher` 精确定位唯一替换区间，并逐 token 断言其余标识符（`GAP-M3-B0-02`/`PR #43`/`33268ff`/`gates §5 :456`）保留。
7. **NB-1 溯源**：调取 PR #48 合并提交 `f6028ca` 及其 head `46a03cb` 的原始 diff，确认 `:47` 的 `generated` 与 `:12/:33/:243` 的 `written` 同由 PR #48 一次写入 → `:47` 确为 PR #48 自引入的唯一离群词，NB-1 事实成立。
8. **时序核对**：报告首版提交 `b5e9b30`（2026-11-02 16:06 +0800）→ PR #29 重跑证据合并 `93c0030`（2026-11-02）→ PR #43 关闭 GAP `33268ff`（2026-11-04）→ PR #48 叙述同步（2026-11-04/05）→ 本 PR #50 用词统一（2026-11-05）。`:47` 所述 “was OPEN … when this report was written” 与 “now closed by PR #43” 的时序语义成立，改词未破坏事实链。
9. **门禁引用核对**：head 版 `docs/m3-m4-gates.md:456` 确为 `GAP-M3-B0-02` 行且状态列为 `已关闭` → `:47` 行内 “gates §5 :456” 引用仍准确（该行为 base 继承，本 PR 未改）。
10. **交叉引用**：`33268ff` → `git log -1` 确认为 `Merge PR #43: docs(gates): mark GAP-M3-B0-02 closed with PR #29 re-run evidence`，PR #43 API 亦返回同一 `merge_commit_sha`，且 `merged=true`。
11. **无关缺口排查**：仓库内 `git grep "RV-PR48|NB-1|RV-PR47|RV-PR40|RV-PR42"` 命中 0，PR diff 不含 `docs/m3-m4-gates.md`；RV-PR47-NB1 由并行 PR #49 承担（改动 `docs/m3-m4-closeout.md`），两 PR 无文件交集 → PR #50 未越界处理无关缺口。
12. **仓库级用词扫描**：对全部 `report.md`（6 份）grep `was OPEN|was generated|was written`，head 版仅本文件 12/33/47/243 四处且全为 `written`，无其他 `was generated` 残留 → 本单目标达成且无新离群词。

---

## 六、评审结论与建议

**结论：批准合并。**

- 5 项验收全部通过，0 阻塞项，0 要求修改项。
- 改动为纯文档用词统一，语义事实链（报告写于 GAP 关闭前、GAP 由 PR #43 关闭、M3 未验收）完整保留。
- 头 check-runs 7/7 success（完整 SHA 实测），mergeable true / clean，无冲突预演通过。
- 非阻塞观察 2 条（NB-a / NB-b）均为“确认本单无需处理”，供协调者归档留痕，不构成后续阻塞。

后续建议（非本单范围）：若需统一 :12/:33/:243 的反引号包裹格式，应另开独立单据，且不应并入本次合并。

---

*本报告仅为独立评审意见。未执行合并、未修改分支、未新建 PR。*
