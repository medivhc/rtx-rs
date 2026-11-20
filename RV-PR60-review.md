# RV-PR60 独立评审报告

- 仓库：https://github.com/medivhc/rtx-rs
- 评审对象：PR #60（分支 `docs/rv-nb-bundle-wording`，头 `977cc5699ca23d4ddd1c966e97a147fb1650d0ef`）
- 基线：`main` @ `b3522c7d7847e52b8fe810f90b99590ac3888fa7`（PR #59 合并后头）
- 评审范围：`docs/m4-resource-budget.md`（5 处）+ `crates/rtx-quic/tests/facade_metrics.rs`（1 处），共 2 文件 +8/-6
- 评审时间：2026-11-21（Asia/Shanghai）
- 评审方式：独立复核（fresh clone + `git fetch --unshallow`、GitHub API 经沙箱出口、实跑 `cargo fmt --check` 与 `cargo test`）；不合并、不改分支、不新建 PR

---

## 1. 结论

**批准合并。**

PR #60 的 6 处改动全部与任务书 `tasks/RV-NB-bundle-doc-wording.md` 的六项闭环意见逐项一致，无越权改动；§1.2 快照刷新与 §10 版本列口径的事实表述经独立实测全部属实；NB2 的 6 行超 80 列保留理由经 rustfmt 实测复核成立（手工换行确被 rustfmt 驳回）。无阻塞项。

---

## 2. 验收逐项表

| # | 验收项 | 结论 | 证据 |
|---|---|---|---|
| 1 | diff 仅 2 文件 +8/-6；6 处改动逐项与任务书一致；NB1 零改动；NB2 六行原样保留；无范围外改动 | **PASS** | `git diff --shortstat origin/main...origin/pr60` → `2 files changed, 8 insertions(+), 6 deletions(-)`；`git diff --numstat` → `2/2 crates/rtx-quic/tests/facade_metrics.rs`、`6/4 docs/m4-resource-budget.md`；GitHub API `GET /pulls/60` → `changed_files=2, additions=8, deletions=6, commits=1, state=open, mergeable=true, mergeable_state=clean, head.sha=977cc56…, base.sha=b3522c7…`；budget 5 hunk（`@@ -3,7` → :6、`@@ -27,7` → :30、`@@ -38,7` → :41、`@@ -307,7` → :310、`@@ -391,6` → §10 新增说明）+ facade 1 hunk（`@@ -142,8` → :145–:146）；NB1 零改动：`diff <(git show origin/main:docs/m4-resource-budget.md \| sed -n '35p') <(git show origin/pr60:… \| sed -n '35p')` → 无差异（逐字一致）；NB2 六行：base/head 的 :10/:12/:54/:55/:173/:175 逐行 `IDENTICAL`，列宽 88/87/97/86/88/87 与所称完全一致；`git diff --summary` 为空（无模式变更/重命名），`git diff --numstat` 无二进制；`git diff --name-only` 仅上述 2 个文件 |
| 2 | NB3/NB4 措辞改动准确：主语明确、行号已删，块内每行 ≤80 列，:34 断言未动 | **PASS** | head `:145` = `// This mechanism is not an assertion in this test; `min_rtt_micros` is`，`:146` = `// asserted in `m3_q8_metrics_after_handshake`, not here.`；`git grep -n '(line 34)' origin/pr60` → 无命中；`git grep -n 'It is not an assertion' origin/pr60` → 无命中（base 命中 :145）且 `This mechanism is not an assertion` 命中 head :145；块内逐行列宽 `:142–:146` = 75/71/77/75/61，全部 ≤80；`:34` base/head 逐字相同（`    assert!(metrics.min_rtt_micros > 0);`）；:142/:143/:144 三行未变，diff 仅动 :145/:146 两行 |
| 3 | §1.2 快照刷新属实：:6/:30/:41/:310 四处与 b3522c7 实测一致；历史快照、§8.1 命令、:379 未动；`52e4ac9..b3522c7` 四文件注释-only 断言属实 | **PASS** | :6=`main @ b3522c7`（2026-11-13 PR #59 合并后头，API `merged_at=2026-11-13T01:35:19Z` → CST 2026-11-13 ✓）；:30=`b3522c7d7847e52b8fe810f90b99590ac3888fa7`（PR #59 合并后），与 `git ls-remote origin refs/heads/main` 实测一致；:41 新增 `52e4ac9..b3522c7` 四文件句，:310 记 `#53`–`#59`；四项复核项在 b3522c7 实测：预算文档存在（`git cat-file -e b3522c7:docs/m4-resource-budget.md` exit 0）、固件目录空（`git ls-tree b3522c7 -- firmware` 无输出）、`docs/m4-quic-decision.md`/`docs/m4-memory-report.md` 均不存在（exit 128）、CI 6 job 无 `embedded-build`（YAML `jobs:` 解析 = test/suite/coverage/crypto-vectors/proptest/fuzz）、ELF/map 0 个、PR refs 最大 #59 且 `#43`–`#59` 逐个 `merge-base --is-ancestor` 全为 ANCESTOR、选型结论仍 `未选定`（A/B T 2/6、V 6/4，C `M4-V9` 否决，`docs/m4-target-selection.md` :242–:244）；历史快照 :32–:38 与 :35 逐字未动（diff 无差异）、§8.1 命令 :322–:329 与 :379 逐字未动；四文件断言：`git diff --name-only 52e4ac9 b3522c7` 恰为 4 个文件（facade_metrics.rs 7 行、docs/m3-m4-gates.md 2 行、docs/m4-resource-budget.md 42 行、docs/m4-target-selection.md 18 行），`-- .github Cargo.toml Cargo.lock` 与 `-- 'crates/*/src'` 均为空；facade 在该区间的 diff 逐行过滤后无任何非 `//` 行 |
| 4 | §10 版本列口径说明准确：S5–S17 读于 ea870b6、S18 例外与 job 集合一致性属实；S18 行本身未改 | **PASS** | head §10 表版本列逐行提取：S5–S17 全为 `ea870b6`、S18 为 `52e4ac9`、S1–S4 为手册 Rev、S19 为 rustc 输出；新增说明位于 head :394（`## 10. 来源清单` 与来源表之间）；job 集合实测：`ea870b6`/`52e4ac9`/`b3522c7` 三点的 `jobs:` 解析结果完全相同（6 个，test/suite/coverage/crypto-vectors/proptest/fuzz，`embedded-build` 存在=False）；S18 行 base :413 与 head :415 逐字 `IDENTICAL`；S5–S17 十三行 base/head 逐行无差异 |
| 5 | NB2 保留理由属实：6 行确为代码行且列宽与所称一致，fmt --check 在 PR 头上通过，未加 rustfmt::skip | **PASS** | head 中 >80 列的行恰为 6 行且均为 `Endpoint::new(...)` 代码行（非注释）：`:10`(88)、`:12`(87)、`:54`(97)、`:55`(86)、`:173`(88)、`:175`(87)；在 detached worktree（PR 头）实跑 `cargo fmt --check` → EXIT=0（输出 0 行）；CI 等价命令 `cargo fmt --all -- --check` → EXIT=0；`rustfmt --print-config default` → `max_width = 100`（仓库无 rustfmt.toml/Cargo.toml rustfmt 配置）；独立复现“手工换行被驳回”：把 :10/:12/:54/:55 改写为拆参/断行形式后 `cargo fmt --all -- --check` → EXIT=1，rustfmt 明确要求拼回原 88/87/97/86 列单行形式；`git grep rustfmt origin/pr60` 在 diff 与 facade_metrics.rs 中均无命中（未加 `rustfmt::skip`） |
| 6 | PR 描述的六项处置与 git 一致；头 check-runs 7/7 success 与 mergeable clean 经 API 核实并记录；PR #60 open，分支/头与任务书一致 | **PASS** | PR body 六项逐条与 git 对齐（基线 b3522c7、NB1 零改动、NB2 保留、NB3 主语、NB4 去行号、§1.2 刷新表全部实测吻合，其中 body 自述的 `git diff --stat ea870b6 b3522c7 -- crates Cargo.toml Cargo.lock .github` = `crates/rtx-quic/tests/facade_metrics.rs | 7 +++++--`（1 file, 5+/2-）经复核逐字一致）；API `GET /pulls/60` → `state=open, merged=false, mergeable=true, mergeable_state=clean, draft=false, head.ref=docs/rv-nb-bundle-wording, head.sha=977cc5699ca23d4ddd1c966e97a147fb1650d0ef, base.ref=main, base.sha=b3522c7…, created_at=2026-11-20T19:05:26Z, user=medivhc`；`GET /commits/977cc56…/check-runs` → total_count=7，7 项全 `conclusion=success`（对应 workflow run 44798882003）；`GET /commits/b3522c7…/check-runs` → total_count=7，7 项全 success（对应 run 43346033735）；PR body 验证项复现：`cargo fmt --check` EXIT=0、`cargo test -p rtx-quic --test facade_metrics` → `3 passed; 0 failed; 0 ignored`、diff → `2 files changed, 8 insertions(+), 6 deletions(-)`；`git merge-base origin/pr60 origin/main` = `b3522c7…` = main 头；`git ls-remote origin refs/pull/60/head` = `977cc56…` |

---

## 3. 问题清单

### 阻塞项

无。

### 非阻塞（仅记录，不要求本 PR 改动）

| # | 位置 | 描述 |
|---|---|---|
| N1 | `docs/m4-resource-budget.md:37` | §1.2 「PR refs」行的复核命令是实时 `git ls-remote origin 'refs/pull/4[0-9]/head' 'refs/pull/5[0-9]/head'`，而结果列记的是 52e4ac9 时点的「最大为 `#52`」；在 b3522c7 上重跑同一条命令会得到最大 #59。该行按任务书定位为历史快照行（逐字未动），且 §1.2 头（:30）、说明（:41）与 §7（:310）已承担“当前主线头 = b3522c7”的陈述，故不构成阻塞；建议后续快照刷新单统一处理。 |
| N2 | `docs/m4-resource-budget.md:41` | 新文“`52e4ac9..b3522c7` 只改 … 与 `crates/rtx-quic/tests/facade_metrics.rs` 的注释”中“的注释”对三个 markdown 文件属用词不精确：这三处的实际改动是文档措辞/反引号排版（GAP 表 `OPEN` → `` `OPEN` ``、`docs/m3-m4-gates.md` GAP-M3-B0-02 状态行等），并非字面“注释”；承载结论的实质断言（四文件清单、`crates/` 库代码 0 改动、CI 与 Cargo.toml/Cargo.lock 0 改动、§2.2 对象级测量仍有效）经实测全部属实。 |
| N3 | `docs/m4-resource-budget.md:310` | 括注“`#53`–`#59`（§1.2 快照与措辞刷新）”为概括表述；其中 #59 的实际改动位于 `crates/rtx-quic/tests/facade_metrics.rs` 的注释重排（PR #40-N2 措辞），并非 §1.2 快照本身，#54–#58 则确为预算/门禁文档措辞刷新。 |

---

## 4. 附录：核实方法与关键输出

### A. 环境与取证

- 出网：`HTTPS_PROXY=http://127.0.0.1:18080`，`git`/`curl` 均经该出口；GitHub API 需鉴权，使用沙箱内既有 credential（`/run/shared/git/credentials`，40 字符 token）以 `curl -u x-access-token:<token>` 访问 `api.github.com`（未登录 `gh`，未修改任何远端状态）。
- 取证仓库：`/workspace`（既有克隆，`origin=medivhc/rtx-rs`）。首轮为浅克隆（`.git/shallow` 仅含 b3522c7），导致 `merge-base --is-ancestor` 对多数 PR 头误报 NOT-ancestor；`git fetch --unshallow` 后历史完整（`git rev-list --count b3522c7` = 168），ancestry 结论全部可复算。
- 工作区：未 checkout 任何分支、未改任何分支；PR 头通过 `git worktree add --detach /tmp/rtx-pr60 origin/pr60` 取得，验证结束后已 `git worktree remove --force`；`git ls-remote` 复核 `refs/heads/main` 仍为 `b3522c7…`、`refs/heads/docs/rv-nb-bundle-wording` 仍为 `977cc56…`。
- 工具链：rustc/cargo 1.92.0、rustfmt 1.8.0-stable；workspace `edition = "2024"`，仓库无 `rustfmt.toml`/`.rustfmt.toml`，Cargo.toml 无 rustfmt 配置。

### B. 关键命令与输出摘要

```
$ git ls-remote origin refs/heads/main refs/heads/docs/rv-nb-bundle-wording refs/pull/60/head
b3522c7d7847e52b8fe810f90b99590ac3888fa7  refs/heads/main
977cc5699ca23d4ddd1c966e97a147fb1650d0ef  refs/heads/docs/rv-nb-bundle-wording
977cc5699ca23d4ddd1c966e97a147fb1650d0ef  refs/pull/60/head

$ git merge-base origin/pr60 origin/main ; git rev-parse origin/main
b3522c7d7847e52b8fe810f90b99590ac3888fa7
b3522c7d7847e52b8fe810f90b99590ac3888fa7

$ git rev-list --count origin/main..origin/pr60
1

$ git diff --shortstat origin/main...origin/pr60
2 files changed, 8 insertions(+), 6 deletions(-)

$ git diff --numstat origin/main...origin/pr60
2       2       crates/rtx-quic/tests/facade_metrics.rs
6       4       docs/m4-resource-budget.md

$ git diff origin/main...origin/pr60 -- docs/m4-resource-budget.md | grep '^@@'
@@ -3,7 +3,7 @@      (:6   基线行)
@@ -27,7 +27,7 @@    (:30  主线头行)
@@ -38,7 +38,7 @@    (:41  §1.2 说明)
@@ -307,7 +307,7 @@  (:310 PR 引用现状)
@@ -391,6 +391,8 @@  (§10 新增版本列口径说明 → head :394)

$ git diff origin/main...origin/pr60 -- crates/rtx-quic/tests/facade_metrics.rs | grep '^@@'
@@ -142,8 +142,8 @@  (:145 主语改写、:146 去 (line 34))
```

```
# NB1 零改动（:35 逐字一致）
$ diff <(git show origin/main:docs/m4-resource-budget.md|sed -n '35p') \
       <(git show origin/pr60:docs/m4-resource-budget.md|sed -n '35p')
(无输出)
… 只有 `test`、`suite`、`coverage`、`crypto-vectors`、`proptest`、`fuzz`；无 `embedded-build`。注：该 grep 模式另匹配 …
（结论句止于「无 `embedded-build`。」，「注：」另起一句；引用前缀与正文逐字一致）

# NB2 六行（head >80 列的全部行 = 6 行，均为代码行）
$ git show origin/pr60:crates/rtx-quic/tests/facade_metrics.rs | awk 'length($0)>80{print NR"|"length($0)"|"$0}'
10|88|    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
12|87|    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
54|97|        Endpoint::new(server_config(&pki, &[ALPN], transport.clone())).expect("server endpoint");
55|86|    let client = Endpoint::new(client_config(&pki, &[ALPN]).with_transport(transport))
173|88|    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
175|87|    let client = Endpoint::new(client_config(&pki, &[ALPN])).expect("client endpoint");
（以上 6 行 base/head 逐行 IDENTICAL）

# NB2 rustfmt 驳回复现（在副本上改写为拆参断行后）
$ cargo fmt --all -- --check
EXIT=1
Diff in crates/rtx-quic/tests/facade_metrics.rs:7:
-    let server = Endpoint::new(
-        server_config(&pki, &[ALPN], TransportConfig::default()),
-    )
-    .expect("server endpoint");
+    let server = Endpoint::new(server_config(&pki, &[ALPN], TransportConfig::default()))
+        .expect("server endpoint");
（另 2 处同类 diff；rustfmt 要求全部拼回原长行）

$ rustfmt --print-config default | grep -E '^(max_width|fn_call_width)'
max_width = 100
fn_call_width = 60

$ cd /tmp/rtx-pr60 && cargo fmt --check ; echo $?      # PR 头原样
0
$ cargo fmt --all -- --check ; echo $?                # CI 等价命令
0
$ cargo test -p rtx-quic --test facade_metrics
running 3 tests
test m3_q8_metrics_after_handshake ... ok
test m3_q8_metrics_reflect_loss_and_rtt ... ok
test m3_q8_snapshot_allocations ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

```
# §1.2 快照事实（b3522c7 实测）
$ git cat-file -e b3522c7:docs/m4-resource-budget.md        → EXISTS (exit 0)
$ git ls-tree b3522c7 -- firmware                            → 空输出
$ git cat-file -e b3522c7:docs/m4-quic-decision.md           → NOT EXIST (exit 128)
$ git cat-file -e b3522c7:docs/m4-memory-report.md            → NOT EXIST (exit 128)
$ git ls-tree -r --name-only b3522c7 -- '*.elf' '*.map'      → 无输出
$ git show b3522c7:.github/workflows/ci.yml | grep -n '^  [a-z-]*:'
4:  push:      10: group: …  11: cancel-in-progress: …     (非 job 键)
20: test:  74: suite:  112: coverage:  152: crypto-vectors:  184: proptest:  207: fuzz:
YAML jobs 解析（ea870b6 / 52e4ac9 / b3522c7 三点一致）：
  [('test',20),('suite',74),('coverage',112),('crypto-vectors',152),('proptest',184),('fuzz',207)]  count=6  embedded-build=False

$ git merge-base --is-ancestor <PR#n head sha> b3522c7   # n = 43..59，逐个
#43…#59 全部 ANCESTOR ✓（首轮浅克隆误报，--unshallow 后复算全部为真）

$ git show b3522c7:docs/m4-target-selection.md | sed -n '242,244p'
| A STM32H723ZG / NUCLEO-H723ZG | 2 / 6 / 0 | 6 / 4 / 0 | 未完成核实，保留候选；不选中 |
| B STM32F767ZI / NUCLEO-F767ZI | 2 / 6 / 0 | 6 / 4 / 0 | 未完成核实，保留候选；不选中 |
| C MIMXRT1062DVL6A / MIMXRT1060-EVK | 2 / 6 / 0 | 5 / 4 / 1 | `M4-V9` 否决，落选 |

# 52e4ac9..b3522c7 范围
$ git diff --name-only 52e4ac9 b3522c7
crates/rtx-quic/tests/facade_metrics.rs
docs/m3-m4-gates.md
docs/m4-resource-budget.md
docs/m4-target-selection.md
$ git diff --name-only 52e4ac9 b3522c7 -- .github Cargo.toml Cargo.lock   → 空
$ git diff --name-only 52e4ac9 b3522c7 -- 'crates/*/src'                  → 空
$ git diff 52e4ac9 b3522c7 -- crates/rtx-quic/tests/facade_metrics.rs | grep '^[+-]' | grep -v '^[+-]\s*//'
（无非注释行 → 该区间 facade 改动为纯注释重排）

# §10 版本列（head）
S5…S17 → `ea870b6`；S18 → `52e4ac9`；S18 行 base:413 与 head:415 逐字 IDENTICAL
```

```
# GitHub API（沙箱出口，token 鉴权）
GET /repos/medivhc/rtx-rs/pulls/60
  state=open  merged=false  draft=false  mergeable=true  mergeable_state=clean  rebaseable=true
  commits=1  changed_files=2  additions=8  deletions=6
  head.ref=docs/rv-nb-bundle-wording  head.sha=977cc5699ca23d4ddd1c966e97a147fb1650d0ef
  base.ref=main  base.sha=b3522c7d7847e52b8fe810f90b99590ac3888fa7
  created_at=2026-11-20T19:05:26Z  user=medivhc
GET /pulls/60/files
  crates/rtx-quic/tests/facade_metrics.rs  modified  +2/-2
  docs/m4-resource-budget.md               modified  +6/-4
GET /commits/977cc56…/check-runs   total_count=7，7/7 conclusion=success
GET /commits/b3522c7…/check-runs   total_count=7，7/7 conclusion=success
GET /actions/runs/44798882003      CI  head_sha=977cc56  conclusion=success
GET /actions/runs/43346033735      CI  head_sha=b3522c7  head_branch=main  conclusion=success
GET /pulls/{43..59}                 全部 state=closed, merged=true, merged_at 2026-11-04 ~ 2026-11-13
```

### C. 复核过程中的一处工具事故（已复原，不影响结论）

在 `/tmp/rtx-pr60` 临时 worktree 中执行 `rustfmt --print-config default <file>` 时，rustfmt 将打印配置误当作输入写回了 `crates/rtx-quic/tests/facade_metrics.rs`（工作树出现 `M`）。随即以 `git checkout --` 复原，并用 blob 哈希核对：`git hash-object` = `e9d87562c75c44c18b9157eedc4ad81517145c30` = `git rev-parse origin/pr60:crates/rtx-quic/tests/facade_metrics.rs`，`git status` 干净；此后所有 fmt/测试结果均在复原后的 PR 头上重跑取得。该事故只发生在本地临时 worktree，未触及任何远端分支或 PR。

---

**评审范围声明**：本报告只针对 PR #60 的 2 文件 6 处改动；未纳入 RV-PR59-NB1、RV-PR58-NB2 或任何其他跟进项、基准/B3/B4 及其他任务；未合并、未改分支、未新建 PR。
