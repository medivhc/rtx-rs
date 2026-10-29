# Formal M3-P results live here, one JSON file per scenario.

`benchmarks/m3/run.sh` (formal mode) writes `<scenario>.json` into this
directory plus `run.log` and, when `perf` can count cycles,
`perf-cycles.tsv`. The files are produced on the coordinator's `xc` host and
committed after the harness PR is merged.

Rules:

- `--smoke` output is never written here; smoke defaults to a temporary
  directory and is PR evidence only.
- Every JSON carries the ten `M3-PM3` metadata fields; a file without a
  resolved `commit` is invalid and must not be committed.
- Missing dimension values stay `null` with a `reason`; they are never filled
  with `0` or estimates.
- `docs/m3-benchmarks.md` is the report that summarizes these files. It is a
  skeleton until the first baseline exists, and it may not claim “no
  regression” without that baseline.
