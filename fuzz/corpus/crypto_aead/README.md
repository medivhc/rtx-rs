# `crypto_aead` corpus

`docs/progress-report.md` §6 records no defect for the `rtx-crypto` AEAD
pipeline, so there is no historical crash input to pin here. This directory is
kept so the corpus layout covers all four targets; the target itself already
checks no-panic, untouched-on-failure and round-trip fidelity on arbitrary
input.

Do not add unrelated synthetic seeds here: a corpus entry is only worth
committing when it reproduces a concrete past failure.
