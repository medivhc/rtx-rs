# Fuzz regression corpus

This directory holds the **curated, committed** corpus for the four targets in
`fuzz/fuzz_targets/`. It exists so the defects found by fuzzing and fixed in
`936f701` ("fix(rtcp,stun): enforce length-consistent decode") stay fixed: each
seed below used to trip the corresponding fuzz target before the fix and must
pass now.

The seeds are hand-built minimal wire packets, not random files produced by a
long fuzzing campaign. Every one is derived from a defect listed in
[`docs/progress-report.md` §6](../../docs/progress-report.md).

| Target | Defect (progress-report §6) | Seed |
|---|---|---|
| `rtcp_compound` | 1. Goodbye `raw_len()` not 32-bit aligned | `rtcp_compound/rtcp_bye_empty_reason_padding.bin` |
| `rtcp_compound` | 2. Goodbye accepts a tail after the reason | `rtcp_compound/rtcp_bye_trailing_bytes.bin`, `rtcp_compound/rtcp_bye_three_octet_reason.bin` |
| `rtcp_compound` | 3. PLI fixed-size packet with an inflated `length` | `rtcp_compound/rtcp_pli_inflated_length.bin` |
| `rtcp_compound` | 3. RRR fixed-size packet with an inflated `length` | `rtcp_compound/rtcp_rrr_inflated_length.bin` |
| `rtcp_compound` | 4. REMB `length` contradicting `ssrc_count` | `rtcp_compound/rtcp_remb_ssrc_count_mismatch.bin` |
| `rtcp_compound` | 5. TWCC residual bytes beyond the delta region | `rtcp_compound/rtcp_twcc_extra_word.bin` |
| `stun_message` | 6. STUN `MessageType` reserved bits dropped | `stun_message/stun_reserved_type_bits.bin` |
| `crypto_aead` | none (§6 defects are all RTCP/STUN) | — |
| `rtp_header` | none (§6 defects are all RTCP/STUN) | — |

Per-target READMEs next to the seeds document the exact byte layout and the
pre-fix failure mode. `crypto_aead/` and `rtp_header/` contain no regression
seed because §6 records no defect for those targets; their READMEs say so
instead of inventing unrelated inputs.

## Replay (deterministic, no fuzzing)

```console
cd fuzz
cargo fuzz run rtcp_compound corpus/rtcp_compound -- -runs=0
cargo fuzz run stun_message  corpus/stun_message  -- -runs=0
```

`-runs=0` makes libFuzzer execute the corpus once and exit; it does not start a
fuzzing campaign. CI runs the same command for every target before the 20-second
smoke run, and the default corpus directory (`fuzz/corpus/<target>/`) means the
smoke run is seeded by these files as well.

Note: libFuzzer treats every regular file in a corpus directory as an input, so
the `README.md` files are also executed once during replay. They are ordinary
text and each target rejects or ignores them; they are documentation, not
regression vectors. Files created by a fuzzing run are covered by
`.gitignore` and are not committed.
