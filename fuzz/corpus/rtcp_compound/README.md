# `rtcp_compound` regression corpus

`fuzz_targets/rtcp_compound.rs` asserts that a decoded sub-packet re-encodes to
exactly the number of bytes `decode` consumed, and that a compound packet tiles
its input exactly. Every seed below failed the target before `936f701` and
passes after it (either by decoding correctly or by being rejected early).

## `rtcp_bye_empty_reason_padding.bin` — §6 defect 1 (Goodbye alignment)

`80 cb 00 01 00 00 00 00` — BYE, SC=0, length 1 (8 bytes), reason length 0, then
three null octets (RFC 3550 §6.4.4 alignment).

Pre-fix: `raw_len()` = 5, not rounded up, so `encoded_len()` = 5 while decode
consumed 8 and the header claimed 4 bytes; `written == consumed` failed (5 vs 8).
Post-fix: `aligned_len()` = 8; decode accepts and re-encoding is byte-identical.

## `rtcp_bye_trailing_bytes.bin` — §6 defect 2 (Goodbye trailing bytes)

`81 cb 00 03 90 2f 9e 2e 00 de ad be ef 00 00 00` — BYE, SC=1, length 3
(16 bytes announced), one SSRC, reason length 0, then four bytes after the
reason. A BYE ends after the reason and its padding, so the model is at most
4 + 4 + 1 = 9 raw bytes (12 aligned).

Pre-fix: the tail was ignored and `consumed` = 16 while `encoded_len()` = 9; the
target failed (9 vs 16). Post-fix: 16 != `aligned_len()` 12 → `InvalidValue`.

## `rtcp_bye_three_octet_reason.bin` — §6 defect 2 (three-octet reason shape)

`80 cb 00 02 03 61 62 63 de ad be ef` — BYE, SC=0, length 2 (12 bytes
announced), reason length 3 + `abc`, then one trailing 32-bit word. The reason
and its length octet occupy 4 bytes, so the model is 8 bytes and the trailing
word is unrepresentable.

Pre-fix: `consumed` = 12, `encoded_len()` = 8, target failed (8 vs 12).
Post-fix: 12 != `aligned_len()` 8 → `InvalidValue`.

## `rtcp_pli_inflated_length.bin` — §6 defect 3 (PLI)

`81 ce 00 05` + 20×`14` — PSFB, FMT=1 (PLI), length 5 announcing 24 bytes. PLI
carries no FCI, so its model is exactly 12 bytes.

Pre-fix: only the lower bound was checked, so the packet decoded and re-encoded
to 12 bytes; `written == consumed` failed (12 vs 24).
Post-fix: `total != PLI_LENGTH` → `InvalidValue`.

## `rtcp_rrr_inflated_length.bin` — §6 defect 3 (RRR)

`85 cd 00 05` + 20×`14` — same shape for Rapid Resynchronization Request
(PT=205, FMT=5, no FCI, 12-byte model). Pre-fix it decoded and re-encoded to 12
bytes (12 vs 24); post-fix `total != RAPID_RESYNC_LENGTH` rejects it.

## `rtcp_remb_ssrc_count_mismatch.bin` — §6 defect 4 (REMB)

`8f ce 00 06` + sender 1 + media 0 + `REMB` + `01 1a 20 df` + one SSRC
`48 74 ed 16` + four extra bytes — PSFB FMT=15, length 6 (28 bytes announced),
`Num SSRC=1`. The SSRC list is the last field, so the model is 20 + 4 = 24
bytes.

Pre-fix: the bound check used `input.len()` (28) instead of the length-derived
total, so it decoded and re-encoded to 24 bytes (24 vs 28).
Post-fix: `total > 20 + ssrc_count * 4` → `InvalidValue`.

## `rtcp_twcc_extra_word.bin` — §6 defect 5 (TWCC)

`af cd 00 06` + sender 1 + media 2 + base 0 + status count 4 + reference time 0
+ feedback count 0 + chunk `00 04` (4 packets, not received, no deltas) +
padding `00 02` + `de ad be ef` — TSFB FMT=15, P=1, length 6 (28 bytes). The
model is 20 + 2 = 22 raw bytes, 24 with alignment padding.

Pre-fix: bytes after the delta region were ignored, so `consumed` = 28 while
re-encode wrote 24 bytes (24 vs 28). Post-fix:
`raw_len + padding_size(raw_len) != total` → `InvalidValue`.
