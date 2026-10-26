# `rtcp_compound` regression corpus

All seeds are checked by `fuzz_targets/rtcp_compound.rs`, which asserts that a
decoded RTCP sub-packet re-encodes to exactly the number of bytes `decode`
consumed, and that a compound packet tiles its input exactly. Before commit
`936f701` each seed below made the target fail; after it every seed passes
(either by decoding to the correct model or by being rejected early).

## `rtcp_bye_empty_reason_padding.bin` — §6 defect 1 (Goodbye alignment)

```
80 cb 00 01 00 00 00 00
```

Wire layout: BYE (PT=203), SC=0, `length=1` (8 bytes), reason length octet `00`
at offset 4, then three null octets. RFC 3550 §6.4.4 requires the reason to be
followed by nulls up to a 32-bit boundary.

Pre-fix: `raw_len()` counted `4 + 0 + 1 = 5` and was not rounded up, so
`encoded_len()` was 5 while `decode` consumed 8; re-encode wrote a header
claiming 4 bytes. The target's `written == consumed` assertion failed (5 vs 8).
Post-fix: `aligned_len()` is 8, decode accepts the packet and re-encoding is
byte-identical.

## `rtcp_bye_trailing_bytes.bin` — §6 defect 2 (Goodbye trailing bytes)

```
81 cb 00 03 90 2f 9e 2e 00 de ad be ef 00 00 00
```

Wire layout: BYE, SC=1, `length=3` (16 bytes announced), one SSRC, reason length
octet `00`, then four bytes that follow the reason. A BYE has no field after the
reason and its alignment padding, so the model can represent at most
`4 + 4 + 1 = 9` raw bytes, i.e. 12 aligned bytes.

Pre-fix: the decoder ignored the tail and reported `consumed=16`, while
`encoded_len()` was 9; the target's length assertion failed (9 vs 16).
Post-fix: `input.len() != aligned_len()` (16 != 12) returns
`WireError::InvalidValue`.

## `rtcp_bye_three_octet_reason.bin` — §6 defect 2 (three-octet reason shape)

```
80 cb 00 02 03 61 62 63 de ad be ef
```

Wire layout: BYE, SC=0, `length=2` (12 bytes announced), reason length octet
`03` followed by `abc`, then one trailing 32-bit word. The reason and its length
octet occupy 4 bytes, so the model is 8 bytes in total and the trailing word is
unrepresentable.

Pre-fix: the decoder ignored the tail and reported `consumed=12`, while
`encoded_len()` was 8; the target's length assertion failed (8 vs 12).
Post-fix: `input.len() != aligned_len()` (12 != 8) returns
`WireError::InvalidValue`.

## `rtcp_pli_inflated_length.bin` — §6 defect 3 (PLI)

```
81 ce 00 05 14 14 ... (20 bytes of 0x14)
```

Wire layout: PSFB (PT=206), FMT=1 (PLI), `length=5` announcing 24 bytes. PLI
carries no FCI, so its model is exactly 12 bytes.

Pre-fix: only the lower bound was checked, so the 24-byte packet decoded and
re-encoded to 12 bytes; `written == consumed` failed (12 vs 24).
Post-fix: `total != PLI_LENGTH` returns `WireError::InvalidValue`.

## `rtcp_rrr_inflated_length.bin` — §6 defect 3 (RRR)

```
85 cd 00 05 14 14 ... (20 bytes of 0x14)
```

Same shape for Rapid Resynchronization Request (PT=205, FMT=5, no FCI,
12-byte model). Pre-fix the 24-byte announced packet decoded and re-encoded to
12 bytes; post-fix `total != RAPID_RESYNC_LENGTH` rejects it.

## `rtcp_remb_ssrc_count_mismatch.bin` — §6 defect 4 (REMB)

```
8f ce 00 06 00 00 00 01 00 00 00 00 52 45 4d 42
01 1a 20 df 48 74 ed 16 00 00 00 02
```

Wire layout: PSFB FMT=15 (REMB), `length=6` (28 bytes announced), sender SSRC
1, media SSRC 0, identifier `REMB`, `Num SSRC=1`, exp/mantissa bytes
`1a 20 df`, one SSRC entry, then four extra bytes. The SSRC list is the last
field, so `Num SSRC=1` fixes the model at 24 bytes.

Pre-fix: the bound check used `input.len()` (28) instead of the length-derived
total, so the packet decoded and re-encoded to 24 bytes; the target's length
assertion failed (24 vs 28).
Post-fix: `total > 20 + ssrc_count * 4` returns `WireError::InvalidValue`.

## `rtcp_twcc_extra_word.bin` — §6 defect 5 (TWCC)

```
af cd 00 06 00 00 00 01 00 00 00 02 00 00 00 04
00 00 00 00 00 04 00 02 de ad be ef
```

Wire layout: TSFB FMT=15 (TWCC), P=1, `length=6` (28 bytes), sender/media
SSRCs, base sequence 0, packet status count 4, reference time 0, feedback
count 0, one run-length chunk `00 04` (4 packets, not received, no deltas),
2 bytes of alignment padding `00 02`, then one extra 32-bit word.
The model is `20 + 2 = 22` raw bytes, i.e. 24 with padding.

Pre-fix: bytes after the delta region were ignored, so the packet decoded with
`consumed=28` but re-encoded to 24 bytes; the target failed (24 vs 28).
Post-fix: `raw_len + padding_size(raw_len) != total` returns
`WireError::InvalidValue`.
