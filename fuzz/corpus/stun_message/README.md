# `stun_message` regression corpus

## `stun_reserved_type_bits.bin` — §6 defect 6 (MessageType reserved bits)

```
40 01 00 00 21 12 a4 42 00 01 02 03 04 05 06 07 08 09 0a 0b
```

Wire layout: 20-byte STUN header. Type field `0x4001` sets reserved bit 14
(`01` in the top two bits is the TURN ChannelData marker per RFC 5389 §6), body
length 0, magic cookie `0x2112A442`, a 12-byte transaction ID.

Pre-fix: `MessageType::read_value` discarded the top two bits, so `decode`
accepted the packet and re-encoding silently rewrote the type to `0x0001`.
The target's verbatim round-trip assertion failed (`0x40` vs `0x00` in the
first byte).
Post-fix: `Message::decode` rejects a non-zero reserved field with
`WireError::InvalidValue`, so the packet never reaches the re-encode check.
