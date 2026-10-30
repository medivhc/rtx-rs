//! `RTP` header extensions ([RFC 8285]).
//!
//! Two element framings share the wire: the one-byte form (profile
//! [`EXTENSION_PROFILE_ONE_BYTE`]) packs the identifier and a length-minus-one
//! into one octet, and the two-byte form (profile
//! [`EXTENSION_PROFILE_TWO_BYTE`]) spends one octet on each. Any other profile
//! carries opaque data with no element framing ([RFC 3550] §5.3.1).
//!
//! [RFC 3550]: https://www.rfc-editor.org/rfc/rfc3550
//! [RFC 8285]: https://www.rfc-editor.org/rfc/rfc8285

use rtx_wire::WireError;

/// Profile identifier of the one-byte extension form ([RFC 8285] §4.1).
pub const EXTENSION_PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// Profile identifier of the two-byte extension form ([RFC 8285] §4.2).
pub const EXTENSION_PROFILE_TWO_BYTE: u16 = 0x1000;
/// Reserved identifier in the one-byte form; parsing terminates when it is
/// encountered ([RFC 8285] §4.1.2).
pub const EXTENSION_ID_RESERVED: u8 = 0xF;
/// Largest usable identifier in the one-byte form (identifier 15 is reserved).
pub const EXTENSION_ONE_BYTE_ID_MAX: u8 = 14;
/// Largest one-byte-form payload length: the length nibble stores the count
/// minus one.
pub const EXTENSION_ONE_BYTE_LEN_MAX: usize = 16;
/// Largest two-byte-form payload length: the length octet stores the count
/// verbatim.
pub const EXTENSION_TWO_BYTE_LEN_MAX: usize = 255;

/// One decoded header extension element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionItem<'a> {
    /// The extension identifier.
    pub id: u8,
    /// The extension payload, borrowed from the packet.
    pub payload: &'a [u8],
}

/// Iterator over the extension elements of an [`crate::header::Header`].
///
/// Iteration stops at the first malformed or reserved element instead of
/// panicking; [`validate_extension_block`] is the strict check used while
/// decoding.
#[derive(Debug, Clone, Copy)]
pub struct Extensions<'a> {
    profile: u16,
    data: &'a [u8],
    offset: usize,
}

impl<'a> Extensions<'a> {
    /// Starts an iteration over `data` framed by `profile`.
    pub(crate) const fn new(profile: u16, data: &'a [u8]) -> Self {
        Self {
            profile,
            data,
            offset: 0,
        }
    }
}

// `Extensions` is deliberately `Copy` (it is a three-word cursor over the
// borrowed block), so `Header::extensions()` can hand out fresh iterators
// cheaply and repeatedly; that is why `Iterator` is implemented directly
// instead of only `IntoIterator`.
#[allow(clippy::copy_iterator)]
impl<'a> Iterator for Extensions<'a> {
    type Item = ExtensionItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let byte = *self.data.get(self.offset)?;
            match self.profile {
                EXTENSION_PROFILE_ONE_BYTE => {
                    let id = byte >> 4;
                    if id == 0 {
                        if byte == 0x00 {
                            // RFC 8285 §4.1.1: bare 0x00 octets pad the gap
                            // between elements.
                            self.offset += 1;
                            continue;
                        }
                        // RFC 8285 §4.1.2: identifier 0 with a non-zero length
                        // means the length is ignored and the remainder of the
                        // block is padding.
                        return None;
                    }
                    if id == EXTENSION_ID_RESERVED {
                        // RFC 8285 §4.1.2: identifier 15 is reserved; the rest
                        // of the block is not element data.
                        return None;
                    }
                    let len = usize::from(byte & 0x0F) + 1;
                    let start = self.offset + 1;
                    let payload = self.data.get(start..start + len)?;
                    self.offset = start + len;
                    return Some(ExtensionItem { id, payload });
                }
                EXTENSION_PROFILE_TWO_BYTE => {
                    if byte == 0x00 {
                        // RFC 8285 §4.2: bare 0x00 octets pad the gap between
                        // elements.
                        self.offset += 1;
                        continue;
                    }
                    let len = usize::from(*self.data.get(self.offset + 1)?);
                    let start = self.offset + 2;
                    let payload = self.data.get(start..start + len)?;
                    self.offset = start + len;
                    return Some(ExtensionItem { id: byte, payload });
                }
                // Legacy profiles carry opaque data without element framing.
                _ => return None,
            }
        }
    }
}

/// Validates the element framing of an extension block.
///
/// # Errors
///
/// Returns [`WireError::InvalidValue`] when an element's payload runs past the
/// end of `data`, or when the two-byte form is missing its length octet.
/// Legacy profiles carry opaque data and always validate.
pub fn validate_extension_block(profile: u16, data: &[u8]) -> Result<(), WireError> {
    match profile {
        EXTENSION_PROFILE_ONE_BYTE => {
            let mut offset = 0usize;
            while let Some(&byte) = data.get(offset) {
                let id = byte >> 4;
                if id == 0 {
                    if byte == 0x00 {
                        offset += 1;
                        continue;
                    }
                    // RFC 8285 §4.1.2: the length is ignored, the remainder is
                    // padding.
                    return Ok(());
                }
                if id == EXTENSION_ID_RESERVED {
                    // RFC 8285 §4.1.2: identifier 15 terminates parsing.
                    return Ok(());
                }
                let len = usize::from(byte & 0x0F) + 1;
                let end = offset + 1 + len;
                if end > data.len() {
                    return Err(WireError::InvalidValue);
                }
                offset = end;
            }
            Ok(())
        }
        EXTENSION_PROFILE_TWO_BYTE => {
            let mut offset = 0usize;
            while let Some(&id) = data.get(offset) {
                if id == 0x00 {
                    offset += 1;
                    continue;
                }
                let len = usize::from(*data.get(offset + 1).ok_or(WireError::InvalidValue)?);
                let end = offset + 2 + len;
                if end > data.len() {
                    return Err(WireError::InvalidValue);
                }
                offset = end;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- RTP-EXT: differential vectors from upstream rtc-rtp ----------------
    //
    // The packet fixtures below carry the upstream bytes verbatim; the
    // extension data starts at offset 16 (12-byte fixed header plus the
    // 4-byte extension header) and its length comes from the length field.

    /// Extension data of [`TEST_8285_ONE_BYTE`] (see `packet.rs` tests).
    const ONE_BYTE_SINGLE: [u8; 4] = [0x50, 0xAA, 0x00, 0x00];
    /// Extension data of the two-element one-byte fixture.
    const ONE_BYTE_TWO: [u8; 4] = [0x10, 0xAA, 0x20, 0xBB];
    /// Extension data with interior padding between elements.
    const ONE_BYTE_PADDED: [u8; 12] = [
        0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x00, 0x00, 0x33, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    /// Extension data with the padding moved to the end.
    const ONE_BYTE_MULTI: [u8; 12] = [
        0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x33, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00,
    ];
    /// Two-byte form, single element with a 24-octet payload.
    const TWO_BYTE_SINGLE: [u8; 28] = [
        0x05, 0x18, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
    ];
    /// Two-byte form with a padding octet between elements.
    const TWO_BYTE_PADDED: [u8; 12] = [
        0x01, 0x00, 0x02, 0x01, 0xBB, 0x00, 0x03, 0x04, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    /// Two-byte form with a 17-octet payload.
    const TWO_BYTE_LARGE: [u8; 24] = [
        0x01, 0x00, 0x02, 0x01, 0xBB, 0x03, 0x11, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];

    fn items(profile: u16, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        Extensions::new(profile, data)
            .map(|item| (item.id, item.payload.to_vec()))
            .collect()
    }

    // RTP-EXT-001 — one-byte form, single element (upstream packet_test.rs:175-178).
    #[test]
    fn one_byte_single_element() {
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_SINGLE),
            vec![(5, vec![0xAA])]
        );
    }

    // RTP-EXT-002 — one-byte form, two one-octet elements (upstream packet_test.rs:217-221).
    #[test]
    fn one_byte_two_elements() {
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_TWO),
            vec![(1, vec![0xAA]), (2, vec![0xBB])]
        );
    }

    // RTP-EXT-003 — one-byte form, interior padding is skipped (upstream packet_test.rs:288-293).
    #[test]
    fn one_byte_elements_with_interior_padding() {
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_PADDED),
            vec![
                (1, vec![0xAA]),
                (2, vec![0xBB, 0xBB]),
                (3, vec![0xCC, 0xCC, 0xCC, 0xCC]),
            ]
        );
    }

    // RTP-EXT-004 — one-byte form, trailing padding (upstream packet_test.rs:367-372).
    #[test]
    fn one_byte_elements_with_trailing_padding() {
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_MULTI),
            vec![
                (1, vec![0xAA]),
                (2, vec![0xBB, 0xBB]),
                (3, vec![0xCC, 0xCC, 0xCC, 0xCC]),
            ]
        );
    }

    // RTP-EXT-005 — two-byte form, single element, length is verbatim (upstream packet_test.rs:415-420).
    #[test]
    fn two_byte_single_element() {
        let expected = (5, vec![0xAA; 24]);
        assert_eq!(
            items(EXTENSION_PROFILE_TWO_BYTE, &TWO_BYTE_SINGLE),
            vec![expected]
        );
    }

    // RTP-EXT-006 — two-byte form, padding octet between elements (upstream packet_test.rs:468-472).
    #[test]
    fn two_byte_elements_with_padding() {
        assert_eq!(
            items(EXTENSION_PROFILE_TWO_BYTE, &TWO_BYTE_PADDED),
            vec![
                (1, vec![]),
                (2, vec![0xBB]),
                (3, vec![0xCC, 0xCC, 0xCC, 0xCC]),
            ]
        );
    }

    // RTP-EXT-007 — two-byte form, 17-octet payload (upstream packet_test.rs:520-525).
    #[test]
    fn two_byte_large_element() {
        assert_eq!(
            items(EXTENSION_PROFILE_TWO_BYTE, &TWO_BYTE_LARGE),
            vec![(1, vec![]), (2, vec![0xBB]), (3, vec![0xCC; 17])]
        );
    }

    // RTP-EXT-008 — reserved identifier 15 terminates parsing (upstream packet_test.rs:894-897).
    #[test]
    fn reserved_id_terminates_parsing() {
        // 0xF0: identifier 15, length nibble 0.
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &[0xF0, 0xAA, 0x98]),
            [] as [(u8, std::vec::Vec<u8>); 0]
        );
    }

    // RTP-EXT-009 — identifier 0 with a non-zero length nibble terminates
    // parsing (RFC 8285 §4.1.2: the length is ignored, the rest is padding).
    #[test]
    fn id_zero_with_length_terminates_parsing() {
        // 0x05: identifier 0, length nibble 5.
        assert_eq!(
            items(EXTENSION_PROFILE_ONE_BYTE, &[0x05, 0xAA, 0xBB, 0xCC]),
            [] as [(u8, std::vec::Vec<u8>); 0]
        );
    }

    // RTP-EXT-010 — a legacy profile yields no elements (opaque data).
    #[test]
    fn legacy_profile_yields_no_elements() {
        assert_eq!(
            items(0x0001, &[0xFF, 0xFF, 0xFF, 0xFF]),
            [] as [(u8, std::vec::Vec<u8>); 0]
        );
    }

    // RTP-EXT-011 — validate accepts well-formed one-byte blocks.
    #[test]
    fn validate_one_byte_accepts_wellformed_blocks() {
        assert!(validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_SINGLE).is_ok());
        assert!(validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &ONE_BYTE_PADDED).is_ok());
        assert!(validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x00, 0x00]).is_ok());
        // Reserved identifier 15 and identifier 0 with data both terminate.
        assert!(validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0xF0, 0xAA]).is_ok());
        assert!(validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x05, 0xAA]).is_ok());
    }

    // RTP-EXT-012 — validate rejects a one-byte element whose payload overruns.
    #[test]
    fn validate_one_byte_rejects_overrun() {
        // 0x21: identifier 2, length 2, but only one payload octet follows.
        assert_eq!(
            validate_extension_block(EXTENSION_PROFILE_ONE_BYTE, &[0x21, 0xBB]),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            validate_extension_block(
                EXTENSION_PROFILE_ONE_BYTE,
                &[0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x33]
            ),
            Err(WireError::InvalidValue)
        );
    }

    // RTP-EXT-013 — validate rejects a two-byte block missing its length octet.
    #[test]
    fn validate_two_byte_rejects_missing_length() {
        assert_eq!(
            validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[0x05]),
            Err(WireError::InvalidValue)
        );
    }

    // RTP-EXT-014 — validate rejects a two-byte element whose payload overruns.
    #[test]
    fn validate_two_byte_rejects_overrun() {
        assert_eq!(
            validate_extension_block(EXTENSION_PROFILE_TWO_BYTE, &[0x05, 0x18, 0xAA, 0xAA]),
            Err(WireError::InvalidValue)
        );
    }

    // RTP-EXT-015 — legacy profiles carry opaque data and always validate.
    #[test]
    fn validate_legacy_profile_is_permissive() {
        assert!(validate_extension_block(0x0001, &[0xFF, 0xFF, 0xFF, 0xFF]).is_ok());
        assert!(validate_extension_block(0x1111, &[0x01, 0x02]).is_ok());
    }
}
