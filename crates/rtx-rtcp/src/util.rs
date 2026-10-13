//! Internal helpers shared by the RTCP encoders.

use rtx_wire::{WireError, Writer};

/// Number of zero bytes needed to pad `len` up to a 4-byte boundary.
///
/// Returns a value in `0..=3` (RFC 3550 section 6.4.1 padding rules).
pub(crate) const fn padding_size(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// Writes `count` zero bytes followed by a trailing count byte.
///
/// RTCP padding is self-describing: the final byte of the padded region
/// contains the total number of padding bytes that were appended
/// (RFC 3550 section 6.4.1). `count` must be in `1..=3`.
pub(crate) fn write_padding(writer: &mut Writer<'_>, count: usize) -> Result<(), WireError> {
    const ZEROS: [u8; 3] = [0, 0, 0];
    debug_assert!((1..=3).contains(&count), "padding count must be 1..=3");
    writer.put(&ZEROS[..count - 1])?;
    let count_byte = u8::try_from(count).map_err(|_| WireError::Overflow)?;
    writer.u8(count_byte)?;
    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn rtcp_util_001_padding_size_aligned() {
        assert_eq!(padding_size(0), 0);
        assert_eq!(padding_size(4), 0);
        assert_eq!(padding_size(8), 0);
    }

    #[test]
    fn rtcp_util_002_padding_size_unaligned() {
        assert_eq!(padding_size(1), 3);
        assert_eq!(padding_size(2), 2);
        assert_eq!(padding_size(3), 1);
    }

    #[test]
    fn rtcp_util_003_write_padding_round_trip() {
        for count in 1..=3usize {
            let mut buf = [0u8; 8];
            let mut writer = Writer::new(&mut buf);
            write_padding(&mut writer, count).expect("write padding");
            assert_eq!(writer.offset(), count, "written byte count");
            let written = &buf[..count];
            // All leading bytes are zero, the trailing byte is the count.
            assert_eq!(
                written[count - 1],
                u8::try_from(count).expect("count fits u8")
            );
            assert!(written[..count - 1].iter().all(|&b| b == 0));
        }
    }
}
