//! `RTP` header access shared by the sender and receiver paths.
//!
//! The fixed 12-byte header is always cleartext. The receiver reads only that
//! prefix before authentication; and because this module encrypts the `CSRC`
//! list and header extension too, it parses the complete header only after
//! decryption.

use rtx_rtp::{Decode, Header};

use crate::FIXED_HEADER_LEN;
use crate::error::Error;

const RTP_VERSION: u8 = 2;
const VERSION_SHIFT: u8 = 6;
const VERSION_MASK: u8 = 0x3;

/// Reads the version, sequence number and `SSRC` from the cleartext fixed
/// header.
///
/// # Errors
///
/// Returns [`Error::MalformedPacket`] when the packet is shorter than 12 bytes
/// or is not `RTP` version 2.
pub(crate) fn fixed_header(packet: &[u8]) -> Result<(u16, u32), Error> {
    let fixed = packet
        .get(..FIXED_HEADER_LEN)
        .ok_or(Error::MalformedPacket)?;
    let version = (fixed[0] >> VERSION_SHIFT) & VERSION_MASK;
    if version != RTP_VERSION {
        return Err(Error::MalformedPacket);
    }
    let sequence = u16::from_be_bytes([fixed[2], fixed[3]]);
    let ssrc = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
    Ok((sequence, ssrc))
}

/// Parses and validates the full `RTP` header.
///
/// # Errors
///
/// Returns [`Error::MalformedPacket`] for a bad version, a truncated `CSRC`
/// list, or an extension length or element framing that does not fit the
/// packet.
pub(crate) fn parse(packet: &[u8]) -> Result<Header<'_>, Error> {
    Header::decode(packet)
        .map(|(header, _consumed)| header)
        .map_err(|_| Error::MalformedPacket)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn bare(version: u8, sequence: u16, ssrc: u32) -> [u8; FIXED_HEADER_LEN] {
        let mut packet = [0u8; FIXED_HEADER_LEN];
        packet[0] = version << VERSION_SHIFT;
        packet[1] = 96;
        packet[2..4].copy_from_slice(&sequence.to_be_bytes());
        packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
        packet
    }

    // SRTP-PKT-001 — the cleartext prefix yields sequence number and SSRC.
    #[test]
    fn fixed_header_reads_sequence_and_ssrc() {
        let packet = bare(2, 0x1234, 0xDEAD_BEEF);
        assert_eq!(fixed_header(&packet), Ok((0x1234, 0xDEAD_BEEF)));
    }

    // SRTP-PKT-002 — short prefixes and non-version-2 packets are rejected.
    #[test]
    fn short_or_non_rtp_prefix_is_rejected() {
        assert_eq!(fixed_header(&[]), Err(Error::MalformedPacket));
        assert_eq!(
            fixed_header(&[0x80; FIXED_HEADER_LEN - 1]),
            Err(Error::MalformedPacket)
        );
        for version in [0_u8, 1, 3] {
            assert_eq!(
                fixed_header(&bare(version, 0, 0)),
                Err(Error::MalformedPacket)
            );
        }
    }

    // SRTP-PKT-003 — the full parser accepts a clean header and rejects a
    // lying CSRC count or extension length.
    #[test]
    fn full_parser_validates_csrc_and_extension_bounds() {
        assert!(parse(&bare(2, 1, 2)).is_ok());

        let mut short_csrc = vec![0u8; FIXED_HEADER_LEN];
        short_csrc[0] = 0x8F;
        assert_eq!(parse(&short_csrc), Err(Error::MalformedPacket));

        let mut long_extension = vec![0u8; 20];
        long_extension[0] = 0x90;
        long_extension[12..16].copy_from_slice(&[0xBE, 0xDE, 0xFF, 0xFF]);
        assert_eq!(parse(&long_extension), Err(Error::MalformedPacket));
    }
}
