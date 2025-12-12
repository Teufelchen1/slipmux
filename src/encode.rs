use crate::Constants;
use crate::FrameType;
#[cfg(feature = "std")]
use crate::Slipmux;
use crate::checksum::CONF_FCS16;
use crate::checksum::fcs16_finish;
use crate::checksum::fcs16_part;
use serial_line_ip::Encoder;

/// Short hand for `encode(FrameType::Diagnostic, text.as_bytes(), buffer)`
#[must_use]
pub fn encode_diagnostic(text: &str, buffer: &mut [u8]) -> usize {
    encode(FrameType::Diagnostic, text.as_bytes(), buffer)
}

/// Short hand for `encode(FrameType::Configuration, &packet, buffer)`
#[must_use]
pub fn encode_configuration(packet: &[u8], buffer: &mut [u8]) -> usize {
    encode(FrameType::Configuration, packet, buffer)
}

/// Short hand for `encode(FrameType::Ip, &packet, buffer)`
#[must_use]
pub fn encode_packet(packet: &[u8], buffer: &mut [u8]) -> usize {
    encode(FrameType::Ip, packet, buffer)
}

/// Encodes `Slipmux` data into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into the buffer
#[cfg(feature = "std")]
#[must_use]
pub fn encode_buffered(input: Slipmux) -> Vec<u8> {
    // Calculate the worst-case amount of space needed to encode this much data
    const fn space_requirement(data_len: usize) -> usize {
        const FRAMETYPE_BYTE: usize = 1;
        const ENDFRAME_BYTE: usize = 1;
        // Assuming every single byte needs to be escaped
        let max_encoded_len: usize = data_len * 2;
        // leading endframe byte to flush privious unclean states (if any)
        // see slip rfc
        ENDFRAME_BYTE + FRAMETYPE_BYTE + max_encoded_len + ENDFRAME_BYTE
    }
    let mut buffer: Vec<u8> = vec![];
    let length = match input {
        Slipmux::Diagnostic(message) => {
            buffer.resize(space_requirement(message.len()), 0);
            encode(FrameType::Diagnostic, message.as_bytes(), &mut buffer)
        }
        Slipmux::Configuration(conf) => {
            const CHECKSUM_BYTES: usize = 2;
            buffer.resize(space_requirement(conf.len() + CHECKSUM_BYTES), 0);
            encode(FrameType::Configuration, &conf, &mut buffer)
        }
        Slipmux::Packet(packet) => {
            // IP packets don't have a start byte so this is over provisioning one byte
            buffer.resize(space_requirement(packet.len()), 0);
            encode(FrameType::Ip, &packet, &mut buffer)
        }
    };
    buffer.truncate(length);
    buffer
}

/// Encodes data based on the `FrameType` into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into the buffer
#[must_use]
pub fn encode(ftype: FrameType, data: &[u8], buffer: &mut [u8]) -> usize {
    let mut encoder = ChunkedEncoder::new(ftype, data);
    let size = encoder.encode_chunk(buffer);
    assert!(encoder.is_exhausted(), "Output buffer was too small");
    size
}

/// Encoder for a frame.
///
/// This item keeps the state of an encoding progress when encoding into a small buffer, e.g. a
/// UART output buffer, which might be reused as soon as some data is flushed out.
pub struct ChunkedEncoder<'input> {
    header: &'static [u8],
    data: &'input [u8],
    // Note that this is often initialized to 2 to not serialize any FCS
    fcs_cursor: u8,
    fcs: [u8; 2],
    slip: Option<Encoder>,
}

impl<'input> ChunkedEncoder<'input> {
    /// Creates a new chunked encoder.
    ///
    /// This will encode the data based on the `FrameType` over any number of calls to
    /// [`Self::encode_chunk()`] into a buffer provided there.
    #[must_use]
    pub fn new(ftype: FrameType, data: &'input [u8]) -> Self {
        let header: &[u8] = match ftype {
            FrameType::Diagnostic => &[Constants::DIAGNOSTIC],
            FrameType::Configuration => &[Constants::CONFIGURATION],
            FrameType::Ip => &[],
        };

        let (fcs, fcs_cursor) = if matches!(ftype, FrameType::Configuration) {
            let fcs = fcs16_part(CONF_FCS16, data);
            (fcs16_finish(fcs).to_le_bytes(), 0)
        } else {
            ([0, 0], 2)
        };

        Self {
            header,
            data,
            fcs_cursor,
            fcs,
            slip: Some(Encoder::new()),
        }
    }

    /// Non-empty next piece of data that should be encoded, or None if all data has been encoded
    /// (but probably not the End marker).
    fn slice_to_encode(&self) -> Option<&[u8]> {
        if !self.header.is_empty() {
            Some(self.header)
        } else if !self.data.is_empty() {
            Some(self.data)
        } else if (self.fcs_cursor as usize) < self.fcs.len() {
            Some(&self.fcs[self.fcs_cursor as usize..])
        } else {
            None
        }
    }

    /// Advance whichever slice was just selected in [`Self::slice_to_encode()`] by some amount of
    /// bytes.
    #[expect(clippy::cast_possible_truncation)] // TODO: should this be fixed?
    fn advance_slice(&mut self, amount: usize) {
        if !self.header.is_empty() {
            self.header = &self.header[amount..];
        } else if !self.data.is_empty() {
            self.data = &self.data[amount..];
        } else {
            self.fcs_cursor += amount as u8;
        }
    }

    /// Writes some of the data into the output buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// Unlike many other write-style methods, this does *not* fill up the buffer to the last byte
    /// except for the last block; this simplifies encoding escaped bytes.
    ///
    /// Call this function on some buffer until it returns 0 (in which case all of its content is
    /// serialized).
    ///
    /// # Panics
    ///
    /// Panics if `out` is less than 2 byte (the maximum encoded length of the minimum progress
    /// this can make).
    pub fn encode_chunk(&mut self, mut buffer: &mut [u8]) -> usize {
        // We might get over small buffers in some situations, but things would break on generic
        // data. If a user calculates the buffer precisely to the maximum needs, there would be a
        // case for tolerating len 1 when only the End marker is left, but then, if a user has a
        // precisely calculated buffer, they can populated it right away in full.
        assert!(buffer.len() >= 2, "Chunk too short for minimal progress.");

        let buffer_len_initial = buffer.len();

        let Some(mut slip) = self.slip.take() else {
            return 0;
        };

        loop {
            if let Some(slice) = self.slice_to_encode() {
                let encoded = slip.encode(slice, buffer).expect(
                    "this only fails when there is not even enough room for the start byte",
                );

                buffer = &mut buffer[encoded.written..];
                self.advance_slice(encoded.read);

                if encoded.written == 0 {
                    break;
                }
            } else {
                #[expect(
                    clippy::redundant_else,
                    clippy::if_not_else,
                    reason = "reflects logical decision tree"
                )]
                if !buffer.is_empty() {
                    let encoded = slip.finish(buffer).expect("buffer was checked explictly");
                    // FIXME can we leave the loop sensibly here to reuse the trailing logic?
                    return buffer_len_initial - buffer.len() + encoded.written;
                } else {
                    break;
                }
            }
        }
        self.slip = Some(slip);

        buffer_len_initial - buffer.len()
    }

    /// Returns true iff [`Self::encode_chunk`] would return 0.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "no point in this for runtime state"
    )]
    pub fn is_exhausted(&self) -> bool {
        self.slip.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap_lite::Packet;

    #[test]
    #[cfg(feature = "std")]
    fn simple_diagnostic() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_diagnostic("Hello World!", &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");
        let length = encode_diagnostic("Yes, I would like one \x0a please.", &mut buffer);
        assert_eq!(
            buffer[..length],
            *b"\xc0\x0aYes, I would like one \x0a please.\xc0"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn wrapper_diagnostic() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_diagnostic("", &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0a\xc0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn wrapper_configuration() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_configuration(&Packet::new().to_bytes().unwrap(), &mut buffer);
        assert_eq!(
            buffer[..length],
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    #[test]
    fn direct() {
        const DATA: &str = "Hello World!";
        let mut buffer: [u8; 2048] = [0; 2048];

        let length = encode(FrameType::Diagnostic, DATA.as_bytes(), &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");

        let packet: &[u8] = &Packet::new().to_bytes().unwrap();
        let length = encode(FrameType::Configuration, packet, &mut buffer);
        assert_eq!(
            buffer[..length],
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    fn chunked<const N: usize>() {
        extern crate alloc;
        use alloc::vec::Vec;
        const DATA: &str = "Hello World!";

        let mut encoder = ChunkedEncoder::new(FrameType::Diagnostic, DATA.as_bytes());
        let mut output = Vec::new();
        while !encoder.is_exhausted() {
            let mut buf = [0; N];
            let length = encoder.encode_chunk(&mut buf);
            output.extend_from_slice(&buf[..length]);
        }
        assert_eq!(output, *b"\xc0\x0aHello World!\xc0");

        let packet: &[u8] = &Packet::new().to_bytes().unwrap();
        let mut encoder = ChunkedEncoder::new(FrameType::Configuration, packet);
        let mut output = Vec::new();
        while !encoder.is_exhausted() {
            let mut buf = [0, 0];
            let length = encoder.encode_chunk(&mut buf);
            output.extend_from_slice(&buf[..length]);
        }
        assert_eq!(
            output,
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    #[test]
    fn chunked_2() {
        chunked::<2>();
    }

    #[test]
    fn chunked_3() {
        chunked::<3>();
    }

    #[test]
    #[cfg(feature = "std")]
    fn direct_std() {
        const DATA: &str = "Hello World!";
        let input = Slipmux::Diagnostic(DATA.to_owned());
        let result = encode_buffered(input);
        assert_eq!(result, *b"\xc0\x0aHello World!\xc0");

        let packet: &[u8] = &Packet::new().to_bytes().unwrap();
        let input = Slipmux::Configuration(packet.to_vec());
        let result = encode_buffered(input);
        assert_eq!(
            result,
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn encode_buffered_max_encoding_size() {
        let mut data: Vec<u8> = vec![
            Constants::END,
            Constants::ESC,
            Constants::ESC,
            Constants::END,
            Constants::ESC,
            Constants::END,
            Constants::ESC,
            Constants::END,
        ];
        for _ in 0..=45 {
            data.push(Constants::ESC);
        }
        assert_eq!(data.len(), 54);
        let input = Slipmux::Configuration(data);
        let result = encode_buffered(input);

        // endbyte + startbyte + data * 2 + fcs * 2 + endbyte
        // data * 2 because every single byte needs escaping
        // fcs * 2 because both fcs bytes need escaping
        assert_eq!(result.len(), 1 + 1 + 54 * 2 + 2 * 2 + 1);

        let mut expected: Vec<u8> = vec![
            Constants::END,
            Constants::CONFIGURATION,
            Constants::ESC,
            Constants::ESC_END,
            Constants::ESC,
            Constants::ESC_ESC,
            Constants::ESC,
            Constants::ESC_ESC,
            Constants::ESC,
            Constants::ESC_END,
            Constants::ESC,
            Constants::ESC_ESC,
            Constants::ESC,
            Constants::ESC_END,
            Constants::ESC,
            Constants::ESC_ESC,
            Constants::ESC,
            Constants::ESC_END,
        ];
        for _ in 0..=45 {
            expected.push(Constants::ESC);
            expected.push(Constants::ESC_ESC);
        }

        // Checksum is 0xC0C0
        expected.push(Constants::ESC);
        expected.push(Constants::ESC_END);
        expected.push(Constants::ESC);
        expected.push(Constants::ESC_END);

        // End frame
        expected.push(Constants::END);

        assert_eq!(result, expected);
    }
}
