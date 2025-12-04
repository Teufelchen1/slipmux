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
        Slipmux::Diagnostic(s) => {
            buffer.resize(space_requirement(s.len()), 0);
            encode(FrameType::Diagnostic, s.as_bytes(), &mut buffer)
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
    ftype: FrameType,
    data: &'input [u8],
    stage: EncoderStage,
    fcs: u16,
    slip: Option<Encoder>,
}

#[derive(Copy, Clone, PartialEq)]
enum EncoderStage {
    EncodeHeader,
    EncodeData,
    EncodeFcs1,
    EncodeFcs2,
    EncodeEnd,
    // Done has no extra stage: Once done, the .slip Encoder is gone.
}

impl<'input> ChunkedEncoder<'input> {
    /// Creates a new chunked encoder.
    ///
    /// This will encode the data based on the `FrameType` over any number of calls to
    /// [`Self::encode_chunk()`] into a buffer provided there.
    #[must_use]
    pub fn new(ftype: FrameType, data: &'input [u8]) -> Self {
        let fcs = if matches!(ftype, FrameType::Configuration) {
            let fcs = fcs16_part(CONF_FCS16, data);
            fcs16_finish(fcs)
        } else {
            // Will not be used
            0
        };

        Self {
            ftype,
            data,
            fcs,
            stage: EncoderStage::EncodeHeader,
            slip: Some(Encoder::new()),
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
    // Note that none of the unwrap()s here can actually panic: encode() will happily not make
    // progress except for
    // * NoOutputSpaceForHeader: that is covered by the initial minimal size,
    //   as the header will always be encoded at the start of a (in particular, the first) chunk
    // * finish running out of space (NoOutputSpaceForEndByte): there is an explicit break
    //   condition.
    pub fn encode_chunk(&mut self, mut buffer: &mut [u8]) -> usize {
        assert!(buffer.len() >= 2, "Chunk too short for minimal progress.");

        let buffer_len_initial = buffer.len();

        let Some(mut slip) = self.slip.take() else {
            return 0;
        };

        loop {
            let (written, new_stage) = match self.stage {
                EncoderStage::EncodeHeader => (
                    // None of those are escapeable, so they always fit in a 2-long buffer from the
                    // start along with the End-Of-Frame marker.
                    match self.ftype {
                        FrameType::Diagnostic => {
                            slip.encode(&[Constants::DIAGNOSTIC], buffer)
                                .unwrap()
                                .written
                        }
                        FrameType::Configuration => {
                            slip.encode(&[Constants::CONFIGURATION], buffer)
                                .unwrap()
                                .written
                        }
                        FrameType::Ip => slip.encode(&[], buffer).unwrap().written,
                    },
                    EncoderStage::EncodeData,
                ),
                EncoderStage::EncodeData => {
                    if self.data.is_empty() {
                        match self.ftype {
                            FrameType::Configuration => (0, EncoderStage::EncodeFcs1),
                            _ => (0, EncoderStage::EncodeEnd),
                        }
                    } else {
                        let encoded = slip.encode(self.data, buffer).unwrap();
                        self.data = &self.data[encoded.read..];
                        (encoded.written, EncoderStage::EncodeData)
                    }
                }
                EncoderStage::EncodeFcs1 => {
                    let encoded = slip.encode(&self.fcs.to_le_bytes()[0..1], buffer).unwrap();
                    if encoded.written == 0 {
                        (0, EncoderStage::EncodeFcs1)
                    } else {
                        (encoded.written, EncoderStage::EncodeFcs2)
                    }
                }
                EncoderStage::EncodeFcs2 => {
                    let encoded = slip.encode(&self.fcs.to_le_bytes()[1..2], buffer).unwrap();
                    if encoded.written == 0 {
                        (0, EncoderStage::EncodeFcs1)
                    } else {
                        (encoded.written, EncoderStage::EncodeEnd)
                    }
                }
                EncoderStage::EncodeEnd => {
                    if buffer.is_empty() {
                        (0, EncoderStage::EncodeEnd)
                    } else {
                        let encoded = slip.finish(buffer).unwrap();
                        // Not advancing data; we won't get around to reading it any more anyway
                        // FIXME can we leave the loop sensibly here to reuse the trailing logic?
                        return buffer_len_initial - buffer.len() + encoded.written;
                    }
                }
            };

            if written == 0 && new_stage == self.stage {
                // No progress made
                break;
            }

            self.stage = new_stage;
            buffer = &mut buffer[written..];
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
            let mut buf = [0, 0];
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
