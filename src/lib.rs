//! Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer
//!
//! Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).
//!
//! Note: Frame aborting is not implemented!
//!
//! ## What is Slipmux
//!
//! Slipmux is a very simple framing and multiplexing protocol. It uses RFC1055,
//! commonly known as [serial line ip (slip)](https://datatracker.ietf.org/doc/html/rfc1055),
//! as a basis for encoding / decoding data streams into frames but extends it with
//! multiplexing. Slipmux defines three frame types: traditional IP packets,
//! diagnostic frames and configuration messages.
//! Diagnostic frames are UTF-8 encoded strings intended as human-readable messages.
//! Configuration messages are serialized `CoAP` messages.
//!
//! ## Examples
//!
//! Slipmux can be used to both encode and decode streams of bytes:
//!
//! ### Encoding
//!
//! Encoding is done in a single pass.
//! First wrap your data in the matching type of the `Slipmux` enum. Then
//! feed it into the `encode()` function.
//! Alternatively, use the helper function `encode_diagnostic()` and `encode_configurtation()`.
//!
//! ```
//! use slipmux::Slipmux;
//! use slipmux::encode;
//! use coap_lite::Packet;
//!
//! let input = Slipmux::Diagnostic("Hello World!".to_owned());
//! let (result, length) = encode(input);
//! assert_eq!(result[..length], *b"\xc0\x0aHello World!\xc0");
//!
//! let input = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
//! let (result, length) = encode(input);
//! assert_eq!(result[..length], [0xc0, 0xa9, 0x40, 0x01, 0x00, 0x00, 0xbc, 0x38, 0xc0]);
//! ```
//!
//! ### Decoding
//!
//! Since the length and number of frames in a data stream (byte slice)
//! is unknown upfront, the decoder retains a state even after finishing decoding
//! the input. This enables to repeatedly call the decoder with new input data and
//! if a frame is split between two or more calls, the decoder will correctly concat the frame.
//!
//! ```
//! use slipmux::Slipmux;
//! use slipmux::Decoder;
//!
//! const SLIPMUX_ENCODED: [u8; 15] = [
//!     0xc0, 0x0a,
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//!     0xc0
//! ];
//!
//! let mut slipmux = Decoder::new();
//! let mut results = slipmux.decode(&SLIPMUX_ENCODED);
//! assert_eq!(results.len(), 1);
//! let frame = results.pop().unwrap();
//! assert!(frame.is_ok());
//! match frame.unwrap() {
//!     Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
//!     _ => panic!(),
//! }
//!
//! ```
//!
//! If you keep getting new input data, try iterating through the result:
//!
//! ```
//! use slipmux::Slipmux;
//! use slipmux::Decoder;
//!
//! const SLIPMUX_ENCODED: [u8; 45] = [
//!     0xc0, 0x0a,
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//!     0xc0,
//!     0xc0, 0x0a,
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//!     0xc0,
//!     0xc0, 0x0a,
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//!     0xc0,
//! ];
//!
//! let mut slipmux = Decoder::new();
//!
//! for input_slice in SLIPMUX_ENCODED.chunks(4) {
//!     for slipframe in slipmux.decode(&input_slice) {
//!         if slipframe.is_err() {
//!            panic!();
//!         }
//!         match slipframe.unwrap() {
//!             Slipmux::Diagnostic(s) => {
//!                 assert_eq!(s, "Hello World!")
//!             }
//!             Slipmux::Configuration(conf) => {
//!                 // Do stuff
//!             }
//!             Slipmux::Packet(packet) => {
//!                 // Do stuff
//!             }
//!         }
//!     }
//! }
//!
//! ```
use checksum::{check_fcs, fcs16};
use serial_line_ip::EncodeTotals;
use serial_line_ip::Encoder;
use serial_line_ip::Error as SlipError;

mod checksum;

/// Ends a frame
const END: u8 = 0xC0;

/// Start byte of a diagnostic frame
const DIAGNOSTIC: u8 = 0x0A;

/// Start byte of a configuration message
const CONFIGURATION: u8 = 0xA9;

/// Start byte of IPv4 packet range
const IP4_FROM: u8 = 0x45;

/// Final start byte of IPv4 packet range
const IP4_TO: u8 = 0x4F;

/// Start byte of IPv6 packet range
const IP6_FROM: u8 = 0x60;

/// Final start byte of IPv6 packet range
const IP6_TO: u8 = 0x6F;

/// The frame types that Slipmux offers
#[derive(Debug)]
pub enum Slipmux {
    /// A diagnostic frame.
    Diagnostic(String),
    /// A configuration frame, should contain a coap packet but that is not guaranteed.
    Configuration(Vec<u8>),
    /// An IPv4/6 packet frame.
    Packet(Vec<u8>),
}

/// Errors encountered in Slipmux.
#[derive(Debug)]
pub enum Error {
    // Encoder errors
    /// The encoder does not have enough space to write your frame.
    NotEnoughSpace,

    // Decoder errors
    /// The decoder encountered an invalid frame, e.g. a bad escape sequence.
    BadFraming,
    /// The decoder encountered an unkown frame type.
    BadFrameType,
}

/// Short hand for `encode(Slipmux::Diagnostic(text.to_owned()))`
#[must_use]
pub fn encode_diagnostic(text: &str) -> ([u8; 256], usize) {
    encode(Slipmux::Diagnostic(text.to_owned()))
}

/// Short hand for `encode(Slipmux::Configuration(packet))`
#[must_use]
pub fn encode_configuration(packet: Vec<u8>) -> ([u8; 256], usize) {
    encode(Slipmux::Configuration(packet))
}

/// Short hand for `encode(Slipmux::Packet(packet))`
#[must_use]
pub fn encode_packet(packet: Vec<u8>) -> ([u8; 256], usize) {
    encode(Slipmux::Packet(packet))
}

/// Encodes `Slipmux` data into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into 256 byte buffer.
#[must_use]
pub fn encode(input: Slipmux) -> ([u8; 256], usize) {
    let mut buffer = [0; 256];
    let mut slip = Encoder::new();
    let mut totals = EncodeTotals {
        read: 0,
        written: 0,
    };
    match input {
        Slipmux::Diagnostic(s) => {
            totals += slip.encode(&[DIAGNOSTIC], &mut buffer).unwrap();
            totals += slip
                .encode(s.as_bytes(), &mut buffer[totals.written..])
                .unwrap();
        }
        Slipmux::Configuration(mut conf) => {
            conf.insert(0, CONFIGURATION);
            let fcs = fcs16(&conf);
            conf.extend_from_slice(&fcs.to_le_bytes());
            totals += slip.encode(&conf, &mut buffer).unwrap();
        }
        Slipmux::Packet(packet) => {
            totals += slip.encode(&packet, &mut buffer[totals.written..]).unwrap();
        }
    }
    totals += slip.finish(&mut buffer[totals.written..]).unwrap();
    (buffer, totals.written)
}

enum DecoderState {
    Fin(Result<Slipmux, Error>, usize),
    DecodeError(Error),
    Skip,
    Incomplete,
}

/// Slipmux decoder context
pub struct Decoder {
    slip: serial_line_ip::Decoder,
    index: usize,
    buffer: [u8; 10240],
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Create a new context for the slipmux decoder
    ///
    /// # Panics
    ///
    /// Will panic if the underlying decoder context can not be created.
    #[must_use]
    pub fn new() -> Self {
        let mut decoder = serial_line_ip::Decoder::new();
        let mut buffer = [0; 10240];
        decoder.decode(&[END], &mut buffer).unwrap();
        Self {
            slip: decoder,
            index: 0,
            buffer,
        }
    }

    fn reset(&mut self) {
        self.slip = serial_line_ip::Decoder::new();
        self.slip.decode(&[END], &mut self.buffer).unwrap();
        self.index = 0;
    }

    /// Decode an input slice into a vector of Slipmux frames
    ///
    /// Returns a vector of frames.
    /// Length of the vector might be zero, for example when a frame is started but not
    /// completed in the given input. In this case, call `decode()` again once new
    /// input data is available.
    pub fn decode(&mut self, input: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut result_vec = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let used_bytes = {
                match self.decode_partial(&input[offset..]) {
                    DecoderState::Fin(data, bytes_consumed) => {
                        result_vec.push(data);
                        bytes_consumed
                    }
                    DecoderState::DecodeError(err) => {
                        result_vec.push(Err(err));
                        break;
                    }
                    DecoderState::Incomplete => input.len(),
                    DecoderState::Skip => 1,
                }
            };
            offset += used_bytes;
        }
        result_vec
    }

    fn decode_partial(&mut self, input: &[u8]) -> DecoderState {
        let partial_result = self.slip.decode(input, &mut self.buffer[self.index..]);

        match partial_result {
            Err(SlipError::NoOutputSpaceForHeader | SlipError::NoOutputSpaceForEndByte) => {
                return DecoderState::DecodeError(Error::NotEnoughSpace);
            }
            Err(SlipError::BadHeaderDecode | SlipError::BadEscapeSequenceDecode) => {
                return DecoderState::DecodeError(Error::BadFraming);
            }
            _ => (),
        }

        let (used_bytes_from_input, out, end) = partial_result.unwrap();
        self.index += out.len();
        if end && self.index == 0 {
            return DecoderState::Skip;
        }
        if end {
            let retval = {
                match self.buffer[0] {
                    DIAGNOSTIC => {
                        let s = String::from_utf8_lossy(&self.buffer[1..self.index]).to_string();
                        Ok(Slipmux::Diagnostic(s))
                    }
                    CONFIGURATION => {
                        // Check the checksum, which is two bytes long and we don't pass it further
                        if check_fcs(&self.buffer[0..self.index]) {
                            Ok(Slipmux::Configuration(
                                self.buffer[1..self.index - 2].to_vec(),
                            ))
                        } else {
                            Err(Error::BadFraming)
                        }
                    }
                    IP4_FROM..IP4_TO | IP6_FROM..IP6_TO => {
                        Ok(Slipmux::Packet(self.buffer[0..self.index].to_vec()))
                    }
                    _ => Err(Error::BadFrameType),
                }
            };

            self.reset();
            DecoderState::Fin(retval, used_bytes_from_input)
        } else {
            assert!(used_bytes_from_input == input.len());
            DecoderState::Incomplete
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap_lite::Packet;

    #[test]
    fn encode_simple_diagnostic() {
        let (result, length) = encode_diagnostic("Hello World!");
        assert_eq!(result[..length], *b"\xc0\x0aHello World!\xc0");
        let (result, length) = encode_diagnostic("Yes, I would like one \x0a please.");
        assert_eq!(
            result[..length],
            *b"\xc0\x0aYes, I would like one \x0a please.\xc0"
        );
    }

    #[test]
    fn encode_wrapper_diagnostic() {
        let (result, length) = encode_diagnostic("");
        assert_eq!(result[..length], *b"\xc0\x0a\xc0");
    }

    #[test]
    fn encode_wrapper_configuration() {
        let (result, length) = encode_configuration(Packet::new().to_bytes().unwrap());
        assert_eq!(
            result[..length],
            [END, CONFIGURATION, 0x40, 0x01, 0x00, 0x00, 0xbc, 0x38, END]
        );
    }

    #[test]
    fn encode_direct() {
        let input = Slipmux::Diagnostic("Hello World!".to_owned());
        let (result, length) = encode(input);
        assert_eq!(result[..length], *b"\xc0\x0aHello World!\xc0");

        let input = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
        let (result, length) = encode(input);
        assert_eq!(
            result[..length],
            [END, CONFIGURATION, 0x40, 0x01, 0x00, 0x00, 0xbc, 0x38, END]
        );
    }

    #[test]
    fn decode_diagnostic() {
        const SLIPMUX_ENCODED: [u8; 15] = [
            END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        match frame.unwrap() {
            Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_configuration() {
        const SLIPMUX_ENCODED: [u8; 17] = [
            END,
            CONFIGURATION,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x57,
            0x6f,
            0x72,
            0x6c,
            0x64,
            0x21,
            0x49,
            0xff,
            END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        match frame.unwrap() {
            Slipmux::Configuration(s) => assert_eq!(s, b"Hello World!"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_no_leading_deliminator() {
        const SLIPMUX_ENCODED: [u8; 14] = [
            DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        match frame.unwrap() {
            Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_ignore_empty_frames() {
        const SLIPMUX_ENCODED: [u8; 19] = [
            END, END, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
            0x64, 0x21, END, END, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        match frame.unwrap() {
            Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_only_one_end_byte_frames() {
        // Contains three hello world!s
        const SLIPMUX_ENCODED: [u8; 43] = [
            END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
            0x64, 0x21, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72,
            0x6c, 0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        for input_slice in SLIPMUX_ENCODED.chunks(3) {
            for slipframe in slipmux.decode(input_slice) {
                match slipframe {
                    Ok(Slipmux::Diagnostic(s)) => {
                        assert_eq!(s, "Hello World!");
                    }
                    Ok(Slipmux::Configuration(_conf)) => {
                        // Do stuff
                    }
                    Ok(Slipmux::Packet(_packet)) => {
                        // Do stuff
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn decode_unkown_frametype() {
        const SLIPMUX_ENCODED: [u8; 15] = [
            END, 0x50, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        assert!(frame.is_err());
        match frame {
            Err(Error::BadFrameType) => {} // expected case
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_stream_with_unkown_frametype_inbetween() {
        // Contains three hello world!s
        const SLIPMUX_ENCODED: [u8; 45] = [
            END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END, END, 0x50, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
            0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let frames = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Ok(Slipmux::Diagnostic(_))));
        assert!(matches!(frames[1], Err(Error::BadFrameType)));
        assert!(matches!(frames[2], Ok(Slipmux::Diagnostic(_))));
    }

    #[test]
    fn decode_stream() {
        // Contains three hello world!s
        const SLIPMUX_ENCODED: [u8; 45] = [
            END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
            0x64, 0x21, END, END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72,
            0x6c, 0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        for input_slice in SLIPMUX_ENCODED.chunks(4) {
            for slipframe in slipmux.decode(input_slice) {
                match slipframe {
                    Ok(Slipmux::Diagnostic(s)) => {
                        assert_eq!(s, "Hello World!");
                    }
                    Ok(Slipmux::Configuration(_conf)) => {
                        // Do stuff
                    }
                    Ok(Slipmux::Packet(_packet)) => {
                        // Do stuff
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn encode_decode_all_frametypes() {
        let mut stream = vec![];
        let input_diagnostic = Slipmux::Diagnostic("Hello World!".to_owned());
        let (result, length) = encode(input_diagnostic);
        stream.extend_from_slice(&result[..length]);

        let input_configuration = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
        let (result, length) = encode(input_configuration);
        stream.extend_from_slice(&result[..length]);

        let input_packet = Slipmux::Packet(vec![0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80]);
        let (result, length) = encode(input_packet);
        stream.extend_from_slice(&result[..length]);

        let mut slipmux = Decoder::new();
        let frames = slipmux.decode(&stream);
        assert_eq!(3, frames.len());
        for slipframe in frames {
            match slipframe {
                Ok(Slipmux::Diagnostic(s)) => {
                    assert_eq!(s, "Hello World!");
                }
                Ok(Slipmux::Configuration(conf)) => {
                    assert_eq!(conf, Packet::new().to_bytes().unwrap());
                }
                Ok(Slipmux::Packet(packet)) => {
                    assert_eq!(packet, vec![0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80]);
                }
                Err(_) => unreachable!(),
            }
        }
    }

    #[test]
    fn encode_decode_ip() {
        const IP4_FOO: [u8; 124] = [
            0x45, 0x00, 0x00, 0x7c, 0x44, 0xcd, 0x40, 0x00, 0x40, 0x06, 0x96, 0x57, 0x8d, 0x16,
            0x1c, 0x31, 0x68, 0x14, 0x4d, 0xfc, 0xa6, 0x1c, 0x01, 0xbb, 0xb2, 0xb2, 0xfc, 0xee,
            0x81, 0xf0, 0x38, 0xfd, 0x80, 0x18, 0x26, 0x70, 0x5f, 0xc6, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0xb0, 0x74, 0xff, 0x78, 0x39, 0x26, 0x09, 0xb2, 0x17, 0x03, 0x03, 0x00,
            0x43, 0x81, 0x0d, 0xf1, 0x55, 0xb4, 0x9b, 0xcc, 0xb6, 0xd3, 0xcc, 0x91, 0x02, 0x27,
            0x33, 0xef, 0x55, 0x88, 0x75, 0x7f, 0x18, 0x07, 0x01, 0xba, 0x6f, 0x89, 0xd8, 0x30,
            0xfc, 0x3a, 0x9f, 0xc8, 0x66, 0xa4, 0xf4, 0x77, 0x71, 0x2c, 0xac, 0xc2, 0xbc, 0x06,
            0x45, 0x00, 0x20, 0x48, 0xbe, 0xda, 0x93, 0x23, 0xf3, 0xf5, 0x23, 0xfb, 0x4c, 0x26,
            0x13, 0xcf, 0x97, 0xdf, 0x09, 0x1e, 0x01, 0x7c, 0x98, 0xc1, 0xf2, 0xea,
        ];

        const IP4_BAR: [u8; 90] = [
            0x45, 0x00, 0x00, 0x5a, 0x3f, 0x6a, 0x40, 0x00, 0x40, 0x06, 0x4f, 0x4e, 0x8d, 0x16,
            0x1c, 0x31, 0x41, 0x6c, 0xc1, 0x32, 0xde, 0x8c, 0x01, 0xbb, 0xd8, 0x6c, 0xbb, 0x32,
            0x1a, 0x93, 0x1f, 0x83, 0x80, 0x18, 0x30, 0xf3, 0xac, 0x32, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x46, 0x9d, 0x99, 0x43, 0x16, 0x9f, 0x1e, 0xf2, 0x17, 0x03, 0x03, 0x00,
            0x21, 0xa2, 0x2b, 0xbf, 0x36, 0xaa, 0x63, 0x47, 0x6d, 0xcf, 0xe6, 0x30, 0x6e, 0xb7,
            0x79, 0x28, 0x49, 0x42, 0x3e, 0x7f, 0xc1, 0xb4, 0x80, 0x09, 0x5a, 0xd2, 0x63, 0x16,
            0x35, 0x4a, 0xe5, 0x98, 0xf8, 0x70,
        ];

        const IP6_FOO: [u8; 147] = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x11, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x1a, 0xe8, 0xff, 0xfe, 0x96, 0xa1, 0xd7, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22,
            0x02, 0x23, 0x00, 0x6b, 0xc0, 0x0a, 0x01, 0xb0, 0x49, 0x0e, 0x00, 0x01, 0x00, 0x0a,
            0x00, 0x03, 0x00, 0x01, 0x00, 0x1a, 0xe8, 0x96, 0xa1, 0xd7, 0x00, 0x06, 0x00, 0x0e,
            0x00, 0x17, 0x00, 0x18, 0x00, 0x1f, 0x00, 0x11, 0x00, 0x15, 0x00, 0x16, 0x00, 0x27,
            0x00, 0x08, 0x00, 0x02, 0xff, 0xff, 0x00, 0x10, 0x00, 0x11, 0x00, 0x00, 0x80, 0x24,
            0x00, 0x0b, 0x4f, 0x70, 0x74, 0x69, 0x49, 0x70, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x00,
            0x27, 0x00, 0x10, 0x01, 0x0d, 0x34, 0x39, 0x34, 0x30, 0x34, 0x32, 0x38, 0x37, 0x35,
            0x38, 0x35, 0x34, 0x35, 0x00, 0x00, 0x03, 0x00, 0x0c, 0xe8, 0x96, 0xa1, 0xd7, 0x00,
            0x00, 0x0e, 0x10, 0x00, 0x00, 0x15, 0x18,
        ];

        const IP6_BAR: [u8; 105] = [
            0x60, 0x0d, 0xda, 0x0e, 0x00, 0x41, 0x11, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x45, 0x45, 0xbc, 0x0d, 0x6f, 0x88, 0x2f, 0x17, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22,
            0x02, 0x23, 0x00, 0x41, 0x84, 0xbe, 0x0b, 0xe1, 0x3f, 0x99, 0x00, 0x01, 0x00, 0x0e,
            0x00, 0x01, 0x00, 0x01, 0x23, 0xfd, 0xc5, 0x32, 0x50, 0x9a, 0x4c, 0xb3, 0x04, 0xfe,
            0x00, 0x06, 0x00, 0x0a, 0x00, 0x11, 0x00, 0x20, 0x00, 0x17, 0x00, 0x18, 0x00, 0x27,
            0x00, 0x08, 0x00, 0x02, 0xff, 0xff, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x00, 0x02, 0xa2,
            0x00, 0x05, 0x69, 0x44, 0x52, 0x41, 0x43,
        ];

        let (result, length) = encode_packet(IP4_FOO.to_vec());
        assert_eq!(length, 126);
        let mut slipmux = Decoder::new();
        // Pop should be safe as we expect exactly one frame
        let decoded = slipmux.decode(&result[..length]).pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip4_foo) => assert_eq!(decoded_ip4_foo, IP4_FOO),
            _ => unreachable!(),
        }

        let (result, length) = encode_packet(IP4_BAR.to_vec());
        assert_eq!(length, 92);
        let mut slipmux = Decoder::new();
        // Pop should be safe as we expect exactly one frame
        let decoded = slipmux.decode(&result[..length]).pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip4_bar) => assert_eq!(decoded_ip4_bar, IP4_BAR),
            _ => unreachable!(),
        }

        let (result, length) = encode_packet(IP6_FOO.to_vec());
        // On byte extra to escape a 0xc0 / END
        assert_eq!(length, 150);
        let mut slipmux = Decoder::new();
        // Pop should be safe as we expect exactly one frame
        let decoded = slipmux.decode(&result[..length]).pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip6_foo) => assert_eq!(decoded_ip6_foo, IP6_FOO),
            _ => unreachable!(),
        }

        let (result, length) = encode_packet(IP6_BAR.to_vec());
        assert_eq!(length, 107);
        let mut slipmux = Decoder::new();
        // Pop should be safe as we expect exactly one frame
        let decoded = slipmux.decode(&result[..length]).pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip6_bar) => assert_eq!(decoded_ip6_bar, IP6_BAR),
            _ => unreachable!(),
        }
    }
}
