//! Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer
//!
//! Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).
//!
//! Note: Currently no checksumming on the configuration frames, and no frame aborting is implemented!
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
//! assert_eq!(result[..length], [0xc0, 0xa9, 0x40, 0x01, 0x00, 0x00, 0xc0]);
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
use serial_line_ip::EncodeTotals;
use serial_line_ip::Encoder;
use serial_line_ip::Error as SlipError;

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
        Slipmux::Configuration(conf) => {
            totals += slip.encode(&[CONFIGURATION], &mut buffer).unwrap();
            totals += slip.encode(&conf, &mut buffer[totals.written..]).unwrap();
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
                        Ok(Slipmux::Configuration(self.buffer[1..self.index].to_vec()))
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
    fn encode_empty_diagnostic() {
        let (result, length) = encode_diagnostic("");
        assert_eq!(result[..length], *b"\xc0\x0a\xc0");
    }

    #[test]
    fn encode_simple_configuration() {
        let (result, length) = encode_configuration(Packet::new().to_bytes().unwrap());
        assert_eq!(
            result[..length],
            [END, CONFIGURATION, 0x40, 0x01, 0x00, 0x00, END]
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
            [END, CONFIGURATION, 0x40, 0x01, 0x00, 0x00, END]
        );
    }

    #[test]
    fn decode_simple() {
        const SLIPMUX_ENCODED: [u8; 15] = [
            END, DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
            0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        assert!(frame.is_ok());
        match frame.unwrap() {
            Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decode_simple_no_leading_deliminator() {
        const SLIPMUX_ENCODED: [u8; 14] = [
            DIAGNOSTIC, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, END,
        ];
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        assert!(frame.is_ok());
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
        assert!(frame.is_ok());
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
}
