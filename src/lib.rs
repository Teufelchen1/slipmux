//! Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer
//!
//! Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).
//!
//! Note: Currently no checksumming on the configuration frames implemented!
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
//!     _ => assert!(false),
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
#![allow(clippy::missing_panics_doc)]
use coap_lite::Packet;
use serial_line_ip::EncodeTotals;
use serial_line_ip::Encoder;
use serial_line_ip::Error;

/// Ends a frame
const END: u8 = 0xC0;

/// Start byte of a diagnostic frame
const DIAGNOSTIC: u8 = 0x0A;

/// Start byte of a configuration message
const CONFIGURATION: u8 = 0xA9;

#[must_use]
pub fn encode_diagnostic(text: &str) -> ([u8; 256], usize) {
    encode(Slipmux::Diagnostic(text.to_string()))
}

#[must_use]
pub fn encode_configuration(packet: &Packet) -> ([u8; 256], usize) {
    encode(Slipmux::Configuration(packet.to_bytes().unwrap()))
}

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

pub enum Slipmux {
    Diagnostic(String),
    Configuration(Vec<u8>),
    Packet(Vec<u8>),
}

enum SlipmuxState {
    Fin(Result<Slipmux, Error>, usize),
    Error(Error),
    Skip(),
    Incomplete(),
}

pub struct Decoder {
    slip_decoder: serial_line_ip::Decoder,
    index: usize,
    buffer: [u8; 10240],
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    #[must_use]
    pub fn new() -> Self {
        let mut decoder = serial_line_ip::Decoder::new();
        let mut buffer = [0; 10240];
        decoder.decode(&[END], &mut buffer).unwrap();
        Self {
            slip_decoder: decoder,
            index: 0,
            buffer,
        }
    }

    fn reset(&mut self) {
        self.slip_decoder = serial_line_ip::Decoder::new();
        self.slip_decoder.decode(&[END], &mut self.buffer).unwrap();
        self.index = 0;
    }

    pub fn decode(&mut self, input: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut result_vec = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let used_bytes = {
                match self.decode_partial(&input[offset..]) {
                    SlipmuxState::Fin(data, bytes_consumed) => {
                        result_vec.push(data);
                        bytes_consumed
                    }
                    SlipmuxState::Error(err) => {
                        result_vec.push(Err(err));
                        break;
                    }
                    SlipmuxState::Incomplete() => input.len(),
                    SlipmuxState::Skip() => 1,
                }
            };
            offset += used_bytes;
        }
        result_vec
    }

    fn decode_partial(&mut self, input: &[u8]) -> SlipmuxState {
        let partial_result = self
            .slip_decoder
            .decode(input, &mut self.buffer[self.index..]);

        if let Err(err) = partial_result {
            return SlipmuxState::Error(err);
        }
        let (used_bytes_from_input, out, end) = partial_result.unwrap();
        self.index += out.len();
        if end && self.index == 0 {
            return SlipmuxState::Skip();
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
                    _ => Ok(Slipmux::Packet(self.buffer[1..self.index].to_vec())),
                }
            };

            self.reset();
            SlipmuxState::Fin(retval, used_bytes_from_input)
        } else {
            assert!(used_bytes_from_input == input.len());
            SlipmuxState::Incomplete()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (result, length) = encode_configuration(&Packet::new());
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
            _ => assert!(false),
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
            _ => assert!(false),
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
            _ => assert!(false),
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
            for slipframe in slipmux.decode(&input_slice) {
                if slipframe.is_err() {
                    panic!();
                }
                match slipframe.unwrap() {
                    Slipmux::Diagnostic(s) => {
                        assert_eq!(s, "Hello World!")
                    }
                    Slipmux::Configuration(_conf) => {
                        // Do stuff
                    }
                    Slipmux::Packet(_packet) => {
                        // Do stuff
                    }
                }
            }
        }
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
            for slipframe in slipmux.decode(&input_slice) {
                if slipframe.is_err() {
                    panic!();
                }
                match slipframe.unwrap() {
                    Slipmux::Diagnostic(s) => {
                        assert_eq!(s, "Hello World!")
                    }
                    Slipmux::Configuration(_conf) => {
                        // Do stuff
                    }
                    Slipmux::Packet(_packet) => {
                        // Do stuff
                    }
                }
            }
        }
    }
}
