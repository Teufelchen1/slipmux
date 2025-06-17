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
//! Alternatively, use the helper functions `encode_diagnostic()`, `encode_configurtation()` and `encode_packet()`.
//!
//! ```
//! use slipmux::Slipmux;
//! use slipmux::encode;
//! use coap_lite::Packet;
//!
//! let mut buffer: [u8; 2048] = [0; 2048];
//! let input = Slipmux::Diagnostic("Hello World!".to_owned());
//! let length = encode(input, &mut buffer);
//! assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");
//!
//! let input = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
//! let length = encode(input, &mut buffer);
//! assert_eq!(buffer[..length], [0xc0, 0xa9, 0x40, 0x01, 0x00, 0x00, 0xbc, 0x38, 0xc0]);
//! ```
//!
//! ### Decoding
//!
//! Since the length and number of frames in a data stream (byte slice)
//! is unknown upfront, the decoder retains a state even after finishing decoding
//! the input. This enables to repeatedly call the decoder with new input data and
//! if a frame is split between two or more calls, the decoder will correctly concat the frame.
//!
//! The decoded bytes of a frame are passed to a `FrameHandler`. The user has to provide a handler either
//! by implementing one themselves or use one of the provided generic implementations. This example uses
//! the `BufferedFrameHandler` which is characterized by collecting all frames and errors in to a result
//! vector of type `Vec<Result<Slipmux, Error>>`.
//! ```
//! use slipmux::Slipmux;
//! use slipmux::Decoder;
//! use slipmux::BufferedFrameHandler;
//!
//! const SLIPMUX_ENCODED: [u8; 15] = [
//!     0xc0, 0x0a,
//!     0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
//!     0xc0
//! ];
//!
//! let mut slipmux = Decoder::new();
//! let mut handler = BufferedFrameHandler::new();
//! for byte in &SLIPMUX_ENCODED {
//!     let _: Result<slipmux::DecodeStatus, slipmux::Error> = slipmux.decode(*byte, &mut handler);
//! }
//! let mut results = handler.results;
//! assert_eq!(results.len(), 1);
//! let frame = results.pop().unwrap();
//! assert!(frame.is_ok());
//! match frame.unwrap() {
//!     Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
//!     _ => panic!(),
//! }
//!
//! ```

mod checksum;
mod decoder;
mod encode;
mod framehandler;

pub use encode::encode;
pub use encode::encode_configuration;
pub use encode::encode_diagnostic;
pub use encode::encode_packet;

pub use decoder::DecodeStatus;
pub use decoder::Decoder;
pub use decoder::FrameHandler;

pub use framehandler::BufferedFrameHandler;
pub use framehandler::OwnedLatestFrame;

/// Magic byte constants used in Slipmux
#[non_exhaustive]
pub struct Constants;

impl Constants {
    /// Ends a frame
    pub const END: u8 = 0xC0;

    /// Frame escape
    pub const ESC: u8 = 0xDB;

    /// Escaped frame end
    pub const ESC_END: u8 = 0xDC;

    /// Escaped frame escape
    pub const ESC_ESC: u8 = 0xDD;

    /// Start byte of a diagnostic frame
    pub const DIAGNOSTIC: u8 = 0x0A;

    /// Start byte of a configuration message
    pub const CONFIGURATION: u8 = 0xA9;

    /// Start byte of IPv4 packet range
    pub const IP4_FROM: u8 = 0x45;

    /// Final start byte of IPv4 packet range
    pub const IP4_TO: u8 = 0x4F;

    /// Start byte of IPv6 packet range
    pub const IP6_FROM: u8 = 0x60;

    /// Final start byte of IPv6 packet range
    pub const IP6_TO: u8 = 0x6F;
}

/// The frame types that Slipmux offers
#[derive(Debug)]
pub enum Slipmux {
    /// A diagnostic frame.
    Diagnostic(String),
    /// A configuration frame without the FCS.
    ///
    /// Should contain a CoAP packet but that is not guaranteed.
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
    BadFrameType(u8),
    /// The frame checksum was invalid.
    BadFCS(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap_lite::Packet;

    #[test]
    fn encode_decode_all_frametypes() {
        let mut buffer: [u8; 2048] = [0; 2048];

        let input_diagnostic = Slipmux::Diagnostic("Hello World!".to_owned());
        let mut length = encode(input_diagnostic, &mut buffer);

        let input_configuration = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
        length += encode(input_configuration, &mut buffer[length..]);

        let input_packet = Slipmux::Packet(vec![0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80]);
        length += encode(input_packet, &mut buffer[length..]);

        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in &buffer[..length] {
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        let frames = handler.results;
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

        let mut buffer: [u8; 2048] = [0; 2048];

        let length = encode_packet(IP4_FOO.to_vec(), &mut buffer);
        assert_eq!(length, 126);
        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in &buffer[..length] {
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        let mut frames = handler.results;
        // Pop should be safe as we expect exactly one frame
        let decoded = frames.pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip4_foo) => assert_eq!(decoded_ip4_foo, IP4_FOO),
            _ => unreachable!(),
        }

        let length = encode_packet(IP4_BAR.to_vec(), &mut buffer);
        assert_eq!(length, 92);
        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in &buffer[..length] {
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        let mut frames = handler.results;
        // Pop should be safe as we expect exactly one frame
        let decoded = frames.pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip4_bar) => assert_eq!(decoded_ip4_bar, IP4_BAR),
            _ => unreachable!(),
        }

        let length = encode_packet(IP6_FOO.to_vec(), &mut buffer);
        // On byte extra to escape a 0xc0 / END
        assert_eq!(length, 150);
        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in &buffer[..length] {
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        let mut frames = handler.results;
        // Pop should be safe as we expect exactly one frame
        let decoded = frames.pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip6_foo) => assert_eq!(decoded_ip6_foo, IP6_FOO),
            _ => unreachable!(),
        }

        let length = encode_packet(IP6_BAR.to_vec(), &mut buffer);
        assert_eq!(length, 107);
        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in &buffer[..length] {
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        let mut frames = handler.results;
        // Pop should be safe as we expect exactly one frame
        let decoded = frames.pop().unwrap();
        match decoded.unwrap() {
            Slipmux::Packet(decoded_ip6_bar) => assert_eq!(decoded_ip6_bar, IP6_BAR),
            _ => unreachable!(),
        }
    }
}
