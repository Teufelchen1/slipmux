use crate::Error;
use crate::Slipmux;
use crate::decoder_no_std::FrameType;

use crate::decoder_no_std::FrameHandler;

/// A simple handler for the `Decoder::decode()` function.
///
/// It tracks the current frame type and writes all bytes into the matching buffer.
/// The buffers can directly be read by the handlers owner. The owner is also responsible
/// for clearing the buffer when a frame is completed.
pub struct SimpleFrameHandler {
    frame_type: FrameType,
    /// Stores the current diagnostic frame
    pub diagnostic_buffer: Vec<u8>,
    /// Stores the current configuration frame
    pub configuration_buffer: Vec<u8>,
    /// Stores the current IP packet
    pub packet_buffer: Vec<u8>,
}

impl SimpleFrameHandler {
    /// Creates a new handler
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frame_type: FrameType::Diagnostic,
            diagnostic_buffer: vec![],
            configuration_buffer: vec![],
            packet_buffer: vec![],
        }
    }
}

impl Default for SimpleFrameHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameHandler for SimpleFrameHandler {
    fn begin_frame(&mut self, frame_type: FrameType) {
        self.frame_type = frame_type;
    }

    fn write_byte(&mut self, byte: u8) {
        match &self.frame_type {
            FrameType::Diagnostic => {
                self.diagnostic_buffer.push(byte);
            }
            FrameType::Configuration => {
                self.configuration_buffer.push(byte);
            }
            FrameType::Ip => {
                self.packet_buffer.push(byte);
            }
        }
    }

    fn end_frame(&mut self, _: Option<Error>) {}
}

/// A buffered handler for the `Decoder::decode()` function.
///
/// It collects completed frames in the `.results` vector. The owner is responsible
/// for clearing this vector if needed.
pub struct BufferedFrameHandler {
    frame_type: FrameType,
    diagnostic_buffer: Vec<u8>,
    configuration_buffer: Vec<u8>,
    packet_buffer: Vec<u8>,
    /// Contains completed frames
    pub results: Vec<Result<Slipmux, Error>>,
}

impl BufferedFrameHandler {
    /// Creates a new hander
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frame_type: FrameType::Diagnostic,
            diagnostic_buffer: vec![],
            configuration_buffer: vec![],
            packet_buffer: vec![],
            results: vec![],
        }
    }
}

impl Default for BufferedFrameHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameHandler for BufferedFrameHandler {
    fn begin_frame(&mut self, frame_type: FrameType) {
        self.frame_type = frame_type;
    }

    fn write_byte(&mut self, byte: u8) {
        match &self.frame_type {
            FrameType::Diagnostic => {
                self.diagnostic_buffer.push(byte);
            }
            FrameType::Configuration => {
                self.configuration_buffer.push(byte);
            }
            FrameType::Ip => {
                self.packet_buffer.push(byte);
            }
        }
    }

    fn end_frame(&mut self, error: Option<Error>) {
        match error {
            None => match self.frame_type {
                FrameType::Diagnostic => {
                    self.results.push(Ok(Slipmux::Diagnostic(
                        String::from_utf8_lossy(&self.diagnostic_buffer).to_string(),
                    )));
                    self.diagnostic_buffer.clear();
                }
                FrameType::Configuration => {
                    self.configuration_buffer
                        .truncate(self.configuration_buffer.len() - 2);
                    self.results.push(Ok(Slipmux::Configuration(
                        self.configuration_buffer.clone(),
                    )));
                }
                FrameType::Ip => self
                    .results
                    .push(Ok(Slipmux::Packet(self.configuration_buffer.clone()))),
            },
            Some(e) => {
                self.results.push(Err(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BufferedDecoder;
    use crate::Constants;
    use crate::DecodeStatus;
    use crate::Decoder;
    use crate::Slipmux;
    use crate::encode;
    use crate::framehandler::BufferedFrameHandler;
    use crate::framehandler::SimpleFrameHandler;
    use coap_lite::Packet;

    fn simple_frame_handler_wrapper(data: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut slipmux = Decoder::new();
        let mut handler = SimpleFrameHandler::new();
        let mut results: Vec<Result<Slipmux, Error>> = vec![];
        for byte in data {
            match slipmux.decode(*byte, &mut handler) {
                DecodeStatus::Incomplete => {}
                DecodeStatus::FrameCompleteDiagnostic => {
                    results.push(Ok(Slipmux::Diagnostic(
                        String::from_utf8_lossy(&handler.diagnostic_buffer).to_string(),
                    )));
                    handler.diagnostic_buffer.clear();
                }
                DecodeStatus::FrameCompleteConfiguration => {
                    // Drop the FCS at the end
                    handler
                        .configuration_buffer
                        .truncate(handler.configuration_buffer.len() - 2);
                    results.push(Ok(Slipmux::Configuration(
                        handler.configuration_buffer.clone(),
                    )));
                    handler.configuration_buffer.clear();
                }
                DecodeStatus::FrameCompleteIp => {
                    results.push(Ok(Slipmux::Packet(handler.packet_buffer.clone())));
                    handler.packet_buffer.clear();
                }
                DecodeStatus::Error(err) => {
                    results.push(Err(err));
                }
            }
        }
        results
    }

    fn buffered_frame_handler_wrapper(data: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut slipmux = Decoder::new();
        let mut handler = BufferedFrameHandler::new();
        for byte in data {
            slipmux.decode(*byte, &mut handler);
        }
        handler.results
    }

    fn buffered_decoder_wrapper(data: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut slipmux = BufferedDecoder::new();
        slipmux.decode(data)
    }

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
        let mut handler = SimpleFrameHandler::new();
        for (index, byte) in buffer[..length].iter().enumerate() {
            let result = slipmux.decode(*byte, &mut handler);
            match result {
                DecodeStatus::FrameCompleteConfiguration => {
                    // Drop the FCS at the end
                    handler
                        .configuration_buffer
                        .truncate(handler.configuration_buffer.len() - 2);
                }
                DecodeStatus::FrameCompleteIp
                | DecodeStatus::FrameCompleteDiagnostic
                | DecodeStatus::Incomplete => {}
                DecodeStatus::Error(_err) => {}
            }
            if index == 15 {
                assert_eq!(handler.diagnostic_buffer, b"Hello World!");
            }
            if index == 24 {
                assert_eq!(
                    handler.configuration_buffer,
                    Packet::new().to_bytes().unwrap()
                );
            }
        }
    }

    #[test]
    fn diagnostic() {
        const SLIPMUX_ENCODED: [u8; 15] = [
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
        ];

        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn configuration() {
        const SLIPMUX_ENCODED: [u8; 17] = [
            Constants::END,
            Constants::CONFIGURATION,
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
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Configuration(s) => assert_eq!(s, b"Hello World!"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn configuration_wrong_fcs() {
        const SLIPMUX_ENCODED: [u8; 17] = [
            Constants::END,
            Constants::CONFIGURATION,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x21,
            0x57,
            0x6f,
            0x72,
            0x6c,
            0x64,
            0x21,
            0x49,
            0xff,
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            assert!(matches!(frame, Err(Error::BadFCS(_))));
        }
    }

    #[test]
    fn no_leading_deliminator() {
        const SLIPMUX_ENCODED: [u8; 14] = [
            Constants::DIAGNOSTIC,
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
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn ignore_empty_frames() {
        const SLIPMUX_ENCODED: [u8; 19] = [
            Constants::END,
            Constants::END,
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
            Constants::END,
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(s) => assert_eq!(s, "Hello World!"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn only_one_end_byte_frames() {
        // Contains three hello world!s
        const SLIPMUX_ENCODED: [u8; 43] = [
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
        ];

        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for results in results_arr {
            for slipframe in results {
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
    fn unkown_frametype() {
        const SLIPMUX_ENCODED: [u8; 15] = [
            Constants::END,
            0x50,
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
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            assert!(frame.is_err());
            match frame {
                Err(Error::BadFrameType(0x50)) => {} // expected case
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn stream_with_unkown_frametype_inbetween() {
        // Contains three hello world!s
        const SLIPMUX_ENCODED: [u8; 45] = [
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
            Constants::END,
            0x50,
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
            Constants::END,
            Constants::END,
            Constants::DIAGNOSTIC,
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
            Constants::END,
        ];
        let results_arr = [
            buffered_frame_handler_wrapper(&SLIPMUX_ENCODED),
            simple_frame_handler_wrapper(&SLIPMUX_ENCODED),
            buffered_decoder_wrapper(&SLIPMUX_ENCODED),
        ];
        for frames in results_arr {
            assert_eq!(frames.len(), 3);
            assert!(matches!(frames[0], Ok(Slipmux::Diagnostic(_))));
            assert!(matches!(frames[1], Err(Error::BadFrameType(0x50))));
            assert!(matches!(frames[2], Ok(Slipmux::Diagnostic(_))));
        }
    }
}
