use crate::Error;
use crate::FrameType;
#[cfg(feature = "std")]
use crate::Slipmux;

use crate::decoder::FrameHandler;

/// A simple `no_std` handler for the `Decoder::decode()` function.
///
/// It tracks the current frame type and writes all bytes into the matching buffer.
/// The buffers can directly be read by the handlers owner. The owner is also responsible
/// for clearing the buffer when a frame is completed.
pub struct ReferencedLatestFrame<'a> {
    /// Current offset from start of the buffer
    pub index: usize,
    frame_type: Option<FrameType>,
    /// Destination of the current diagnostic frame
    pub diagnostic_buffer: &'a mut [u8],
    /// Destination of the current configuration frame, including the FCS checksum
    pub configuration_buffer: &'a mut [u8],
    /// Destination of the current IP packet
    pub packet_buffer: &'a mut [u8],
}

impl<'a> ReferencedLatestFrame<'a> {
    /// Creates a new handler
    #[must_use]
    pub const fn new(
        diagnostic_buffer: &'a mut [u8],
        configuration_buffer: &'a mut [u8],
        packet_buffer: &'a mut [u8],
    ) -> Self {
        Self {
            index: 0,
            frame_type: None,
            diagnostic_buffer,
            configuration_buffer,
            packet_buffer,
        }
    }
}

impl FrameHandler for ReferencedLatestFrame<'_> {
    fn begin_frame(&mut self, frame_type: FrameType) {
        assert!(
            self.frame_type.is_none(),
            "Called .begin_frame when a frame was still in progress, .end_frame must be called before a new frame can be started."
        );
        self.frame_type = Some(frame_type);
        self.index = 0;
    }

    fn write_byte(&mut self, byte: u8) {
        match &self.frame_type {
            Some(FrameType::Diagnostic) => {
                self.diagnostic_buffer[self.index] = byte;
            }
            Some(FrameType::Configuration) => {
                self.configuration_buffer[self.index] = byte;
            }
            Some(FrameType::Ip) => {
                self.packet_buffer[self.index] = byte;
            }
            None => {
                panic!("Called .write_byte before .begin_frame, frame_type not set.");
            }
        }
        self.index += 1;
    }

    fn end_frame(&mut self, _: Option<Error>) {
        self.frame_type = None;
    }
}

/// A simple handler for the `Decoder::decode()` function.
///
/// It tracks the current frame type and writes all bytes into the matching buffer.
/// The buffers can directly be read by the handlers owner. The owner is also responsible
/// for clearing the buffer when a frame is completed.
#[cfg(feature = "std")]
pub struct OwnedLatestFrame {
    frame_type: Option<FrameType>,
    /// Stores the current diagnostic frame
    pub diagnostic_buffer: Vec<u8>,
    /// Stores the current configuration frame, including the FCS checksum
    pub configuration_buffer: Vec<u8>,
    /// Stores the current IP packet
    pub packet_buffer: Vec<u8>,
}

#[cfg(feature = "std")]
impl OwnedLatestFrame {
    /// Creates a new handler
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frame_type: None,
            diagnostic_buffer: vec![],
            configuration_buffer: vec![],
            packet_buffer: vec![],
        }
    }
}

#[cfg(feature = "std")]
impl Default for OwnedLatestFrame {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl FrameHandler for OwnedLatestFrame {
    fn begin_frame(&mut self, frame_type: FrameType) {
        assert!(
            self.frame_type.is_none(),
            "Called .begin_frame when a frame was still in progress, .end_frame must be called before a new frame can be started."
        );
        self.frame_type = Some(frame_type);
    }

    fn write_byte(&mut self, byte: u8) {
        match &self.frame_type {
            Some(FrameType::Diagnostic) => {
                self.diagnostic_buffer.push(byte);
            }
            Some(FrameType::Configuration) => {
                self.configuration_buffer.push(byte);
            }
            Some(FrameType::Ip) => {
                self.packet_buffer.push(byte);
            }
            None => {
                panic!("Called .write_byte before .begin_frame, frame_type not set.");
            }
        }
    }

    fn end_frame(&mut self, _: Option<Error>) {
        self.frame_type = None;
    }
}

/// A buffered handler for the `Decoder::decode()` function.
///
/// It collects completed frames in the `.results` vector. The owner is responsible
/// for clearing this vector if needed.
#[cfg(feature = "std")]
pub struct BufferedFrameHandler {
    subhandler: OwnedLatestFrame,
    /// Contains completed frames
    pub results: Vec<Result<Slipmux, Error>>,
}

#[cfg(feature = "std")]
impl BufferedFrameHandler {
    /// Creates a new hander
    #[must_use]
    pub const fn new() -> Self {
        Self {
            subhandler: OwnedLatestFrame::new(),
            results: vec![],
        }
    }
}

#[cfg(feature = "std")]
impl Default for BufferedFrameHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl FrameHandler for BufferedFrameHandler {
    fn begin_frame(&mut self, frame_type: FrameType) {
        self.subhandler.begin_frame(frame_type);
    }

    fn write_byte(&mut self, byte: u8) {
        self.subhandler.write_byte(byte);
    }

    fn end_frame(&mut self, error: Option<Error>) {
        match error {
            None => {
                if !self.subhandler.diagnostic_buffer.is_empty() {
                    self.results.push(Ok(Slipmux::Diagnostic(
                        String::from_utf8_lossy(&self.subhandler.diagnostic_buffer).to_string(),
                    )));
                    self.subhandler.diagnostic_buffer.clear();
                }
                if self.subhandler.configuration_buffer.len() > 1 {
                    self.subhandler
                        .configuration_buffer
                        .truncate(self.subhandler.configuration_buffer.len() - 2);
                    self.results.push(Ok(Slipmux::Configuration(
                        self.subhandler.configuration_buffer.clone(),
                    )));
                    self.subhandler.configuration_buffer.clear();
                }
                if !self.subhandler.packet_buffer.is_empty() {
                    self.results
                        .push(Ok(Slipmux::Packet(self.subhandler.packet_buffer.clone())));
                    self.subhandler.packet_buffer.clear();
                }
            }
            Some(error) => {
                self.results.push(Err(error));
                self.subhandler.diagnostic_buffer.clear();
                self.subhandler.configuration_buffer.clear();
                self.subhandler.packet_buffer.clear();
            }
        }
        self.subhandler.end_frame(None);
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Constants;
    use crate::DecodeStatus;
    use crate::Decoder;
    use crate::Slipmux;
    use crate::encode::encode_buffered;
    use crate::framehandler::BufferedFrameHandler;
    use crate::framehandler::OwnedLatestFrame;
    use coap_lite::Packet;

    fn owned_latest_frame_wrapper(data: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut slipmux = Decoder::new();
        let mut handler = OwnedLatestFrame::new();
        let mut results: Vec<Result<Slipmux, Error>> = vec![];
        for byte in data {
            match slipmux.decode(*byte, &mut handler) {
                Ok(DecodeStatus::Incomplete) => {}
                Ok(DecodeStatus::FrameCompleteDiagnostic) => {
                    results.push(Ok(Slipmux::Diagnostic(
                        String::from_utf8_lossy(&handler.diagnostic_buffer).to_string(),
                    )));
                    handler.diagnostic_buffer.clear();
                }
                Ok(DecodeStatus::FrameCompleteConfiguration) => {
                    // Drop the FCS at the end
                    handler
                        .configuration_buffer
                        .truncate(handler.configuration_buffer.len() - 2);
                    results.push(Ok(Slipmux::Configuration(
                        handler.configuration_buffer.clone(),
                    )));
                    handler.configuration_buffer.clear();
                }
                Ok(DecodeStatus::FrameCompleteIp) => {
                    results.push(Ok(Slipmux::Packet(handler.packet_buffer.clone())));
                    handler.packet_buffer.clear();
                }
                Err(err) => {
                    results.push(Err(err));
                }
            }
        }
        results
    }

    fn referenced_latest_frame_wrapper(data: &[u8]) -> Vec<Result<Slipmux, Error>> {
        let mut diagnostic_buffer: [u8; 64] = [0; 64];
        let mut configuration_buffer: [u8; 64] = [0; 64];
        let mut packet_buffer: [u8; 64] = [0; 64];
        let mut slipmux = Decoder::new();
        let mut handler = ReferencedLatestFrame::new(
            &mut diagnostic_buffer,
            &mut configuration_buffer,
            &mut packet_buffer,
        );
        let mut results: Vec<Result<Slipmux, Error>> = vec![];
        for byte in data {
            match slipmux.decode(*byte, &mut handler) {
                Ok(DecodeStatus::Incomplete) => {}
                Ok(DecodeStatus::FrameCompleteDiagnostic) => {
                    results.push(Ok(Slipmux::Diagnostic(
                        String::from_utf8_lossy(&handler.diagnostic_buffer[..handler.index])
                            .to_string(),
                    )));
                    handler.diagnostic_buffer.fill(0);
                }
                Ok(DecodeStatus::FrameCompleteConfiguration) => {
                    // Drop the FCS at the end
                    results.push(Ok(Slipmux::Configuration(
                        handler.configuration_buffer[..handler.index - 2].to_vec(),
                    )));
                    handler.configuration_buffer.fill(0);
                }
                Ok(DecodeStatus::FrameCompleteIp) => {
                    results.push(Ok(Slipmux::Packet(
                        handler.packet_buffer[..handler.index - 2].to_vec(),
                    )));
                    handler.packet_buffer.fill(0);
                }
                Err(err) => {
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
            let _: Result<DecodeStatus, Error> = slipmux.decode(*byte, &mut handler);
        }
        handler.results
    }

    #[test]
    #[should_panic(
        expected = "Called .begin_frame when a frame was still in progress, .end_frame must be called before a new frame can be started."
    )]
    fn framehandler_method_beginn_twice() {
        let mut handler = OwnedLatestFrame::new();
        handler.begin_frame(FrameType::Diagnostic);
        handler.begin_frame(FrameType::Configuration);
    }

    #[test]
    #[should_panic(expected = "Called .write_byte before .begin_frame, frame_type not set.")]
    fn framehandler_method_write_before_begin() {
        let mut handler = OwnedLatestFrame::new();
        handler.write_byte(0xff);
        handler.begin_frame(FrameType::Configuration);
    }

    #[test]
    fn encode_decode_all_frametypes() {
        let input_diagnostic = Slipmux::Diagnostic("Hello World!".to_owned());
        let mut buffer = encode_buffered(input_diagnostic);

        let input_configuration = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
        buffer.append(&mut encode_buffered(input_configuration));

        let input_packet = Slipmux::Packet(vec![0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80]);
        buffer.append(&mut encode_buffered(input_packet));

        let mut slipmux = Decoder::new();
        let mut handler = OwnedLatestFrame::new();
        for (index, byte) in buffer.iter().enumerate() {
            let result = slipmux.decode(*byte, &mut handler);
            match result {
                Ok(DecodeStatus::FrameCompleteConfiguration) => {
                    // Drop the FCS at the end
                    handler
                        .configuration_buffer
                        .truncate(handler.configuration_buffer.len() - 2);
                }
                Ok(
                    DecodeStatus::FrameCompleteIp
                    | DecodeStatus::FrameCompleteDiagnostic
                    | DecodeStatus::Incomplete,
                ) => {}
                Err(_err) => {}
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(message) => assert_eq!(message, "Hello World!"),
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Configuration(config) => assert_eq!(config, b"Hello World!"),
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            assert!(matches!(frame, Err(Error::BadFCS)));
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(message) => assert_eq!(message, "Hello World!"),
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 1);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(message) => assert_eq!(message, "Hello World!"),
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for results in results_arr {
            for slipframe in results {
                match slipframe {
                    Ok(Slipmux::Diagnostic(message)) => {
                        assert_eq!(message, "Hello World!");
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
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
    fn frame_abort() {
        const SLIPMUX_ENCODED: [u8; 25] = [
            Constants::END,
            Constants::CONFIGURATION,
            0x48,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x57,
            Constants::ESC,
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for mut results in results_arr {
            assert_eq!(results.len(), 2);
            let frame = results.pop().unwrap();
            match frame.unwrap() {
                Slipmux::Diagnostic(message) => assert_eq!(message, "Hello World!"),
                _ => unreachable!(),
            }
            let frame = results.pop().unwrap();
            match frame {
                Ok(_) => unreachable!(),
                Err(error) => assert!(matches!(error, Error::Abort)),
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
            owned_latest_frame_wrapper(&SLIPMUX_ENCODED),
            referenced_latest_frame_wrapper(&SLIPMUX_ENCODED),
        ];
        for frames in results_arr {
            assert_eq!(frames.len(), 3);
            assert!(matches!(frames[0], Ok(Slipmux::Diagnostic(_))));
            assert!(matches!(frames[1], Err(Error::BadFrameType(0x50))));
            assert!(matches!(frames[2], Ok(Slipmux::Diagnostic(_))));
        }
    }
}
