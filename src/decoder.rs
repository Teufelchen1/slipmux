use crate::Constants;
use crate::SlipError;
use crate::Slipmux;
use crate::check_fcs;

use crate::Error;

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
        decoder.decode(&[Constants::END], &mut buffer).unwrap();
        Self {
            slip: decoder,
            index: 0,
            buffer,
        }
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

    fn reset(&mut self) {
        self.slip = serial_line_ip::Decoder::new();
        self.slip
            .decode(&[Constants::END], &mut self.buffer)
            .unwrap();
        self.index = 0;
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
                    Constants::DIAGNOSTIC => {
                        let s = String::from_utf8_lossy(&self.buffer[1..self.index]).to_string();
                        Ok(Slipmux::Diagnostic(s))
                    }
                    Constants::CONFIGURATION => {
                        // Check the checksum, which is two bytes long and we don't pass it further
                        if check_fcs(&self.buffer[0..self.index]) {
                            Ok(Slipmux::Configuration(
                                self.buffer[1..self.index - 2].to_vec(),
                            ))
                        } else {
                            Err(Error::BadFCS(self.buffer[0..self.index].to_vec()))
                        }
                    }
                    Constants::IP4_FROM..Constants::IP4_TO
                    | Constants::IP6_FROM..Constants::IP6_TO => {
                        Ok(Slipmux::Packet(self.buffer[0..self.index].to_vec()))
                    }
                    _ => Err(Error::BadFrameType(self.buffer[0])),
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
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        assert!(matches!(frame, Err(Error::BadFCS(_))));
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
        let mut slipmux = Decoder::new();
        let mut results = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(results.len(), 1);
        let frame = results.pop().unwrap();
        assert!(frame.is_err());
        match frame {
            Err(Error::BadFrameType(0x50)) => {} // expected case
            _ => unreachable!(),
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
        let mut slipmux = Decoder::new();
        let frames = slipmux.decode(&SLIPMUX_ENCODED);
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Ok(Slipmux::Diagnostic(_))));
        assert!(matches!(frames[1], Err(Error::BadFrameType(0x50))));
        assert!(matches!(frames[2], Ok(Slipmux::Diagnostic(_))));
    }

    #[test]
    fn stream() {
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
