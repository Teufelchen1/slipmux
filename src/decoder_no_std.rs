use crate::Constants;

enum FrameType {
    Diagnostic,
    Configuration,
    Ip,
}

pub trait FrameHandler {
    /// Called when the decoder identifies a frane and starts filling it
    fn begin_frame(&mut self, frame_type: FrameType);

    /// Called with each new byte that belongs to the current packet
    fn write_byte(&mut self, byte: u8);

    /// Called when a full frame has been received
    fn end_frame(&mut self) -> ();
}

struct BufferedFrameHandler {
    frame_type: FrameType,
    diagnostic_buffer: Vec<u8>,
    configuration_buffer: Vec<u8>,
    packet_buffer: Vec<u8>,
}

impl BufferedFrameHandler {
    pub fn new() -> Self {
        BufferedFrameHandler {
            frame_type: FrameType::Diagnostic,
            diagnostic_buffer: vec![],
            configuration_buffer: vec![],
            packet_buffer: vec![],
        }
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

    fn end_frame(&mut self) -> () {
        ()
    }
}

#[derive(PartialEq, Debug)]
pub enum DecodeStatus {
    Incomplete,
    FrameCompleteDiagnostic,
    FrameCompleteConfiguration,
    FrameCompleteIp,
    Error,
}

enum SlipmuxState {
    Idle,
    Diagnostic,
    DiagnosticEscape,
    Configuration,
    ConfigurationEscape,
}

use SlipmuxState::*;

pub struct Decoder {
    state: SlipmuxState,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { state: Idle }
    }

    pub fn decode<H: FrameHandler>(&mut self, byte: u8, handler: &mut H) -> DecodeStatus {
        // internal decoding logic here...

        self.state = {
            match (&self.state, byte) {
                (Idle, Constants::END) => Idle, /* ignore empty frame */
                (Idle, Constants::DIAGNOSTIC) => {
                    handler.begin_frame(FrameType::Diagnostic);
                    Diagnostic
                }
                (Idle, Constants::CONFIGURATION) => {
                    handler.begin_frame(FrameType::Configuration);
                    Configuration
                }
                (Idle, _) => Idle,

                (Diagnostic, Constants::ESC) => DiagnosticEscape,
                (Diagnostic, Constants::END) => {
                    handler.end_frame();
                    self.state = Idle;
                    return DecodeStatus::FrameCompleteDiagnostic;
                }
                (Diagnostic, _) => {
                    handler.write_byte(byte);
                    Diagnostic
                }
                (DiagnosticEscape, Constants::ESC_END) => Diagnostic,
                (DiagnosticEscape, Constants::ESC_ESC) => Diagnostic,
                (DiagnosticEscape, _) => Diagnostic,

                (Configuration, Constants::ESC) => ConfigurationEscape,
                (Configuration, Constants::END) => {
                    handler.end_frame();
                    self.state = Idle;
                    return DecodeStatus::FrameCompleteConfiguration;
                }
                (Configuration, _) => {
                    handler.write_byte(byte);
                    Configuration
                }
                (ConfigurationEscape, Constants::ESC_END) => Configuration,
                (ConfigurationEscape, Constants::ESC_ESC) => Configuration,
                (ConfigurationEscape, _) => Configuration,
            }
        };

        // return Incomplete when the frame wasn't completed and more data is needed
        DecodeStatus::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Slipmux;
    use crate::decoder_no_std::DecodeStatus::FrameCompleteConfiguration;
    use crate::decoder_no_std::DecodeStatus::FrameCompleteDiagnostic;
    use crate::decoder_no_std::DecodeStatus::Incomplete;
    use crate::encode;
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
        let mut results: Vec<DecodeStatus> = vec![];
        for (index, byte) in buffer[..length].iter().enumerate() {
            results.push(slipmux.decode(*byte, &mut handler));
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

        assert_eq!(
            results,
            [
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                FrameCompleteDiagnostic,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                FrameCompleteConfiguration,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete,
                Incomplete
            ]
        );

        // match slipmux.decode(*byte, &mut handler) {
        //     DecodeStatus::Incomplete => (),
        //     DecodeStatus::FrameCompleteDiagnostic => {
        //         assert_eq!(handler.diagnostic_buffer, b"Hello World!");
        //     }
        //     DecodeStatus::FrameCompleteConfiguration => (),
        //     DecodeStatus::FrameCompleteIp => (),
        //     DecodeStatus::Error => (),
        // }

        // let frames = slipmux.decode(&buffer[..length]);
        // assert_eq!(3, frames.len());
        // for slipframe in frames {
        //     match slipframe {
        //         Ok(Slipmux::Diagnostic(s)) => {
        //             assert_eq!(s, "Hello World!");
        //         }
        //         Ok(Slipmux::Configuration(conf)) => {
        //             assert_eq!(conf, Packet::new().to_bytes().unwrap());
        //         }
        //         Ok(Slipmux::Packet(packet)) => {
        //             assert_eq!(packet, vec![0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80]);
        //         }
        //         Err(_) => unreachable!(),
        //     }
        // }
    }
}
