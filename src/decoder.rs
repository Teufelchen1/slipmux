use crate::Constants;
use crate::FrameType;
use crate::checksum::{GOOD_FCS16, INIT_FCS16, fcs16_byte};

use crate::Error;

enum SlipmuxState {
    Idle,
    UnkownFrameType,
    Diagnostic,
    DiagnosticEscape,
    Configuration,
    ConfigurationEscape,
    Ip,
    IpEscape,
}

use SlipmuxState::{
    Configuration, ConfigurationEscape, Diagnostic, DiagnosticEscape, Idle, Ip, IpEscape,
    UnkownFrameType,
};

/// Callback handler for the decoder
///
/// This is typically driven by [`Decoder::decode()`], which calls it strictly in the sequence of
/// [`.begin_frame()`][Self::begin_frame()], any number of [`.write_byte()`][Self::write_byte()]
/// and then [`.end_frame()`][Self::end_frame()], starting over after that.
pub trait FrameHandler {
    /// Called when the decoder identifies a frame and starts filling it
    fn begin_frame(&mut self, frame_type: FrameType);

    /// Called with each new byte that belongs to the current frame
    fn write_byte(&mut self, byte: u8);

    /// Called when a full frame has been received
    fn end_frame(&mut self, error: Option<Error>);
}

/// The resulting state of the last decoding step
#[derive(Debug)]
pub enum DecodeStatus {
    /// Indicates that more data is needed to complete a frame
    Incomplete,
    /// A diagnostic frame got completed
    FrameCompleteDiagnostic,
    /// A configuration frame got completed
    FrameCompleteConfiguration,
    /// A IP frame got completed
    FrameCompleteIp,
}

/// Slipmux decoder context
pub struct Decoder {
    state: SlipmuxState,
    fcs: u16,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Create a new context for the slipmux decoder
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Idle,
            fcs: 0,
        }
    }

    /// Decodes one incoming byte.
    ///
    /// Depending on the internal decoding state, the handler may or may not get invoked.
    ///
    /// # Errors
    ///
    /// Will return `Err` if either  an unkown frame type is encountered OR the checksum of a
    /// configuration frame is bad OR a frame got aborted.
    #[allow(clippy::match_same_arms)]
    #[allow(clippy::too_many_lines)]
    pub fn decode<H: FrameHandler>(
        &mut self,
        byte: u8,
        handler: &mut H,
    ) -> Result<DecodeStatus, Error> {
        self.state = {
            match (&self.state, byte) {
                (Idle, Constants::END) => Idle, /* ignore empty frame */
                (Idle, Constants::DIAGNOSTIC) => {
                    handler.begin_frame(FrameType::Diagnostic);
                    Diagnostic
                }
                (Idle, Constants::CONFIGURATION) => {
                    handler.begin_frame(FrameType::Configuration);
                    self.fcs = fcs16_byte(INIT_FCS16, Constants::CONFIGURATION);
                    Configuration
                }
                (
                    Idle,
                    Constants::IP4_FROM..Constants::IP4_TO | Constants::IP6_FROM..Constants::IP6_TO,
                ) => {
                    handler.begin_frame(FrameType::Ip);
                    handler.write_byte(byte);
                    Ip
                }
                (Idle, _) => {
                    self.state = UnkownFrameType;
                    handler.end_frame(Some(Error::BadFrameType(byte)));
                    return Err(Error::BadFrameType(byte));
                }
                (UnkownFrameType, Constants::END) => Idle,
                (UnkownFrameType, _) => UnkownFrameType,

                (Diagnostic, Constants::ESC) => DiagnosticEscape,
                (Diagnostic, Constants::END) => {
                    handler.end_frame(None);
                    self.state = Idle;
                    return Ok(DecodeStatus::FrameCompleteDiagnostic);
                }
                (Diagnostic, _) => {
                    handler.write_byte(byte);
                    Diagnostic
                }
                (DiagnosticEscape, Constants::ESC_END) => {
                    handler.write_byte(Constants::END);
                    Diagnostic
                }
                (DiagnosticEscape, Constants::ESC_ESC) => {
                    handler.write_byte(Constants::ESC);
                    Diagnostic
                }
                (DiagnosticEscape, Constants::END) => {
                    self.state = Idle;
                    handler.end_frame(Some(Error::Abort));
                    return Err(Error::Abort);
                }
                (DiagnosticEscape, _) => {
                    handler.write_byte(byte);
                    Diagnostic
                }

                (Configuration, Constants::ESC) => ConfigurationEscape,
                (Configuration, Constants::END) => {
                    self.state = Idle;
                    if self.fcs == GOOD_FCS16 {
                        handler.end_frame(None);
                        return Ok(DecodeStatus::FrameCompleteConfiguration);
                    }
                    handler.end_frame(Some(Error::BadFCS));
                    return Err(Error::BadFCS);
                }
                (Configuration, _) => {
                    handler.write_byte(byte);
                    self.fcs = fcs16_byte(self.fcs, byte);
                    Configuration
                }
                (ConfigurationEscape, Constants::ESC_END) => {
                    handler.write_byte(Constants::END);
                    self.fcs = fcs16_byte(self.fcs, Constants::END);
                    Configuration
                }
                (ConfigurationEscape, Constants::ESC_ESC) => {
                    handler.write_byte(Constants::ESC);
                    self.fcs = fcs16_byte(self.fcs, Constants::ESC);
                    Configuration
                }
                (ConfigurationEscape, Constants::END) => {
                    self.state = Idle;
                    handler.end_frame(Some(Error::Abort));
                    return Err(Error::Abort);
                }
                (ConfigurationEscape, _) => {
                    handler.write_byte(byte);
                    self.fcs = fcs16_byte(self.fcs, byte);
                    Configuration
                }

                (Ip, Constants::ESC) => IpEscape,
                (Ip, Constants::END) => {
                    self.state = Idle;
                    handler.end_frame(None);
                    return Ok(DecodeStatus::FrameCompleteIp);
                }
                (Ip, _) => {
                    handler.write_byte(byte);
                    Ip
                }
                (IpEscape, Constants::ESC_END) => {
                    handler.write_byte(Constants::END);
                    Ip
                }
                (IpEscape, Constants::ESC_ESC) => {
                    handler.write_byte(Constants::ESC);
                    Ip
                }
                (IpEscape, Constants::END) => {
                    self.state = Idle;
                    handler.end_frame(Some(Error::Abort));
                    return Err(Error::Abort);
                }
                (IpEscape, _) => {
                    handler.write_byte(byte);
                    Ip
                }
            }
        };

        // return Incomplete when the frame wasn't completed and more data is needed
        Ok(DecodeStatus::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use crate::{OwnedLatestFrame, Slipmux, encode_buffered};
    use std::assert_matches;

    use super::*;

    #[test]
    fn decode_all_frametypes() {
        const HELLO_WORLD: &str = "Hello World!";
        const HELLO_CONFIG: [u8; 14] = [
            0x64, 0x45, 0x13, 0xFD, 0xD0, 0xE2, 0x4D, 0xAC, 0xFF, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        const HELLO_PACKET: [u8; 6] = [0x60, 0x0d, 0xda, 0x01, 0xfe, 0x80];
        let input_diagnostic = Slipmux::Diagnostic(HELLO_WORLD.to_owned());
        let mut buffer = encode_buffered(input_diagnostic);
        let input_configuration = Slipmux::Configuration(HELLO_CONFIG.to_vec());
        buffer.append(&mut encode_buffered(input_configuration));
        let input_packet = Slipmux::Packet(HELLO_PACKET.to_vec());
        buffer.append(&mut encode_buffered(input_packet));

        let expected: [DecodeStatus; 42] = [
            DecodeStatus::Incomplete, // leading end
            DecodeStatus::Incomplete, // type
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::FrameCompleteDiagnostic,
            DecodeStatus::Incomplete, // leading end
            DecodeStatus::Incomplete, // type
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete, // FCS
            DecodeStatus::Incomplete, // FCS
            DecodeStatus::FrameCompleteConfiguration,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::Incomplete,
            DecodeStatus::FrameCompleteIp,
        ];

        let mut slipmux = Decoder::new();
        let mut handler = OwnedLatestFrame::new();

        for (index, byte) in buffer.iter().enumerate() {
            let result: DecodeStatus = slipmux.decode(*byte, &mut handler).unwrap();
            match expected[index] {
                DecodeStatus::Incomplete => {
                    assert_matches!(result, DecodeStatus::Incomplete);
                }
                DecodeStatus::FrameCompleteDiagnostic => {
                    assert_matches!(result, DecodeStatus::FrameCompleteDiagnostic);
                }
                DecodeStatus::FrameCompleteConfiguration => {
                    assert_matches!(result, DecodeStatus::FrameCompleteConfiguration);
                }
                DecodeStatus::FrameCompleteIp => {
                    assert_matches!(result, DecodeStatus::FrameCompleteIp);
                }
            }
        }
    }
}
