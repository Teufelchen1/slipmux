use crate::Constants;
use crate::FrameType;
use crate::checksum::{GOOD_FCS16, INIT_FCS16, fcs16_byte};

use crate::Error;

enum SlipmuxState {
    Idle,
    Unknown, /* Start state: We do not know what is currently happening "on the wire" when we get
              * "connected", the current state can not be known. It could be that we are in the
              * middle of the transfer of a configuration frame. This frame might contain bytes
              * that match known frame type start bytes! We would enter the wrong state.
              * The only byte that always gets escaped, and therefore is never inside any
              * frame, is the `Constants::END` byte. This means we wait until we see this end
              * byte to change state into `Idle` and can be sure to be in sync with the peer. */
    UnknownFrameType,
    Diagnostic,
    DiagnosticEscape,
    Configuration,
    ConfigurationEscape,
    Ip,
    IpEscape,
}

use SlipmuxState::{
    Configuration, ConfigurationEscape, Diagnostic, DiagnosticEscape, Idle, Ip, IpEscape, Unknown,
    UnknownFrameType,
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
            state: Unknown,
            fcs: 0,
        }
    }

    /// Decodes one incoming byte.
    ///
    /// Depending on the internal decoding state, the handler may or may not get invoked.
    ///
    /// # Errors
    ///
    /// Will return `Err` if either an unknown frame type is encountered OR the checksum of a
    /// configuration frame is bad OR a frame got aborted.
    #[expect(clippy::match_same_arms)]
    #[expect(clippy::too_many_lines)]
    pub fn decode<H: FrameHandler>(
        &mut self,
        byte: u8,
        handler: &mut H,
    ) -> Result<DecodeStatus, Error> {
        self.state = {
            match (&self.state, byte) {
                (Unknown, Constants::END) => Idle,
                (Unknown, _) => Unknown, // Wait until we see the first end-byte
                (Idle, Constants::END) => Idle, // ignore empty frame
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
                    self.state = UnknownFrameType;
                    handler.end_frame(Some(Error::BadFrameType(byte)));
                    return Err(Error::BadFrameType(byte));
                }
                (UnknownFrameType, Constants::END) => Idle,
                (UnknownFrameType, _) => UnknownFrameType,

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
#[cfg(feature = "std")]
mod tests {
    use crate::{OwnedLatestFrame, Slipmux, encode_buffered};

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
                    assert!(matches!(result, DecodeStatus::Incomplete));
                }
                DecodeStatus::FrameCompleteDiagnostic => {
                    assert!(matches!(result, DecodeStatus::FrameCompleteDiagnostic));
                }
                DecodeStatus::FrameCompleteConfiguration => {
                    assert!(matches!(result, DecodeStatus::FrameCompleteConfiguration));
                }
                DecodeStatus::FrameCompleteIp => {
                    assert!(matches!(result, DecodeStatus::FrameCompleteIp));
                }
            }
        }
    }

    #[test]
    fn starting_in_unknown_state_prevents_entering_erroneous_state() {
        const SLIPMUX_ENCODED: [u8; 21] = [
            0x6f,
            0x72,
            Constants::CONFIGURATION,
            Constants::IP6_FROM,
            0x6c,
            0x64,
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
        let mut handler = OwnedLatestFrame::new();

        for (index, byte) in SLIPMUX_ENCODED.iter().enumerate() {
            let result: DecodeStatus = slipmux.decode(*byte, &mut handler).unwrap();
            // Last return should complete the diagnostic frame, all others are incomplete
            if index == SLIPMUX_ENCODED.len() - 1 {
                assert!(matches!(result, DecodeStatus::FrameCompleteDiagnostic));
            } else {
                assert!(matches!(result, DecodeStatus::Incomplete));
            }
        }

        assert_eq!(handler.diagnostic_buffer, b"Hello World!");
    }
}
