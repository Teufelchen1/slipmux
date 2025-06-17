use crate::Constants;
use crate::FrameType;
#[cfg(feature = "std")]
use crate::Slipmux;
use crate::checksum::{CONF_FCS16, fcs16_finish, fcs16_part};
use serial_line_ip::EncodeTotals;
use serial_line_ip::Encoder;

/// Short hand for `encode(FrameType::Diagnostic, text.as_bytes(), buffer)`
#[must_use]
pub fn encode_diagnostic(text: &str, buffer: &mut [u8]) -> usize {
    encode(FrameType::Diagnostic, text.as_bytes(), buffer)
}

/// Short hand for `encode(FrameType::Configuration, &packet, buffer)`
#[must_use]
pub fn encode_configuration(packet: &[u8], buffer: &mut [u8]) -> usize {
    encode(FrameType::Configuration, packet, buffer)
}

/// Short hand for `encode(FrameType::Ip, &packet, buffer)`
#[must_use]
pub fn encode_packet(packet: &[u8], buffer: &mut [u8]) -> usize {
    encode(FrameType::Ip, packet, buffer)
}

/// Encodes `Slipmux` data into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into the buffer
#[cfg(feature = "std")]
#[must_use]
pub fn encode_buffered(input: Slipmux) -> Vec<u8> {
    let mut buffer: Vec<u8> = vec![];
    let length = match input {
        Slipmux::Diagnostic(s) => {
            buffer.resize(s.len() * 2, 0);
            encode(FrameType::Diagnostic, s.as_bytes(), &mut buffer)
        }
        Slipmux::Configuration(conf) => {
            buffer.resize(conf.len() * 2 + 2, 0);
            encode(FrameType::Configuration, &conf, &mut buffer)
        }
        Slipmux::Packet(packet) => {
            buffer.resize(packet.len() * 2, 0);
            encode(FrameType::Ip, &packet, &mut buffer)
        }
    };
    buffer.truncate(length);
    buffer
}

/// Encodes data based on the `FrameType` into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into the buffer
#[must_use]
pub fn encode(ftype: FrameType, data: &[u8], buffer: &mut [u8]) -> usize {
    let mut slip = Encoder::new();
    let mut totals = EncodeTotals {
        read: 0,
        written: 0,
    };
    match ftype {
        FrameType::Diagnostic => {
            totals += slip.encode(&[Constants::DIAGNOSTIC], buffer).unwrap();
            totals += slip.encode(data, &mut buffer[totals.written..]).unwrap();
        }
        FrameType::Configuration => {
            let fcs = fcs16_part(CONF_FCS16, data);
            let fcs = fcs16_finish(fcs);
            totals += slip.encode(&[Constants::CONFIGURATION], buffer).unwrap();
            totals += slip.encode(data, &mut buffer[totals.written..]).unwrap();
            totals += slip
                .encode(&fcs.to_le_bytes(), &mut buffer[totals.written..])
                .unwrap();
        }
        FrameType::Ip => {
            totals += slip.encode(data, &mut buffer[totals.written..]).unwrap();
        }
    }
    totals += slip.finish(&mut buffer[totals.written..]).unwrap();
    totals.written
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap_lite::Packet;

    #[test]
    #[cfg(feature = "std")]
    fn simple_diagnostic() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_diagnostic("Hello World!", &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");
        let length = encode_diagnostic("Yes, I would like one \x0a please.", &mut buffer);
        assert_eq!(
            buffer[..length],
            *b"\xc0\x0aYes, I would like one \x0a please.\xc0"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn wrapper_diagnostic() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_diagnostic("", &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0a\xc0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn wrapper_configuration() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_configuration(&Packet::new().to_bytes().unwrap(), &mut buffer);
        assert_eq!(
            buffer[..length],
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    #[test]
    fn direct() {
        const DATA: &str = "Hello World!";
        let mut buffer: [u8; 2048] = [0; 2048];

        let length = encode(FrameType::Diagnostic, DATA.as_bytes(), &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");

        let packet: &[u8] = &Packet::new().to_bytes().unwrap();
        let length = encode(FrameType::Configuration, packet, &mut buffer);
        assert_eq!(
            buffer[..length],
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn direct_std() {
        const DATA: &str = "Hello World!";
        let input = Slipmux::Diagnostic(DATA.to_owned());
        let result = encode_buffered(input);
        assert_eq!(result, *b"\xc0\x0aHello World!\xc0");

        let packet: &[u8] = &Packet::new().to_bytes().unwrap();
        let input = Slipmux::Configuration(packet.to_vec());
        let result = encode_buffered(input);
        assert_eq!(
            result,
            [
                Constants::END,
                Constants::CONFIGURATION,
                0x40,
                0x01,
                0x00,
                0x00,
                0xbc,
                0x38,
                Constants::END
            ]
        );
    }
}
