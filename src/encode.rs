use crate::Constants;
use crate::Slipmux;
use crate::checksum::fcs16;
use serial_line_ip::EncodeTotals;
use serial_line_ip::Encoder;

/// Short hand for `encode(Slipmux::Diagnostic(text.to_owned()))`
#[must_use]
pub fn encode_diagnostic(text: &str, buffer: &mut [u8]) -> usize {
    encode(Slipmux::Diagnostic(text.to_owned()), buffer)
}

/// Short hand for `encode(Slipmux::Configuration(packet))`
#[must_use]
pub fn encode_configuration(packet: Vec<u8>, buffer: &mut [u8]) -> usize {
    encode(Slipmux::Configuration(packet), buffer)
}

/// Short hand for `encode(Slipmux::Packet(packet))`
#[must_use]
pub fn encode_packet(packet: Vec<u8>, buffer: &mut [u8]) -> usize {
    encode(Slipmux::Packet(packet), buffer)
}

/// Encodes `Slipmux` data into a frame
///
/// # Panics
///
/// Will panic if the encoded input does not fit into the buffer
#[must_use]
pub fn encode(input: Slipmux, buffer: &mut [u8]) -> usize {
    let mut slip = Encoder::new();
    let mut totals = EncodeTotals {
        read: 0,
        written: 0,
    };
    match input {
        Slipmux::Diagnostic(s) => {
            totals += slip.encode(&[Constants::DIAGNOSTIC], buffer).unwrap();
            totals += slip
                .encode(s.as_bytes(), &mut buffer[totals.written..])
                .unwrap();
        }
        Slipmux::Configuration(mut conf) => {
            conf.insert(0, Constants::CONFIGURATION);
            let fcs = fcs16(&conf);
            conf.extend_from_slice(&fcs.to_le_bytes());
            totals += slip.encode(&conf, buffer).unwrap();
        }
        Slipmux::Packet(packet) => {
            totals += slip.encode(&packet, &mut buffer[totals.written..]).unwrap();
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
    fn wrapper_diagnostic() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_diagnostic("", &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0a\xc0");
    }

    #[test]
    fn wrapper_configuration() {
        let mut buffer: [u8; 2048] = [0; 2048];
        let length = encode_configuration(Packet::new().to_bytes().unwrap(), &mut buffer);
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
        let mut buffer: [u8; 2048] = [0; 2048];
        let input = Slipmux::Diagnostic("Hello World!".to_owned());
        let length = encode(input, &mut buffer);
        assert_eq!(buffer[..length], *b"\xc0\x0aHello World!\xc0");

        let input = Slipmux::Configuration(Packet::new().to_bytes().unwrap());
        let length = encode(input, &mut buffer);
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
}
