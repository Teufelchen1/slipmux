[![Clippy & co](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml/badge.svg)](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml)
# Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer

Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).

Note: Frame aborting is not implemented!

## What is Slipmux

Slipmux is a very simple framing and multiplexing protocol. It uses RFC1055,
commonly known as [serial line ip (slip)](https://datatracker.ietf.org/doc/html/rfc1055),
as a basis for encoding / decoding data streams into frames but extends it with
multiplexing. Slipmux defines three frame types: traditional IP packets,
diagnostic frames and configuration messages.
Diagnostic frames are UTF-8 encoded strings intended as human-readable messages.
Configuration messages are serialized `CoAP` messages.

## Todo

- [x] Remove coap-lite dep
- [x] Don't leak types of the `serial-line-ip-rs` crate
- [x] Provide tests for IP packets
- [x] Implement FCS check sum for configuration frame
- [ ] Implement frame abort
- [ ] Make crate optional `#[no_std]`
- [ ] Rethink public interfaces (generalise the usability):
	- [ ] Currently wild mix of `[u8]` and `Vec<u8>`
	- [ ] Impossible to know if the deocder is completely done or if bytes remain in its buffer
	- [ ] Error handling is tedious
- [ ] Interoperability tests with other slipmux implementations

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
