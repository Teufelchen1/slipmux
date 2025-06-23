[![Clippy & co](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml/badge.svg)](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/slipmux.svg)](https://crates.io/crates/slipmux)
[![Documentation](https://docs.rs/slipmux/badge.svg)](https://docs.rs/slipmux)
# Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer

Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).


## What is Slipmux

Slipmux is a very simple framing and multiplexing protocol. It uses RFC1055,
commonly known as [serial line ip (slip)](https://datatracker.ietf.org/doc/html/rfc1055),
as a basis for encoding / decoding data streams into frames but extends it with
multiplexing. Slipmux defines three frame types: traditional IP packets,
diagnostic frames and configuration messages.
Diagnostic frames are UTF-8 encoded strings intended as human-readable messages.
Configuration messages are serialized `CoAP` messages.

## Usage

Add `slipmux` to the dependencies in your `Cargo.toml`. This crate requires `std` by default via the `std` feature. You can disable this by adding `default-features = false` to the entry, which will make this crate `no_std` compatible.

Check [docs.rs](https://docs.rs/slipmux/latest/slipmux/) for examples and documentation on the programming API.
For even more examples, take a look at the unittests on the bottom of [src/framehandler.rs](https://github.com/Teufelchen1/slipmux/blob/main/src/framehandler.rs).

## Todo

- [x] Remove coap-lite dep
- [x] Don't leak types of the `serial-line-ip-rs` crate
- [x] Provide tests for IP packets
- [x] Implement FCS check sum for configuration frame
- [x] Implement frame abort
	- [ ] Encoder (this crate does not take control over the transmission, it has no way of aborting)
	- [x] Decoder
- [x] Make crate optional `#[no_std]`
- [x] Rethink public interfaces (generalise the usability):
	- [x] Currently wild mix of `[u8]` and `Vec<u8>`
	- [x] Impossible to know if the deocder is completely done or if bytes remain in its buffer
	- [x] Error handling is tedious
- [ ] Interoperability tests with other slipmux implementations
- [ ] Polishing, QoL improvments, incorporating feedback from experienced crate publishern

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
