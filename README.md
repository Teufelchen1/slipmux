[![Clippy & co](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml/badge.svg)](https://github.com/Teufelchen1/slipmux/actions/workflows/rust.yml)
# Slipmux: Using an UART interface for diagnostics, configuration, and packet transfer

Pure Rust implementation of [draft-bormann-t2trg-slipmux-03](https://datatracker.ietf.org/doc/html/draft-bormann-t2trg-slipmux-03).

Note: Currently no checksumming on the configuration frames implemented!

## What is Slipmux

Slipmux is a very simple framing and multiplexing protocol. It uses RFC1055,
commonly known as [serial line ip (slip)](https://datatracker.ietf.org/doc/html/rfc1055),
as a basis for encoding / decoding data streams into frames but extends it with
multiplexing. Slipmux defines three frame types: traditional IP packets,
diagnostic frames and configuration messages.
Diagnostic frames are UTF-8 encoded strings intended as human-readable messages.
Configuration messages are serialized `CoAP` messages.