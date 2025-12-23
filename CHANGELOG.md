# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2025-12-24

### Added

- Introduced `ChunkedEncoder` that can iteratively encode data into a (small) buffer. Inteded for use on constrained devices where the output buffer might be hardware limited, e.g. uart write buffer.

## [0.3.2] - 2025-07-18

### Fixed

- A bug in `encode_buffered()` where the amount of space needed to encode a configuration frame was off by up to five bytes (missed checksum + endbyte at start)

## [0.3.1] - 2025-06-23

### Removed

- The keyword "framing" from the list of keywords in the `Cargo.toml` due to publishing rejection by `crates.io` because of too many keywords in that list.

## [0.3.0] - 2025-06-23

### Added

- Reworked encoding to use a passed buffer rather than their own
- Introduced reference based frame handler for no_std
- Reworked encoding for no_std
- Make crate no_std compatible
- Added frame aborting handling in the decoder

### Removed

- Old buffered decoder, replaced with new one which is no_std friendly

## [0.2.0] - 2025-04-09

### Added

- Checksums (FCS) to de- and encoding of configuration frames as the rfc draft demands.

## [0.1.0] - 2025-04-04

Initial release.

### Added

- Slipmux de- and encoding, without configuration frame checksums and without frame aborting.