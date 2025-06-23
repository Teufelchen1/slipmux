# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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