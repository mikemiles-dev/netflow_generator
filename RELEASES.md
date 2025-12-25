# Release Notes

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of NetFlow Generator
- Support for NetFlow v5, v7, v9, and IPFIX packet generation
- YAML-based configuration for custom flow definitions
- Built-in sample packets for quick testing
- Continuous generation mode (default: every 2 seconds)
- Single-shot mode with `--once` flag
- Configurable transmission intervals
- UDP transmission to configurable destinations
- File output option for saving generated packets
- Template and data record support for v9 and IPFIX
- Field-level control over all packet parameters
- Automatic header value generation with override support
- CLI with verbose output option
- Comprehensive example YAML configurations
- Full documentation in README.md

### Technical Details
- Built with Rust 2024 edition
- Uses netflow_parser v0.7.0 for packet structures
- Zero clippy warnings
- Comprehensive error handling with custom error types

## [0.1.0] - TBD

Initial release.

### Features
- NetFlow v5 packet generation
- NetFlow v7 packet generation
- NetFlow v9 packet generation with templates
- IPFIX packet generation with templates
- YAML configuration support
- Default sample mode
- Continuous mode (default)
- Single-shot mode
- UDP transmission
- File output
- Verbose logging
- Configurable intervals and destinations

### Supported Field Types

#### NetFlow v9
- IPV4_SRC_ADDR, IPV4_DST_ADDR
- IN_BYTES, IN_PKTS
- L4_SRC_PORT, L4_DST_PORT
- PROTOCOL, TCP_FLAGS
- And 16 additional field types

#### IPFIX
- sourceIPv4Address, destinationIPv4Address
- packetDeltaCount, octetDeltaCount
- sourceTransportPort, destinationTransportPort
- protocolIdentifier, tcpControlBits
- And 14 additional information elements

### Installation
- Available via `cargo install` from git
- Building from source supported
- Tested on macOS, Linux compatibility expected

### Documentation
- Comprehensive README with usage examples
- Example YAML files for all NetFlow versions
- CLI help documentation
- Architecture overview

---

## Release Categories

### Added
Features, functionality, or capabilities that have been introduced.

### Changed
Changes in existing functionality or behavior.

### Deprecated
Features that are still available but scheduled for removal.

### Removed
Features or functionality that have been removed.

### Fixed
Bug fixes and error corrections.

### Security
Security-related improvements or fixes.
