# 0.2.2
* **Fix**: Continuous mode with `--output` now appends to a single pcap file instead of creating multiple files
  - First iteration creates the pcap file with header
  - Subsequent iterations append packets to the same file
  - Eliminates the previous behavior of creating `output.pcap`, `output_2.pcap`, `output_3.pcap`, etc.
  - Results in one consolidated pcap file for the entire continuous run

# 0.2.1
  - Added multi-threading support for parallel packet generation
  - New `--threads` CLI option to configure thread pool size (default: 4)
  - Flows from configuration files are now generated in parallel using rayon
  - Significant performance improvement when processing multiple flows
  - Thread pool is configurable from 1 to any desired number of threads
  - Added Configuration error variant for thread pool setup errors

# 0.2.0
* **BREAKING**: File output now exports to PCAP format instead of raw binary
  - Generated pcap files include proper Ethernet/IP/UDP headers
  - Files can be analyzed with Wireshark, tcpdump, and other pcap tools
  - Destination IP/port from `--dest` argument is used in pcap headers
* **Safety**: Complete rewrite of all type conversions and arithmetic to use safe operations
  - Replaced all `as` casts with `try_from()` with proper error handling
  - Replaced all arithmetic (`+`, `-`, `*`, `/`) with checked operations (`checked_add()`, etc.)
  - Prevents silent overflow, truncation, and potential panics
  - Added comprehensive error messages for invalid packet sizes and overflows
* **Dependencies**: Added `pcap-file` v2.0 for pcap file generation
* **Quality**: Zero clippy warnings, all tests passing

# 0.1.0
* Initial public release
* Support for NetFlow v5, v7, v9, and IPFIX
* YAML configuration support
* Continuous and single-shot modes
* UDP transmission support
* File output (raw binary format)

# 0.0.1
* Initial development release
