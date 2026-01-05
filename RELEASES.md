# 0.2.4
* **Fix**: NetFlow v9 and IPFIX sequence numbers now properly increment across iterations in continuous mode
  - Previous behavior reset sequence numbers to 0 on each iteration, causing parsers to detect collisions
  - Sequence numbers are now tracked per exporter (source_id for V9, observation_domain_id for IPFIX)
  - Each exporter maintains independent sequence counters that increment across iterations
  - Prevents "sequence number collision" errors in RFC-compliant parsers
  - Single-shot mode (--once) behavior unchanged - still starts from 0 each run
* **Fix**: Removed parallel processing (rayon) for V9/IPFIX flows to maintain proper sequence number ordering
  - V5 and V7 flows are processed sequentially for consistency
  - Sequential processing ensures correct sequence number tracking
* **Fix**: UDP socket now uses fixed source port 2056 instead of ephemeral ports
  - Matches real NetFlow exporter behavior where routers use consistent source ports
  - Fixes template collision issues with RFC-compliant collectors (AutoScopedParser, RouterScopedParser)
  - RFC 7011 (IPFIX) and RFC 3954 (NetFlow v9) specify scoping by (source_address, observation_domain_id/source_id)
  - Previous ephemeral port behavior caused each packet to be treated as a different source
  - Port 2056 avoids conflicts with NetFlow collectors typically running on port 2055
* **Dependency**: Updated netflow_parser from 0.7.0 to 0.8.0
* **Documentation**: Added "Sequence Number Tracking" section to README explaining behavior in continuous mode
* **Documentation**: Added "Network Behavior" section to README explaining fixed source port rationale

# 0.2.3
* Bump release for cargo publish and README updates.

# 0.2.2
* **Fix**: Continuous mode with `--output` now appends to a single pcap file instead of creating multiple files
  - First iteration creates the pcap file with header
  - Subsequent iterations append packets to the same file
  - Eliminates the previous behavior of creating `output.pcap`, `output_2.pcap`, `output_3.pcap`, etc.
  - Results in one consolidated pcap file for the entire continuous run
* **Fix**: Graceful shutdown handling prevents pcap file corruption when using Ctrl+C
  - Added signal handler to intercept Ctrl+C (SIGINT) in continuous mode
  - Program now exits cleanly, properly flushing and closing pcap files
  - Prevents corrupted pcap files that were unreadable by Wireshark/tcpdump
  - Shutdown flag is checked during loop iterations and sleep intervals for responsive exit

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
