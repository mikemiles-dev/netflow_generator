# NetFlow Generator

A flexible NetFlow packet generator written in Rust that supports NetFlow v5, v7, v9, and IPFIX formats. Generate custom flow data from YAML configurations or use built-in sample packets for testing network monitoring systems. Runs continuously by default, sending flows every 2 seconds for realistic traffic simulation.

## Features

- **Multiple NetFlow Versions**: Support for NetFlow v5, v7, v9, and IPFIX
- **YAML Configuration**: Define custom flow records with full field-level control
- **Default Sample Mode**: Built-in sample packets for quick testing
- **Continuous Generation**: Send flows at configurable intervals for ongoing traffic simulation
- **Flexible Output**: Send packets via UDP or save to file
- **Template Support**: Full support for NetFlow v9 and IPFIX template and data records
- **Configurable Destination**: Override destination IP and port via CLI
- **Validation**: Automatic validation of configuration files

## Installation

### Using Cargo Install

Install directly from crates.io (once published):

```bash
cargo install netflow_generator
```

Or install from the git repository:

```bash
cargo install --git https://github.com/yourusername/netflow_generator.git
```

### Building from Source

```bash
git clone https://github.com/yourusername/netflow_generator.git
cd netflow_generator
cargo build --release
```

The compiled binary will be available at `target/release/netflow_generator`.

## Usage

### Default Mode (Continuous)

By default, the generator runs in continuous mode, sending sample packets every 2 seconds:

```bash
# Using compiled binary
netflow_generator

# Using cargo run
cargo run
```

This will continuously send 6 packets every 2 seconds (press Ctrl+C to stop):
- 1 NetFlow v5 packet (HTTPS traffic)
- 1 NetFlow v7 packet (DNS traffic)
- 2 NetFlow v9 packets (template + data for HTTP traffic)
- 2 IPFIX packets (template + data for SSH traffic)

### Single-Shot Mode

To send flows once and exit, use the `--once` flag:

```bash
# Using compiled binary
netflow_generator --once

# Using cargo run
cargo run -- --once
```

### Custom Configuration

Generate packets from a YAML configuration file:

```bash
# Using compiled binary
netflow_generator --config flows.yaml

# Using cargo run
cargo run -- --config flows.yaml
```

### Override Destination

Send packets to a different destination:

```bash
# Using compiled binary
netflow_generator --config flows.yaml --dest 192.168.1.100:2055

# Using cargo run
cargo run -- --config flows.yaml --dest 192.168.1.100:2055
```

### Save to File

Save generated packets to a binary file instead of sending:

```bash
# Using compiled binary
netflow_generator --config flows.yaml --output packets.bin

# Using cargo run
cargo run -- --config flows.yaml --output packets.bin
```

### Verbose Output

Enable detailed logging:

```bash
# Using compiled binary
netflow_generator --config flows.yaml --verbose

# Using cargo run
cargo run -- --config flows.yaml --verbose
```

### Custom Interval

Change the interval between flow transmissions (default is 2 seconds):

```bash
# Send flows every 5 seconds
netflow_generator --interval 5

# Or using cargo run
cargo run -- --interval 5

# Custom config with 10 second interval
netflow_generator --config flows.yaml --interval 10 --verbose

# Or using cargo run
cargo run -- --config flows.yaml --interval 10 --verbose
```

The generator will loop indefinitely, sending packets at the specified interval. Press Ctrl+C to stop.

Note: When using `--output` in continuous mode, each iteration will create a separate file with an iteration number appended (e.g., `packets.bin`, `packets_2.bin`, `packets_3.bin`).

## CLI Options

```
Options:
  -c, --config <FILE>        Path to YAML configuration file
  -d, --dest <IP:PORT>       Destination address (overrides config)
  -o, --output <FILE>        Save packets to file instead of sending
  -v, --verbose              Enable verbose output
  -i, --interval [SECONDS]   Send flows every N seconds (default: 2)
                             Continuous mode is the default behavior
      --once                 Send flows once and exit (disables continuous mode)
  -h, --help                 Print help information
  -V, --version              Print version information
```

## YAML Configuration Format

### Structure

```yaml
flows:
  - version: v5|v7|v9|ipfix
    header: # Optional, auto-generates if not specified
      # Version-specific header fields
    flowsets:
      # Version-specific flowset records

destination:
  ip: "127.0.0.1"   # Optional, defaults to 127.0.0.1
  port: 2055        # Optional, defaults to 2055
```

### NetFlow v5 Example

```yaml
flows:
  - version: v5
    header:
      unix_secs: 1735141200
      unix_nsecs: 0
      sys_up_time: 360000
      flow_sequence: 1
    flowsets:
      - src_addr: "192.168.1.100"
        dst_addr: "172.217.14.206"
        next_hop: "192.168.1.1"
        input: 1
        output: 2
        d_pkts: 150
        d_octets: 95000
        first: 350000
        last: 360000
        src_port: 52341
        dst_port: 443
        tcp_flags: 24
        protocol: 6
        tos: 0
        src_as: 65000
        dst_as: 15169
        src_mask: 24
        dst_mask: 24

destination:
  ip: "127.0.0.1"
  port: 2055
```

### NetFlow v7 Example

```yaml
flows:
  - version: v7
    header:
      unix_secs: 1735141200
      unix_nsecs: 0
      sys_up_time: 360000
      flow_sequence: 1
    flowsets:
      - src_addr: "10.0.0.50"
        dst_addr: "8.8.8.8"
        next_hop: "10.0.0.1"
        input: 10
        output: 20
        d_pkts: 2
        d_octets: 128
        first: 355000
        last: 355100
        src_port: 54123
        dst_port: 53
        flags: 0
        tcp_flags: 0
        protocol: 17
        tos: 0
        src_as: 64512
        dst_as: 15169
        src_mask: 16
        dst_mask: 8
        flags2: 0
        router_src: "10.0.0.1"

destination:
  ip: "127.0.0.1"
  port: 2055
```

### NetFlow v9 Example

NetFlow v9 requires template definitions followed by data records:

```yaml
flows:
  - version: v9
    header:
      sys_up_time: 360000
      unix_secs: 1735141200
      sequence_number: 100
      source_id: 1
    flowsets:
      # First, define the template
      - type: template
        template_id: 256
        fields:
          - field_type: "IPV4_SRC_ADDR"
            field_length: 4
          - field_type: "IPV4_DST_ADDR"
            field_length: 4
          - field_type: "IN_PKTS"
            field_length: 4
          - field_type: "IN_BYTES"
            field_length: 4
          - field_type: "L4_SRC_PORT"
            field_length: 2
          - field_type: "L4_DST_PORT"
            field_length: 2
          - field_type: "PROTOCOL"
            field_length: 1

      # Then, provide data using the template
      - type: data
        template_id: 256
        records:
          - src_addr: "192.168.10.5"
            dst_addr: "93.184.216.34"
            in_pkts: 50
            in_bytes: 35000
            src_port: 48921
            dst_port: 80
            protocol: 6
          - src_addr: "10.0.1.100"
            dst_addr: "8.8.8.8"
            in_pkts: 2
            in_bytes: 128
            src_port: 54123
            dst_port: 53
            protocol: 17

destination:
  ip: "127.0.0.1"
  port: 2055
```

#### Supported NetFlow v9 Field Types

- IPV4_SRC_ADDR (8)
- IPV4_DST_ADDR (12)
- IN_BYTES (1)
- IN_PKTS (2)
- FLOWS (3)
- PROTOCOL (4)
- SRC_TOS (5)
- TCP_FLAGS (6)
- L4_SRC_PORT (7)
- L4_DST_PORT (11)
- SRC_MASK (9)
- DST_MASK (13)
- INPUT_SNMP (10)
- OUTPUT_SNMP (14)
- IPV4_NEXT_HOP (15)
- SRC_AS (16)
- DST_AS (17)
- BGP_IPV4_NEXT_HOP (18)
- LAST_SWITCHED (21)
- FIRST_SWITCHED (22)
- OUT_BYTES (23)
- OUT_PKTS (24)

### IPFIX Example

IPFIX uses IANA Information Element names:

```yaml
flows:
  - version: ipfix
    header:
      export_time: 1735141200
      sequence_number: 500
      observation_domain_id: 1
    flowsets:
      # Define template using IANA Information Element names
      - type: template
        template_id: 300
        fields:
          - field_type: "sourceIPv4Address"
            field_length: 4
          - field_type: "destinationIPv4Address"
            field_length: 4
          - field_type: "packetDeltaCount"
            field_length: 8
          - field_type: "octetDeltaCount"
            field_length: 8
          - field_type: "sourceTransportPort"
            field_length: 2
          - field_type: "destinationTransportPort"
            field_length: 2
          - field_type: "protocolIdentifier"
            field_length: 1

      # Data records using the template
      - type: data
        template_id: 300
        records:
          - source_ipv4_address: "172.20.0.100"
            destination_ipv4_address: "198.51.100.10"
            packet_delta_count: 500
            octet_delta_count: 125000
            source_transport_port: 50122
            destination_transport_port: 22
            protocol_identifier: 6
          - source_ipv4_address: "192.168.1.50"
            destination_ipv4_address: "1.1.1.1"
            packet_delta_count: 10
            octet_delta_count: 1200
            source_transport_port: 52000
            destination_transport_port: 443
            protocol_identifier: 6

destination:
  ip: "127.0.0.1"
  port: 2055
```

#### Supported IPFIX Information Elements

- octetDeltaCount (1)
- packetDeltaCount (2)
- deltaFlowCount (3)
- protocolIdentifier (4)
- ipClassOfService (5)
- tcpControlBits (6)
- sourceTransportPort (7)
- sourceIPv4Address (8)
- sourceIPv4PrefixLength (9)
- ingressInterface (10)
- destinationTransportPort (11)
- destinationIPv4Address (12)
- destinationIPv4PrefixLength (13)
- egressInterface (14)
- ipNextHopIPv4Address (15)
- bgpSourceAsNumber (16)
- bgpDestinationAsNumber (17)
- bgpNextHopIPv4Address (18)
- flowEndSysUpTime (21)
- flowStartSysUpTime (22)

### Multi-Flow Configuration

You can define multiple flows of different versions in a single configuration:

```yaml
flows:
  - version: v5
    flowsets:
      - src_addr: "192.168.1.10"
        dst_addr: "10.0.0.50"
        # ... other v5 fields

  - version: v9
    flowsets:
      - type: template
        template_id: 256
        fields:
          # ... template fields
      - type: data
        template_id: 256
        records:
          # ... data records

  - version: ipfix
    flowsets:
      - type: template
        template_id: 300
        fields:
          # ... template fields
      - type: data
        template_id: 300
        records:
          # ... data records

destination:
  ip: "127.0.0.1"
  port: 2055
```

## Default Sample Packets

When no configuration is provided, the generator creates realistic sample traffic:

### NetFlow v5
- HTTPS flow: 192.168.1.100:52341 → 172.217.14.206:443
- 150 packets, 95KB transferred
- TCP with ACK+PSH flags
- Google AS (15169)

### NetFlow v7
- DNS query: 10.0.0.50:54123 → 8.8.8.8:53
- 2 packets, 128 bytes
- UDP protocol
- Google DNS server

### NetFlow v9
- HTTP flow: 192.168.10.5:48921 → 93.184.216.34:80
- Template ID 256 with 7 fields
- 50 packets, 35KB transferred
- TCP protocol

### IPFIX
- SSH session: 172.20.0.100:50122 → 198.51.100.10:22
- Template ID 300 with 7 fields
- 500 packets, 125KB transferred
- TCP protocol

## Examples

All example YAML files are available in the `examples/` directory:

- `v5_sample.yaml` - NetFlow v5 configuration
- `v7_sample.yaml` - NetFlow v7 configuration
- `v9_sample.yaml` - NetFlow v9 with template and data
- `ipfix_sample.yaml` - IPFIX with template and data
- `multi_flow.yaml` - Multiple NetFlow versions in one config

Run an example:

```bash
# Using compiled binary
netflow_generator --config examples/v9_sample.yaml --verbose

# Using cargo run
cargo run -- --config examples/v9_sample.yaml --verbose
```

## Testing with NetFlow Collectors

### Using nfdump

```bash
# Start nfcapd collector
nfcapd -l /tmp/nfcapd -p 2055

# In another terminal, send flows continuously (using compiled binary)
netflow_generator --config examples/v9_sample.yaml

# Or send once and exit
netflow_generator --config examples/v9_sample.yaml --once

# Or using cargo run
cargo run -- --config examples/v9_sample.yaml
cargo run -- --config examples/v9_sample.yaml --once

# Read captured flows (Ctrl+C to stop generator first)
nfdump -r /tmp/nfcapd/nfcapd.current
```

### Using Wireshark

1. Start Wireshark capture on loopback interface
2. Apply filter: `udp.port == 2055`
3. Run the generator (continuously by default):
   ```bash
   # Using compiled binary (continuous mode)
   netflow_generator --verbose

   # Or single-shot mode
   netflow_generator --verbose --once

   # Using cargo run
   cargo run -- --verbose
   cargo run -- --verbose --once
   ```
4. Analyze captured NetFlow packets in Wireshark
5. Press Ctrl+C to stop the generator if running in continuous mode

## Architecture

The project is organized into several modules:

- **cli**: Command-line argument parsing using Clap
- **config**: YAML schema definition, parsing, and validation
- **generator**: Packet generation for each NetFlow version
  - `v5.rs` - NetFlow v5 packet builder
  - `v7.rs` - NetFlow v7 packet builder
  - `v9.rs` - NetFlow v9 template and data packet builder
  - `ipfix.rs` - IPFIX template and data packet builder
  - `samples.rs` - Default sample packet definitions
  - `field_serializer.rs` - Field value serialization helpers
- **transmitter**: UDP transmission and file output
- **error**: Custom error types using thiserror

## Dependencies

- `netflow_parser` (0.7.0) - NetFlow packet structures
- `serde_yaml` (0.9) - YAML parsing
- `serde` (1.0) - Serialization framework
- `clap` (4.5) - CLI argument parsing
- `tokio` (1.42) - Async runtime for networking
- `thiserror` (2.0) - Custom error types

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Uses the `netflow_parser` crate for NetFlow packet structures
- NetFlow v5/v7/v9 specifications from Cisco
- IPFIX specification from RFC 7011
