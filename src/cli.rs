use clap::Parser;
use std::path::PathBuf;

/// NetFlow packet generator supporting V5, V7, V9, and IPFIX formats
#[derive(Parser, Debug)]
#[command(name = "netflow_generator")]
#[command(about = "Generate and transmit NetFlow packets (V5, V7, V9, IPFIX)")]
#[command(version)]
pub struct Cli {
    /// Path to YAML configuration file
    ///
    /// If not provided, the generator will send one sample packet
    /// of each version (V5, V7, V9, IPFIX) to demonstrate functionality.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Destination IP:PORT (overrides config file destination)
    ///
    /// Format: IP:PORT (e.g., "192.168.1.100:2055")
    /// Defaults to 127.0.0.1:2055 if not specified.
    /// This is used for UDP transmission destination, or as the
    /// destination IP/port in the pcap file headers when using --output.
    #[arg(short, long, value_name = "IP:PORT")]
    pub dest: Option<String>,

    /// Output to pcap file instead of sending via UDP
    ///
    /// When specified, packets are written to a pcap file
    /// with proper Ethernet/IP/UDP headers instead of being
    /// transmitted over the network. The pcap file can be
    /// analyzed with tools like Wireshark or tcpdump.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Enable verbose output
    ///
    /// Displays detailed information about packet generation
    /// and transmission.
    #[arg(short, long)]
    pub verbose: bool,

    /// Continuously generate and send flows every N seconds (default: 2)
    ///
    /// By default, the generator runs continuously, sending flows
    /// every 2 seconds. Use --once to send flows only once.
    /// Press Ctrl+C to stop continuous mode.
    #[arg(short, long, value_name = "SECONDS", default_value = "2", default_missing_value = "2", num_args = 0..=1)]
    pub interval: Option<u64>,

    /// Send flows once and exit (disables continuous mode)
    ///
    /// Use this flag to override the default continuous behavior
    /// and send flows only once.
    #[arg(long, conflicts_with = "interval")]
    pub once: bool,
}
