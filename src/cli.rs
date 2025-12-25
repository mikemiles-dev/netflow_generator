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
    /// Defaults to 127.0.0.1:2055 if not specified
    #[arg(short, long, value_name = "IP:PORT")]
    pub dest: Option<String>,

    /// Output to file instead of sending via UDP
    ///
    /// When specified, packets are written to a binary file
    /// instead of being transmitted over the network.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Enable verbose output
    ///
    /// Displays detailed information about packet generation
    /// and transmission.
    #[arg(short, long)]
    pub verbose: bool,
}
