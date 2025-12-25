mod cli;
mod config;
mod error;
mod generator;
mod transmitter;

use clap::Parser;
use cli::Cli;
use config::{parse_yaml_file, validate_config, FlowConfig};
use error::Result;
use std::net::SocketAddr;

fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Cli::parse();

    if args.verbose {
        println!("NetFlow Generator starting...");
    }

    // Generate or load packets
    let packets = if let Some(ref config_path) = args.config {
        // Load and parse YAML configuration
        if args.verbose {
            println!("Loading configuration from {:?}", config_path);
        }

        let config = parse_yaml_file(&config_path)?;
        validate_config(&config)?;

        if args.verbose {
            println!("Configuration loaded: {} flow(s)", config.flows.len());
        }

        // Generate packets from config
        generate_packets_from_config(&config, args.verbose)?
    } else {
        // Use default samples
        if args.verbose {
            println!("No configuration provided, using default samples");
        }

        generator::generate_all_samples()?
    };

    if args.verbose {
        println!("Generated {} packet(s)", packets.len());
    }

    // Output packets
    if let Some(output_path) = args.output {
        // Write to file
        transmitter::write_to_file(&packets, &output_path, args.verbose)?;
    } else {
        // Send via UDP
        let destination = parse_destination(&args)?;

        if args.verbose {
            println!("Transmitting packets to {}", destination);
        }

        transmitter::send_udp(&packets, destination, args.verbose)?;
    }

    if args.verbose {
        println!("Done!");
    }

    Ok(())
}

fn generate_packets_from_config(config: &config::Config, verbose: bool) -> Result<Vec<Vec<u8>>> {
    let mut all_packets = Vec::new();

    for flow in &config.flows {
        match flow {
            FlowConfig::V5(v5_config) => {
                if verbose {
                    println!("Generating NetFlow V5 packet...");
                }
                let packet = generator::build_v5_packet(v5_config.clone())?;
                all_packets.push(packet);
            }
            FlowConfig::V7(v7_config) => {
                if verbose {
                    println!("Generating NetFlow V7 packet...");
                }
                let packet = generator::build_v7_packet(v7_config.clone())?;
                all_packets.push(packet);
            }
            FlowConfig::V9(v9_config) => {
                if verbose {
                    println!("Generating NetFlow V9 packet(s)...");
                }
                let packets = generator::build_v9_packets(v9_config.clone())?;
                all_packets.extend(packets);
            }
            FlowConfig::IPFix(ipfix_config) => {
                if verbose {
                    println!("Generating IPFIX packet(s)...");
                }
                let packets = generator::build_ipfix_packets(ipfix_config.clone())?;
                all_packets.extend(packets);
            }
        }
    }

    Ok(all_packets)
}

fn parse_destination(args: &Cli) -> Result<SocketAddr> {
    if let Some(ref dest_str) = args.dest {
        // Parse from CLI argument
        dest_str
            .parse()
            .map_err(|e| error::NetflowError::InvalidDestination(format!("Invalid destination '{}': {}", dest_str, e)))
    } else {
        // Use default
        "127.0.0.1:2055"
            .parse()
            .map_err(|e| error::NetflowError::InvalidDestination(format!("Invalid default destination: {}", e)))
    }
}
