mod cli;
mod config;
mod error;
mod generator;
mod transmitter;

use clap::Parser;
use cli::Cli;
use config::{FlowConfig, parse_yaml_file, validate_config};
use error::Result;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Cli::parse();

    if args.verbose {
        println!("NetFlow Generator starting...");
    }

    // Check if we're in single-shot mode or continuous mode
    if args.once {
        // Single-shot mode
        run_once(&args)?;
    } else {
        // Continuous mode (default)
        let interval_secs = args.interval.unwrap_or(2);
        if args.verbose {
            println!(
                "Continuous mode: sending flows every {} seconds (Ctrl+C to stop)",
                interval_secs
            );
        }

        // Load config once if provided
        let config = if let Some(ref config_path) = args.config {
            if args.verbose {
                println!("Loading configuration from {:?}", config_path);
            }
            let cfg = parse_yaml_file(config_path)?;
            validate_config(&cfg)?;
            if args.verbose {
                println!("Configuration loaded: {} flow(s)", cfg.flows.len());
            }
            Some(cfg)
        } else {
            if args.verbose {
                println!("No configuration provided, using default samples");
            }
            None
        };

        // Get destination once
        let destination = if args.output.is_none() {
            Some(parse_destination(&args)?)
        } else {
            None
        };

        // Loop indefinitely
        let mut iteration = 1;
        loop {
            if args.verbose {
                println!("\n--- Iteration {} ---", iteration);
            }

            // Generate packets
            let packets = if let Some(ref cfg) = config {
                generate_packets_from_config(cfg, args.verbose)?
            } else {
                generator::generate_all_samples()?
            };

            if args.verbose {
                println!("Generated {} packet(s)", packets.len());
            }

            // Output packets
            if let Some(ref output_path) = args.output {
                // Append iteration number to filename for continuous file writes
                let output_with_iteration = if iteration > 1 {
                    let mut path = output_path.clone();
                    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                    let ext = path
                        .extension()
                        .map(|e| format!(".{}", e.to_string_lossy()))
                        .unwrap_or_default();
                    path.set_file_name(format!("{}_{}{}", stem, iteration, ext));
                    path
                } else {
                    output_path.clone()
                };
                transmitter::write_to_file(&packets, &output_with_iteration, args.verbose)?;
            } else if let Some(dest) = destination {
                if args.verbose {
                    println!("Transmitting packets to {}", dest);
                }
                transmitter::send_udp(&packets, dest, args.verbose)?;
            }

            iteration += 1;

            // Sleep for the specified interval
            if args.verbose {
                println!("Sleeping for {} seconds...", interval_secs);
            }
            thread::sleep(Duration::from_secs(interval_secs));
        }
    }

    Ok(())
}

fn run_once(args: &Cli) -> Result<()> {
    // Generate or load packets
    let packets = if let Some(ref config_path) = args.config {
        // Load and parse YAML configuration
        if args.verbose {
            println!("Loading configuration from {:?}", config_path);
        }

        let config = parse_yaml_file(config_path)?;
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
    if let Some(ref output_path) = args.output {
        // Write to file
        transmitter::write_to_file(&packets, output_path, args.verbose)?;
    } else {
        // Send via UDP
        let destination = parse_destination(args)?;

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
        dest_str.parse().map_err(|e| {
            error::NetflowError::InvalidDestination(format!(
                "Invalid destination '{}': {}",
                dest_str, e
            ))
        })
    } else {
        // Use default
        "127.0.0.1:2055".parse().map_err(|e| {
            error::NetflowError::InvalidDestination(format!("Invalid default destination: {}", e))
        })
    }
}
