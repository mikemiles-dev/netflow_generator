mod cli;
mod config;
mod error;
mod generator;
mod transmitter;

use clap::Parser;
use cli::Cli;
use config::{FlowConfig, parse_yaml_file, validate_config};
use error::Result;
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Cli::parse();

    // Configure rayon thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .map_err(|e| {
            error::NetflowError::Configuration(format!("Failed to configure thread pool: {}", e))
        })?;

    if args.verbose {
        println!("NetFlow Generator starting...");
        println!("Using {} threads for parallel processing", args.threads);
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

        // Set up Ctrl+C handler for graceful shutdown
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        ctrlc::set_handler(move || {
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .map_err(|e| {
            error::NetflowError::Configuration(format!("Failed to set Ctrl+C handler: {}", e))
        })?;

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

        // Get destination (needed for both UDP transmission and pcap file generation)
        let destination = parse_destination(&args)?;

        // Create persistent pcap writer if output path is specified
        let mut pcap_writer = if let Some(ref output_path) = args.output {
            Some(transmitter::PersistentPcapWriter::new(
                output_path,
                destination,
                args.verbose,
            )?)
        } else {
            None
        };

        // Loop until shutdown signal received
        let mut iteration = 1;
        loop {
            // Check for shutdown signal
            if shutdown.load(Ordering::Relaxed) {
                if args.verbose {
                    println!("\nReceived shutdown signal, exiting gracefully...");
                }
                break;
            }

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
            if let Some(ref mut writer) = pcap_writer {
                writer.write_packets(&packets)?;
            } else {
                if args.verbose {
                    println!("Transmitting packets to {}", destination);
                }
                transmitter::send_udp(&packets, destination, args.verbose)?;
            }

            iteration += 1;

            // Sleep for the specified interval, checking for shutdown periodically
            let sleep_start = std::time::Instant::now();
            let sleep_duration = Duration::from_secs(interval_secs);

            while sleep_start.elapsed() < sleep_duration {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }

        // Close pcap writer if it exists
        if let Some(writer) = pcap_writer {
            writer.close()?;
        }

        if args.verbose {
            println!("Shutdown complete.");
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

    // Get destination (needed for both UDP transmission and pcap file generation)
    let destination = parse_destination(args)?;

    // Output packets
    if let Some(ref output_path) = args.output {
        // Write to pcap file (always first write in single-shot mode)
        transmitter::write_to_file(&packets, output_path, destination, args.verbose, true)?;
    } else {
        // Send via UDP
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
    // Process flows in parallel using rayon
    let results: Result<Vec<Vec<Vec<u8>>>> = config
        .flows
        .par_iter()
        .map(|flow| match flow {
            FlowConfig::V5(v5_config) => {
                if verbose {
                    println!("Generating NetFlow V5 packet...");
                }
                let packet = generator::build_v5_packet(v5_config.clone())?;
                Ok(vec![packet])
            }
            FlowConfig::V7(v7_config) => {
                if verbose {
                    println!("Generating NetFlow V7 packet...");
                }
                let packet = generator::build_v7_packet(v7_config.clone())?;
                Ok(vec![packet])
            }
            FlowConfig::V9(v9_config) => {
                if verbose {
                    println!("Generating NetFlow V9 packet(s)...");
                }
                let packets = generator::build_v9_packets(v9_config.clone())?;
                Ok(packets)
            }
            FlowConfig::IPFix(ipfix_config) => {
                if verbose {
                    println!("Generating IPFIX packet(s)...");
                }
                let packets = generator::build_ipfix_packets(ipfix_config.clone())?;
                Ok(packets)
            }
        })
        .collect();

    // Flatten the results into a single vector
    let all_packets: Vec<Vec<u8>> = results?.into_iter().flatten().collect();

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
