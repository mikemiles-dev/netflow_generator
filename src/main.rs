mod cli;
mod config;
mod error;
mod generator;
mod transmitter;

use clap::Parser;
use cli::Cli;
use config::{FlowConfig, parse_yaml_file, validate_config};
use error::Result;
use std::collections::HashMap;
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

        // Track sequence numbers across iterations for V9/IPFIX
        // Key: (source_id for V9, observation_domain_id for IPFIX)
        let mut v9_sequence_numbers: HashMap<u32, u32> = HashMap::new();
        let mut ipfix_sequence_numbers: HashMap<u32, u32> = HashMap::new();

        // Track template refresh timing per RFC 7011/3954
        // Templates should be sent periodically (e.g., every 30 seconds) not on every packet
        let mut last_template_send = std::time::Instant::now();
        const TEMPLATE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

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

            // Determine if we should send templates this iteration
            // Send on first iteration or if 30+ seconds have elapsed since last send
            let send_templates =
                iteration == 1 || last_template_send.elapsed() >= TEMPLATE_REFRESH_INTERVAL;
            if send_templates && iteration > 1 {
                if args.verbose {
                    println!(
                        "Template refresh: {} seconds since last send",
                        last_template_send.elapsed().as_secs()
                    );
                }
                last_template_send = std::time::Instant::now();
            } else if iteration == 1 && args.verbose {
                println!("Sending initial templates");
            }

            // Generate packets
            let packets = if let Some(ref cfg) = config {
                generate_packets_from_config(
                    cfg,
                    &mut v9_sequence_numbers,
                    &mut ipfix_sequence_numbers,
                    send_templates,
                    args.verbose,
                )?
            } else {
                // For samples, use a simple counter per version
                // V9 uses source_id=1, IPFIX uses observation_domain_id=2 to avoid collisions
                let v9_seq = *v9_sequence_numbers.get(&1).unwrap_or(&0);
                let ipfix_seq = *ipfix_sequence_numbers.get(&2).unwrap_or(&0);
                let (packets, next_v9_seq, next_ipfix_seq) =
                    generator::generate_all_samples_with_seq(v9_seq, ipfix_seq, send_templates)?;
                v9_sequence_numbers.insert(1, next_v9_seq);
                ipfix_sequence_numbers.insert(2, next_ipfix_seq);
                packets
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
                transmitter::send_udp(&packets, destination, args.source_port, args.verbose)?;
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

        // Generate packets from config (single-shot mode doesn't need sequence tracking across runs)
        let mut v9_sequence_numbers = HashMap::new();
        let mut ipfix_sequence_numbers = HashMap::new();
        generate_packets_from_config(
            &config,
            &mut v9_sequence_numbers,
            &mut ipfix_sequence_numbers,
            true, // Always send templates in single-shot mode
            args.verbose,
        )?
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

        transmitter::send_udp(&packets, destination, args.source_port, args.verbose)?;
    }

    if args.verbose {
        println!("Done!");
    }

    Ok(())
}

fn generate_packets_from_config(
    config: &config::Config,
    v9_sequence_numbers: &mut HashMap<u32, u32>,
    ipfix_sequence_numbers: &mut HashMap<u32, u32>,
    send_templates: bool,
    verbose: bool,
) -> Result<Vec<Vec<u8>>> {
    // Note: We can't use rayon for V9/IPFIX because we need to track sequence numbers sequentially
    // V5 and V7 don't have sequence numbers, so they could be parallelized, but for simplicity
    // we process all flows sequentially to maintain order and proper sequence number tracking

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
                    let template_msg = if send_templates {
                        " (with templates)"
                    } else {
                        ""
                    };
                    println!("Generating NetFlow V9 packet(s){}...", template_msg);
                }
                // Get source_id from config or use default
                let source_id = v9_config
                    .header
                    .as_ref()
                    .and_then(|h| h.source_id)
                    .unwrap_or(1);

                // Get current sequence number for this source_id
                let current_seq = *v9_sequence_numbers.get(&source_id).unwrap_or(&0);

                // Generate packets with sequence number tracking
                let (packets, next_seq) = generator::build_v9_packets(
                    v9_config.clone(),
                    Some(current_seq),
                    send_templates,
                )?;

                // Update sequence number for this source_id
                v9_sequence_numbers.insert(source_id, next_seq);

                all_packets.extend(packets);
            }
            FlowConfig::IPFix(ipfix_config) => {
                if verbose {
                    let template_msg = if send_templates {
                        " (with templates)"
                    } else {
                        ""
                    };
                    println!("Generating IPFIX packet(s){}...", template_msg);
                }
                // Get observation_domain_id from config or use default
                let observation_domain_id = ipfix_config
                    .header
                    .as_ref()
                    .and_then(|h| h.observation_domain_id)
                    .unwrap_or(1);

                // Get current sequence number for this observation_domain_id
                let current_seq = *ipfix_sequence_numbers
                    .get(&observation_domain_id)
                    .unwrap_or(&0);

                // Generate packets with sequence number tracking
                let (packets, next_seq) = generator::build_ipfix_packets(
                    ipfix_config.clone(),
                    Some(current_seq),
                    send_templates,
                )?;

                // Update sequence number for this observation_domain_id
                ipfix_sequence_numbers.insert(observation_domain_id, next_seq);

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
