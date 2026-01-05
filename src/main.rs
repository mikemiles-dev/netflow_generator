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

/// Identifier for grouping flows by exporter
/// Flows with the same ExporterId must be processed sequentially to maintain sequence number correctness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ExporterId {
    /// V5 exporter identified by engine_type and engine_id
    V5 { engine_type: u8, engine_id: u8 },
    /// V7 flow (no exporter ID - each flow is independent)
    V7(usize),
    /// V9 exporter identified by source_id
    V9(u32),
    /// IPFIX exporter identified by observation_domain_id
    IPFix(u32),
}

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

        // Track sequence numbers across iterations for V5/V9/IPFIX
        // V5 Key: (engine_type, engine_id)
        // V9 Key: source_id
        // IPFIX Key: observation_domain_id
        let mut v5_sequence_numbers: HashMap<(u8, u8), u32> = HashMap::new();
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
                    &mut v5_sequence_numbers,
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
        let mut v5_sequence_numbers = HashMap::new();
        let mut v9_sequence_numbers = HashMap::new();
        let mut ipfix_sequence_numbers = HashMap::new();
        generate_packets_from_config(
            &config,
            &mut v5_sequence_numbers,
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
    v5_sequence_numbers: &mut HashMap<(u8, u8), u32>,
    v9_sequence_numbers: &mut HashMap<u32, u32>,
    ipfix_sequence_numbers: &mut HashMap<u32, u32>,
    send_templates: bool,
    verbose: bool,
) -> Result<Vec<Vec<u8>>> {
    use rayon::prelude::*;

    // Per-exporter parallelization: Group flows by exporter ID and process each group in parallel
    // Flows from the same exporter are processed sequentially to maintain sequence number ordering
    // Flows from different exporters can be processed in parallel for better performance

    if config.flows.is_empty() {
        return Ok(Vec::new());
    }

    // Group flows by exporter ID
    let grouped_flows = group_flows_by_exporter(&config.flows);

    if verbose {
        println!(
            "Processing {} exporter group(s) in parallel",
            grouped_flows.len()
        );
    }

    // Process groups in parallel
    let results: Vec<(ExporterId, Vec<Vec<u8>>, u32)> = grouped_flows
        .par_iter()
        .map(|(exporter_id, flows)| {
            // Get initial sequence for this exporter
            let initial_seq = match exporter_id {
                ExporterId::V5 {
                    engine_type,
                    engine_id,
                } => *v5_sequence_numbers
                    .get(&(*engine_type, *engine_id))
                    .unwrap_or(&0),
                ExporterId::V7(_) => 0, // V7 sequences not tracked across iterations
                ExporterId::V9(source_id) => *v9_sequence_numbers.get(source_id).unwrap_or(&0),
                ExporterId::IPFix(obs_domain_id) => {
                    *ipfix_sequence_numbers.get(obs_domain_id).unwrap_or(&0)
                }
            };

            if verbose {
                match exporter_id {
                    ExporterId::V5 {
                        engine_type,
                        engine_id,
                    } => {
                        println!(
                            "Processing V5 exporter (engine_type={}, engine_id={}) with {} flow(s)",
                            engine_type,
                            engine_id,
                            flows.len()
                        );
                    }
                    ExporterId::V7(index) => {
                        println!("Processing V7 flow #{}", index);
                    }
                    ExporterId::V9(source_id) => {
                        println!(
                            "Processing V9 exporter (source_id={}) with {} flow(s)",
                            source_id,
                            flows.len()
                        );
                    }
                    ExporterId::IPFix(obs_domain_id) => {
                        println!(
                            "Processing IPFIX exporter (observation_domain_id={}) with {} flow(s)",
                            obs_domain_id,
                            flows.len()
                        );
                    }
                }
            }

            let (packets, next_seq) =
                process_exporter_group(flows, initial_seq, send_templates, verbose)?;

            Ok((*exporter_id, packets, next_seq))
        })
        .collect::<Result<Vec<_>>>()?;

    // Merge results and update sequence numbers
    let mut all_packets = Vec::new();

    for (exporter_id, packets, next_seq) in results {
        all_packets.extend(packets);

        // Update sequence tracking for V5/V9/IPFIX
        match exporter_id {
            ExporterId::V5 {
                engine_type,
                engine_id,
            } => {
                v5_sequence_numbers.insert((engine_type, engine_id), next_seq);
            }
            ExporterId::V9(source_id) => {
                v9_sequence_numbers.insert(source_id, next_seq);
            }
            ExporterId::IPFix(obs_domain_id) => {
                ipfix_sequence_numbers.insert(obs_domain_id, next_seq);
            }
            ExporterId::V7(_) => {
                // No tracking for V7
            }
        }
    }

    if verbose {
        println!("Generated {} packet(s) total", all_packets.len());
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

/// Extract exporter ID from a flow config
fn extract_exporter_id(flow: &FlowConfig, index: usize) -> ExporterId {
    match flow {
        FlowConfig::V5(config) => {
            let engine_type = config
                .header
                .as_ref()
                .and_then(|h| h.engine_type)
                .unwrap_or(0);
            let engine_id = config
                .header
                .as_ref()
                .and_then(|h| h.engine_id)
                .unwrap_or(0);
            ExporterId::V5 {
                engine_type,
                engine_id,
            }
        }
        FlowConfig::V7(_) => ExporterId::V7(index),
        FlowConfig::V9(config) => {
            let source_id = config
                .header
                .as_ref()
                .and_then(|h| h.source_id)
                .unwrap_or(1);
            ExporterId::V9(source_id)
        }
        FlowConfig::IPFix(config) => {
            let observation_domain_id = config
                .header
                .as_ref()
                .and_then(|h| h.observation_domain_id)
                .unwrap_or(1);
            ExporterId::IPFix(observation_domain_id)
        }
    }
}

/// Group flows by exporter ID for parallel processing
fn group_flows_by_exporter(flows: &[FlowConfig]) -> HashMap<ExporterId, Vec<FlowConfig>> {
    let mut groups: HashMap<ExporterId, Vec<FlowConfig>> = HashMap::new();

    for (index, flow) in flows.iter().enumerate() {
        let exporter_id = extract_exporter_id(flow, index);
        groups.entry(exporter_id).or_default().push(flow.clone());
    }

    groups
}

/// Process all flows for a single exporter group sequentially
fn process_exporter_group(
    flows: &[FlowConfig],
    initial_sequence: u32,
    send_templates: bool,
    verbose: bool,
) -> Result<(Vec<Vec<u8>>, u32)> {
    let mut packets = Vec::new();
    let mut current_seq = initial_sequence;

    for flow in flows {
        match flow {
            FlowConfig::V5(v5_config) => {
                if verbose {
                    println!("  Generating NetFlow V5 packet...");
                }
                let packet = generator::build_v5_packet(v5_config.clone(), Some(current_seq))?;
                packets.push(packet);

                // V5 sequence increments by number of flow records in packet
                let num_records = u32::try_from(v5_config.flowsets.len()).map_err(|_| {
                    error::NetflowError::Generation("Too many V5 flowsets".to_string())
                })?;
                current_seq = current_seq.checked_add(num_records).ok_or_else(|| {
                    error::NetflowError::Generation("Sequence number overflow".to_string())
                })?;
            }
            FlowConfig::V7(v7_config) => {
                if verbose {
                    println!("  Generating NetFlow V7 packet...");
                }
                let packet = generator::build_v7_packet(v7_config.clone())?;
                packets.push(packet);
                // No sequence tracking for V7
            }
            FlowConfig::V9(v9_config) => {
                if verbose {
                    let template_msg = if send_templates {
                        " (with templates)"
                    } else {
                        ""
                    };
                    println!("  Generating NetFlow V9 packet(s){}...", template_msg);
                }
                let (batch, next_seq) = generator::build_v9_packets(
                    v9_config.clone(),
                    Some(current_seq),
                    send_templates,
                )?;
                packets.extend(batch);
                current_seq = next_seq;
            }
            FlowConfig::IPFix(ipfix_config) => {
                if verbose {
                    let template_msg = if send_templates {
                        " (with templates)"
                    } else {
                        ""
                    };
                    println!("  Generating IPFIX packet(s){}...", template_msg);
                }
                let (batch, next_seq) = generator::build_ipfix_packets(
                    ipfix_config.clone(),
                    Some(current_seq),
                    send_templates,
                )?;
                packets.extend(batch);
                current_seq = next_seq;
            }
        }
    }

    Ok((packets, current_seq))
}
