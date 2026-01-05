use crate::config::schema::{FlowConfig, IPFixConfig, V9Config};
use crate::error::{NetflowError, Result};
use crate::generator;
use std::collections::HashMap;

/// Cache for storing generated template packets
/// Ensures templates are generated once and reused across iterations
#[derive(Debug)]
pub struct TemplateCache {
    /// V9 template packets keyed by source_id
    v9_templates: HashMap<u32, Vec<u8>>,
    /// IPFIX template packets keyed by observation_domain_id
    ipfix_templates: HashMap<u32, Vec<u8>>,
}

impl TemplateCache {
    /// Create a new empty template cache
    pub fn new() -> Self {
        Self {
            v9_templates: HashMap::new(),
            ipfix_templates: HashMap::new(),
        }
    }

    /// Build template cache from configuration
    /// This validates that there are no template_id collisions and generates all template packets
    pub fn from_config(flows: &[FlowConfig], verbose: bool) -> Result<Self> {
        let mut cache = Self::new();

        // Group flows by exporter to validate and cache templates
        let mut v9_by_source: HashMap<u32, Vec<&V9Config>> = HashMap::new();
        let mut ipfix_by_domain: HashMap<u32, Vec<&IPFixConfig>> = HashMap::new();

        // Group flows by their exporter IDs
        for flow in flows {
            match flow {
                FlowConfig::V9(config) => {
                    let source_id = config
                        .header
                        .as_ref()
                        .and_then(|h| h.source_id)
                        .unwrap_or(1);
                    v9_by_source.entry(source_id).or_default().push(config);
                }
                FlowConfig::IPFix(config) => {
                    let obs_domain_id = config
                        .header
                        .as_ref()
                        .and_then(|h| h.observation_domain_id)
                        .unwrap_or(1);
                    ipfix_by_domain
                        .entry(obs_domain_id)
                        .or_default()
                        .push(config);
                }
                _ => {} // V5 and V7 don't have templates
            }
        }

        // Build and validate V9 templates
        for (source_id, configs) in v9_by_source {
            let template_packet = build_v9_template_cache(source_id, &configs, verbose)?;
            cache.v9_templates.insert(source_id, template_packet);
        }

        // Build and validate IPFIX templates
        for (obs_domain_id, configs) in ipfix_by_domain {
            let template_packet = build_ipfix_template_cache(obs_domain_id, &configs, verbose)?;
            cache.ipfix_templates.insert(obs_domain_id, template_packet);
        }

        if verbose && (!cache.v9_templates.is_empty() || !cache.ipfix_templates.is_empty()) {
            println!("Template cache built:");
            if !cache.v9_templates.is_empty() {
                println!("  V9 templates: {} exporter(s)", cache.v9_templates.len());
            }
            if !cache.ipfix_templates.is_empty() {
                println!(
                    "  IPFIX templates: {} exporter(s)",
                    cache.ipfix_templates.len()
                );
            }
        }

        Ok(cache)
    }

    /// Get all V9 template packets (for sending to network)
    pub fn v9_templates(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.v9_templates.values()
    }

    /// Get all IPFIX template packets (for sending to network)
    pub fn ipfix_templates(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.ipfix_templates.values()
    }
}

/// Build a V9 template packet from multiple configs with the same source_id
/// Validates that there are no template_id collisions
fn build_v9_template_cache(
    source_id: u32,
    configs: &[&V9Config],
    verbose: bool,
) -> Result<Vec<u8>> {
    use std::collections::HashSet;

    // Collect all templates and validate no collisions
    let mut template_map: HashMap<u16, Vec<crate::config::schema::V9TemplateField>> =
        HashMap::new();
    let mut seen_template_ids = HashSet::new();

    for config in configs {
        for flowset in &config.flowsets {
            if let crate::config::schema::V9FlowSet::Template {
                template_id,
                fields,
            } = flowset
            {
                if !seen_template_ids.insert(*template_id) {
                    // Check if the fields are identical
                    if let Some(existing_fields) = template_map.get(template_id)
                        && existing_fields != fields
                    {
                        return Err(NetflowError::Configuration(format!(
                            "Template ID {} is used with different field definitions in source_id {}",
                            template_id, source_id
                        )));
                    }
                } else {
                    template_map.insert(*template_id, fields.clone());
                }
            }
        }
    }

    if template_map.is_empty() {
        return Err(NetflowError::Configuration(format!(
            "No templates found for V9 source_id {}",
            source_id
        )));
    }

    if verbose {
        println!(
            "  Building V9 template cache for source_id={} ({} template(s))",
            source_id,
            template_map.len()
        );
    }

    // Build the template packet using the generator's function
    // We'll call the existing build_template_packet function
    let templates: Vec<(u16, Vec<crate::config::schema::V9TemplateField>)> =
        template_map.into_iter().collect();

    // Get current time for header
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| NetflowError::Generation(format!("Failed to get system time: {}", e)))?;
    let unix_secs = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);
    let sys_up_time = 360000; // Default value

    generator::v9::build_template_packet_for_cache(
        sys_up_time,
        unix_secs,
        0, // sequence number (templates don't affect sequence)
        source_id,
        &templates,
    )
}

/// Build an IPFIX template packet from multiple configs with the same observation_domain_id
/// Validates that there are no template_id collisions
fn build_ipfix_template_cache(
    observation_domain_id: u32,
    configs: &[&IPFixConfig],
    verbose: bool,
) -> Result<Vec<u8>> {
    use std::collections::HashSet;

    // Collect all templates and validate no collisions
    let mut template_map: HashMap<u16, Vec<crate::config::schema::IPFixTemplateField>> =
        HashMap::new();
    let mut seen_template_ids = HashSet::new();

    for config in configs {
        for flowset in &config.flowsets {
            if let crate::config::schema::IPFixFlowSet::Template {
                template_id,
                fields,
            } = flowset
            {
                if !seen_template_ids.insert(*template_id) {
                    // Check if the fields are identical
                    if let Some(existing_fields) = template_map.get(template_id)
                        && existing_fields != fields
                    {
                        return Err(NetflowError::Configuration(format!(
                            "Template ID {} is used with different field definitions in observation_domain_id {}",
                            template_id, observation_domain_id
                        )));
                    }
                } else {
                    template_map.insert(*template_id, fields.clone());
                }
            }
        }
    }

    if template_map.is_empty() {
        return Err(NetflowError::Configuration(format!(
            "No templates found for IPFIX observation_domain_id {}",
            observation_domain_id
        )));
    }

    if verbose {
        println!(
            "  Building IPFIX template cache for observation_domain_id={} ({} template(s))",
            observation_domain_id,
            template_map.len()
        );
    }

    // Build the template packet using the generator's function
    let templates: Vec<(u16, Vec<crate::config::schema::IPFixTemplateField>)> =
        template_map.into_iter().collect();

    // Get current time for header
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| NetflowError::Generation(format!("Failed to get system time: {}", e)))?;
    let export_time = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);

    generator::ipfix::build_template_packet_for_cache(
        export_time,
        0, // sequence number (templates don't affect sequence)
        observation_domain_id,
        &templates,
    )
}
