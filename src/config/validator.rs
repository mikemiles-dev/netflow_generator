use crate::config::schema::Config;
use crate::error::{NetflowError, Result};

/// Validate a configuration
pub fn validate_config(config: &Config) -> Result<()> {
    // Check that we have at least one flow
    if config.flows.is_empty() {
        return Err(NetflowError::Validation(
            "Configuration must contain at least one flow".to_string(),
        ));
    }

    // Validate destination
    validate_destination(&config.destination)?;

    Ok(())
}

/// Validate destination configuration
fn validate_destination(dest: &crate::config::schema::Destination) -> Result<()> {
    // Validate IP address format
    if dest.ip.parse::<std::net::IpAddr>().is_err() {
        return Err(NetflowError::Validation(format!(
            "Invalid IP address: {}",
            dest.ip
        )));
    }

    // Port is already validated by its type (u16)

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Destination, FlowConfig, V5Config, V5FlowSet};
    use std::net::Ipv4Addr;

    #[test]
    fn test_validate_empty_flows() {
        let config = Config {
            flows: vec![],
            destination: Destination::default(),
        };

        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_invalid_ip() {
        let mut config = Config {
            flows: vec![FlowConfig::V5(V5Config {
                header: None,
                flowsets: vec![V5FlowSet {
                    src_addr: Ipv4Addr::new(192, 168, 1, 10),
                    dst_addr: Ipv4Addr::new(10, 0, 0, 50),
                    next_hop: Ipv4Addr::new(192, 168, 1, 1),
                    input: 1,
                    output: 2,
                    d_pkts: 100,
                    d_octets: 65000,
                    first: 350000,
                    last: 360000,
                    src_port: 54321,
                    dst_port: 443,
                    tcp_flags: 0x18,
                    protocol: 6,
                    tos: 0,
                    src_as: 65001,
                    dst_as: 65002,
                    src_mask: 24,
                    dst_mask: 24,
                }],
            })],
            destination: Destination::default(),
        };

        config.destination.ip = "invalid_ip".to_string();
        assert!(validate_config(&config).is_err());
    }
}
