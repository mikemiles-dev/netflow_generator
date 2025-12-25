use crate::config::schema::Config;
use crate::error::{NetflowError, Result};
use std::fs;
use std::path::Path;

/// Parse a YAML configuration file
pub fn parse_yaml_file<P: AsRef<Path>>(path: P) -> Result<Config> {
    let contents = fs::read_to_string(path)?;
    parse_yaml_str(&contents)
}

/// Parse a YAML configuration string
pub fn parse_yaml_str(contents: &str) -> Result<Config> {
    let config: Config = serde_yaml::from_str(contents)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_v5() {
        let yaml = r#"
flows:
  - version: v5
    flowsets:
      - src_addr: "192.168.1.10"
        dst_addr: "10.0.0.50"
        next_hop: "192.168.1.1"
        input: 1
        output: 2
        d_pkts: 100
        d_octets: 65000
        first: 350000
        last: 360000
        src_port: 54321
        dst_port: 443
        tcp_flags: 0x18
        protocol: 6
        tos: 0
        src_as: 65001
        dst_as: 65002
        src_mask: 24
        dst_mask: 24
"#;

        let config = parse_yaml_str(yaml).unwrap();
        assert_eq!(config.flows.len(), 1);
    }
}
