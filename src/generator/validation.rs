//! Template validation helpers using netflow_parser 0.8.0
//!
//! These helpers validate that generated V9 and IPFIX templates
//! are well-formed and can be parsed correctly.

use crate::error::{NetflowError, Result};
use netflow_parser::NetflowParser;

/// Validate that a generated V9 template packet is well-formed
///
/// This uses netflow_parser's enhanced template validation to verify
/// that the generated template follows NetFlow V9 specifications.
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_v9_template(template_packet: &[u8]) -> Result<()> {
    let mut parser = NetflowParser::default();
    let parse_result = parser.parse_bytes(template_packet);

    // Check for parsing errors
    if let Some(error) = parse_result.error {
        return Err(NetflowError::ValidationError(format!(
            "Invalid V9 template: {:?}",
            error
        )));
    }

    // Verify we got at least one packet
    if parse_result.packets.is_empty() {
        return Err(NetflowError::ValidationError(
            "No packets found in V9 template".to_string(),
        ));
    }

    // Verify all packets are V9
    for packet in &parse_result.packets {
        match packet {
            netflow_parser::NetflowPacket::V9(_) => {
                // Template parsed successfully and passed validation
            }
            _ => {
                return Err(NetflowError::ValidationError(
                    "Expected V9 packet, got different NetFlow version".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Validate that a generated IPFIX template packet is well-formed
///
/// This uses netflow_parser's enhanced template validation to verify
/// that the generated template follows IPFIX specifications (RFC 7011).
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_ipfix_template(template_packet: &[u8]) -> Result<()> {
    let mut parser = NetflowParser::default();
    let parse_result = parser.parse_bytes(template_packet);

    // Check for parsing errors
    if let Some(error) = parse_result.error {
        return Err(NetflowError::ValidationError(format!(
            "Invalid IPFIX template: {:?}",
            error
        )));
    }

    // Verify we got at least one packet
    if parse_result.packets.is_empty() {
        return Err(NetflowError::ValidationError(
            "No packets found in IPFIX template".to_string(),
        ));
    }

    // Verify all packets are IPFIX
    for packet in &parse_result.packets {
        match packet {
            netflow_parser::NetflowPacket::IPFix(_) => {
                // Template parsed successfully and passed validation
            }
            _ => {
                return Err(NetflowError::ValidationError(
                    "Expected IPFIX packet, got different NetFlow version".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_validation_module_compiles() {
        // This test verifies the validation module compiles correctly.
        // Actual validation tests are in the V9 and IPFIX generator test modules.
        assert!(true);
    }
}
