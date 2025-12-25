use crate::config::schema::{
    IPFixConfig, IPFixFlowSet, IPFixTemplateField, V5Config, V5FlowSet, V7Config, V7FlowSet,
    V9Config, V9FlowSet, V9TemplateField,
};
use crate::error::Result;
use std::net::Ipv4Addr;

/// Generate sample V5 configuration
/// Represents HTTPS traffic: 192.168.1.100:52341 -> 172.217.14.206:443
pub fn sample_v5_config() -> V5Config {
    V5Config {
        header: None, // Use defaults
        flowsets: vec![V5FlowSet {
            src_addr: Ipv4Addr::new(192, 168, 1, 100),
            dst_addr: Ipv4Addr::new(172, 217, 14, 206), // Google IP
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            input: 1,
            output: 2,
            d_pkts: 150,
            d_octets: 95000,
            first: 350000,
            last: 360000,
            src_port: 52341,
            dst_port: 443,   // HTTPS
            tcp_flags: 0x18, // ACK + PSH
            protocol: 6,     // TCP
            tos: 0,
            src_as: 65000,
            dst_as: 15169, // Google ASN
            src_mask: 24,
            dst_mask: 24,
        }],
    }
}

/// Generate sample V7 configuration
/// Represents DNS traffic: 10.0.0.50:54123 -> 8.8.8.8:53
pub fn sample_v7_config() -> V7Config {
    V7Config {
        header: None, // Use defaults
        flowsets: vec![V7FlowSet {
            src_addr: Ipv4Addr::new(10, 0, 0, 50),
            dst_addr: Ipv4Addr::new(8, 8, 8, 8), // Google DNS
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            input: 10,
            output: 20,
            d_pkts: 2,
            d_octets: 128,
            first: 355000,
            last: 355100,
            src_port: 54123,
            dst_port: 53, // DNS
            flags: 0,
            tcp_flags: 0,
            protocol: 17, // UDP
            tos: 0,
            src_as: 64512,
            dst_as: 15169, // Google ASN
            src_mask: 16,
            dst_mask: 8,
            flags2: 0,
            router_src: Ipv4Addr::new(10, 0, 0, 1),
        }],
    }
}

/// Generate sample V9 configuration
/// Represents HTTP traffic: 192.168.10.5:48921 -> 93.184.216.34:80
pub fn sample_v9_config() -> V9Config {
    use serde_yaml::Value;

    V9Config {
        header: None, // Use defaults
        flowsets: vec![
            // Template definition
            V9FlowSet::Template {
                template_id: 256,
                fields: vec![
                    V9TemplateField {
                        field_type: "IPV4_SRC_ADDR".to_string(),
                        field_length: 4,
                    },
                    V9TemplateField {
                        field_type: "IPV4_DST_ADDR".to_string(),
                        field_length: 4,
                    },
                    V9TemplateField {
                        field_type: "IN_PKTS".to_string(),
                        field_length: 4,
                    },
                    V9TemplateField {
                        field_type: "IN_BYTES".to_string(),
                        field_length: 4,
                    },
                    V9TemplateField {
                        field_type: "L4_SRC_PORT".to_string(),
                        field_length: 2,
                    },
                    V9TemplateField {
                        field_type: "L4_DST_PORT".to_string(),
                        field_length: 2,
                    },
                    V9TemplateField {
                        field_type: "PROTOCOL".to_string(),
                        field_length: 1,
                    },
                ],
            },
            // Data record
            V9FlowSet::Data {
                template_id: 256,
                records: vec![{
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        Value::String("src_addr".to_string()),
                        Value::String("192.168.10.5".to_string()),
                    );
                    map.insert(
                        Value::String("dst_addr".to_string()),
                        Value::String("93.184.216.34".to_string()),
                    );
                    map.insert(
                        Value::String("in_pkts".to_string()),
                        Value::Number(50.into()),
                    );
                    map.insert(
                        Value::String("in_bytes".to_string()),
                        Value::Number(35000.into()),
                    );
                    map.insert(
                        Value::String("src_port".to_string()),
                        Value::Number(48921.into()),
                    );
                    map.insert(
                        Value::String("dst_port".to_string()),
                        Value::Number(80.into()),
                    );
                    map.insert(
                        Value::String("protocol".to_string()),
                        Value::Number(6.into()),
                    );
                    Value::Mapping(map)
                }],
            },
        ],
    }
}

/// Generate sample IPFIX configuration
/// Represents SSH session: 172.20.0.100:50122 -> 198.51.100.10:22
pub fn sample_ipfix_config() -> IPFixConfig {
    use serde_yaml::Value;

    IPFixConfig {
        header: None, // Use defaults
        flowsets: vec![
            // Template definition
            IPFixFlowSet::Template {
                template_id: 300,
                fields: vec![
                    IPFixTemplateField {
                        field_type: "sourceIPv4Address".to_string(),
                        field_length: 4,
                    },
                    IPFixTemplateField {
                        field_type: "destinationIPv4Address".to_string(),
                        field_length: 4,
                    },
                    IPFixTemplateField {
                        field_type: "packetDeltaCount".to_string(),
                        field_length: 8,
                    },
                    IPFixTemplateField {
                        field_type: "octetDeltaCount".to_string(),
                        field_length: 8,
                    },
                    IPFixTemplateField {
                        field_type: "sourceTransportPort".to_string(),
                        field_length: 2,
                    },
                    IPFixTemplateField {
                        field_type: "destinationTransportPort".to_string(),
                        field_length: 2,
                    },
                    IPFixTemplateField {
                        field_type: "protocolIdentifier".to_string(),
                        field_length: 1,
                    },
                ],
            },
            // Data record
            IPFixFlowSet::Data {
                template_id: 300,
                records: vec![{
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        Value::String("source_ipv4_address".to_string()),
                        Value::String("172.20.0.100".to_string()),
                    );
                    map.insert(
                        Value::String("destination_ipv4_address".to_string()),
                        Value::String("198.51.100.10".to_string()),
                    );
                    map.insert(
                        Value::String("packet_delta_count".to_string()),
                        Value::Number(500.into()),
                    );
                    map.insert(
                        Value::String("octet_delta_count".to_string()),
                        Value::Number(125000.into()),
                    );
                    map.insert(
                        Value::String("source_transport_port".to_string()),
                        Value::Number(50122.into()),
                    );
                    map.insert(
                        Value::String("destination_transport_port".to_string()),
                        Value::Number(22.into()),
                    );
                    map.insert(
                        Value::String("protocol_identifier".to_string()),
                        Value::Number(6.into()),
                    );
                    Value::Mapping(map)
                }],
            },
        ],
    }
}

/// Generate all sample packets
pub fn generate_all_samples() -> Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();

    // V5 sample
    let v5_config = sample_v5_config();
    let v5_packet = crate::generator::v5::build_v5_packet(v5_config)?;
    packets.push(v5_packet);

    // V7 sample
    let v7_config = sample_v7_config();
    let v7_packet = crate::generator::v7::build_v7_packet(v7_config)?;
    packets.push(v7_packet);

    // V9 sample (may return multiple packets)
    let v9_config = sample_v9_config();
    let v9_packets = crate::generator::v9::build_v9_packets(v9_config)?;
    packets.extend(v9_packets);

    // IPFIX sample (may return multiple packets)
    let ipfix_config = sample_ipfix_config();
    let ipfix_packets = crate::generator::ipfix::build_ipfix_packets(ipfix_config)?;
    packets.extend(ipfix_packets);

    Ok(packets)
}
