/// Helper functions for serializing NetFlow field values
use std::net::Ipv4Addr;

/// Serialize a field value based on its length
pub fn serialize_field_value(value: &serde_yaml::Value, field_length: u16) -> Vec<u8> {
    match value {
        // String values might be IP addresses
        serde_yaml::Value::String(s) => {
            // Try to parse as IPv4
            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                ip.octets().to_vec()
            } else {
                // Otherwise treat as hex string or raw bytes
                vec![0; field_length as usize]
            }
        }
        // Number values
        serde_yaml::Value::Number(n) => {
            if let Some(val) = n.as_u64() {
                match field_length {
                    1 => vec![val as u8],
                    2 => (val as u16).to_be_bytes().to_vec(),
                    4 => (val as u32).to_be_bytes().to_vec(),
                    8 => val.to_be_bytes().to_vec(),
                    _ => vec![0; field_length as usize],
                }
            } else {
                vec![0; field_length as usize]
            }
        }
        _ => vec![0; field_length as usize],
    }
}

/// Get field value from a YAML mapping by field name
pub fn get_field_value(
    record: &serde_yaml::Value,
    field_name: &str,
) -> Option<serde_yaml::Value> {
    if let serde_yaml::Value::Mapping(map) = record {
        map.get(serde_yaml::Value::String(field_name.to_string()))
            .cloned()
    } else {
        None
    }
}

/// Map V9 field type ID to common field names
pub fn v9_field_id_to_name(field_type: u16) -> &'static str {
    match field_type {
        1 => "in_bytes",
        2 => "in_pkts",
        3 => "flows",
        4 => "protocol",
        5 => "src_tos",
        6 => "tcp_flags",
        7 => "src_port",
        8 => "src_addr",
        9 => "src_mask",
        10 => "input_snmp",
        11 => "dst_port",
        12 => "dst_addr",
        13 => "dst_mask",
        14 => "output_snmp",
        15 => "next_hop",
        16 => "src_as",
        17 => "dst_as",
        18 => "bgp_next_hop",
        19 => "mul_dst_pkts",
        20 => "mul_dst_bytes",
        21 => "last_switched",
        22 => "first_switched",
        23 => "out_bytes",
        24 => "out_pkts",
        _ => "unknown",
    }
}

/// Map IPFIX field type ID to common field names
pub fn ipfix_field_id_to_name(field_type: u16) -> &'static str {
    match field_type {
        1 => "octet_delta_count",
        2 => "packet_delta_count",
        3 => "delta_flow_count",
        4 => "protocol_identifier",
        5 => "ip_class_of_service",
        6 => "tcp_control_bits",
        7 => "source_transport_port",
        8 => "source_ipv4_address",
        9 => "source_ipv4_prefix_length",
        10 => "ingress_interface",
        11 => "destination_transport_port",
        12 => "destination_ipv4_address",
        13 => "destination_ipv4_prefix_length",
        14 => "egress_interface",
        15 => "ip_next_hop_ipv4_address",
        16 => "bgp_source_as_number",
        17 => "bgp_destination_as_number",
        18 => "bgp_next_hop_ipv4_address",
        21 => "flow_end_sys_up_time",
        22 => "flow_start_sys_up_time",
        _ => "unknown",
    }
}
