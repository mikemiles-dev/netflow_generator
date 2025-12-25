use crate::config::schema::{V9Config, V9FlowSet as ConfigV9FlowSet};
use crate::error::{NetflowError, Result};
use crate::generator::field_serializer::{
    get_field_value, serialize_field_value, v9_field_id_to_name,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build NetFlow V9 packets from configuration
/// Generates proper template and data flowsets
pub fn build_v9_packets(config: V9Config) -> Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();

    // Get header values
    let (sys_up_time, unix_secs, mut sequence_number, source_id) = get_header_values(&config)?;

    // Separate templates and data flowsets
    let mut templates = Vec::new();
    let mut data_flowsets = Vec::new();

    for flowset in &config.flowsets {
        match flowset {
            ConfigV9FlowSet::Template {
                template_id,
                fields,
            } => {
                templates.push((*template_id, fields.clone()));
            }
            ConfigV9FlowSet::Data {
                template_id,
                records,
            } => {
                data_flowsets.push((*template_id, records.clone()));
            }
        }
    }

    // Generate template packet if we have templates
    if !templates.is_empty() {
        let template_packet = build_template_packet(
            sys_up_time,
            unix_secs,
            sequence_number,
            source_id,
            &templates,
        )?;
        packets.push(template_packet);
        sequence_number += 1;
    }

    // Generate data packets
    for (template_id, records) in data_flowsets {
        // Find the template definition
        let template_fields = templates
            .iter()
            .find(|(id, _)| *id == template_id)
            .map(|(_, fields)| fields)
            .ok_or_else(|| {
                NetflowError::Generation(format!(
                    "Data flowset references undefined template ID: {}",
                    template_id
                ))
            })?;

        let data_packet = build_data_packet(
            sys_up_time,
            unix_secs,
            sequence_number,
            source_id,
            template_id,
            template_fields,
            &records,
        )?;
        packets.push(data_packet);
        sequence_number += 1;
    }

    if packets.is_empty() {
        return Err(NetflowError::Generation(
            "V9 configuration must contain at least one template or data flowset".to_string(),
        ));
    }

    Ok(packets)
}

fn get_header_values(config: &V9Config) -> Result<(u32, u32, u32, u32)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NetflowError::Generation(format!("Failed to get system time: {}", e)))?;

    let unix_secs = if let Some(ref h) = config.header {
        h.unix_secs.unwrap_or(now.as_secs() as u32)
    } else {
        now.as_secs() as u32
    };

    let sys_up_time = if let Some(ref h) = config.header {
        h.sys_up_time.unwrap_or(360000)
    } else {
        360000
    };

    let sequence_number = if let Some(ref h) = config.header {
        h.sequence_number.unwrap_or(0)
    } else {
        0
    };

    let source_id = if let Some(ref h) = config.header {
        h.source_id.unwrap_or(1)
    } else {
        1
    };

    Ok((sys_up_time, unix_secs, sequence_number, source_id))
}

fn build_template_packet(
    sys_up_time: u32,
    unix_secs: u32,
    sequence_number: u32,
    source_id: u32,
    templates: &[(u16, Vec<crate::config::schema::V9TemplateField>)],
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // V9 Header (20 bytes)
    packet.extend_from_slice(&9u16.to_be_bytes()); // Version
    let count = templates.len() as u16;
    packet.extend_from_slice(&count.to_be_bytes()); // Count (number of flowsets)
    packet.extend_from_slice(&sys_up_time.to_be_bytes());
    packet.extend_from_slice(&unix_secs.to_be_bytes());
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&source_id.to_be_bytes());

    // Template FlowSet
    for (template_id, fields) in templates {
        let flowset_id = 0u16; // 0 indicates template flowset
        packet.extend_from_slice(&flowset_id.to_be_bytes());

        // Calculate flowset length (will update later)
        let length_pos = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder for length

        // Template ID and field count
        packet.extend_from_slice(&template_id.to_be_bytes());
        let field_count = fields.len() as u16;
        packet.extend_from_slice(&field_count.to_be_bytes());

        // Template fields
        for field in fields {
            let field_type = field_name_to_id(&field.field_type).ok_or_else(|| {
                NetflowError::Generation(format!("Unknown field type: {}", field.field_type))
            })?;
            packet.extend_from_slice(&field_type.to_be_bytes());
            packet.extend_from_slice(&field.field_length.to_be_bytes());
        }

        // Update flowset length (from flowset_id to end of this flowset)
        let flowset_length = (packet.len() - length_pos + 2) as u16;
        packet[length_pos..length_pos + 2].copy_from_slice(&flowset_length.to_be_bytes());
    }

    Ok(packet)
}

fn build_data_packet(
    sys_up_time: u32,
    unix_secs: u32,
    sequence_number: u32,
    source_id: u32,
    template_id: u16,
    template_fields: &[crate::config::schema::V9TemplateField],
    records: &[serde_yaml::Value],
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // V9 Header (20 bytes)
    packet.extend_from_slice(&9u16.to_be_bytes()); // Version
    packet.extend_from_slice(&1u16.to_be_bytes()); // Count (1 data flowset)
    packet.extend_from_slice(&sys_up_time.to_be_bytes());
    packet.extend_from_slice(&unix_secs.to_be_bytes());
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&source_id.to_be_bytes());

    // Data FlowSet
    packet.extend_from_slice(&template_id.to_be_bytes()); // FlowSet ID = Template ID

    // Calculate flowset length (will update later)
    let length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes()); // Placeholder for length

    // Serialize each record
    for record in records {
        for field in template_fields {
            let field_type = field_name_to_id(&field.field_type).ok_or_else(|| {
                NetflowError::Generation(format!("Unknown field type: {}", field.field_type))
            })?;
            let field_name = v9_field_id_to_name(field_type);

            // Get field value from record or use zero
            let value =
                get_field_value(record, field_name).unwrap_or(serde_yaml::Value::Number(0.into()));

            // Serialize the field value
            let bytes = serialize_field_value(&value, field.field_length);
            packet.extend_from_slice(&bytes);
        }
    }

    // Add padding if needed (flowset length must be multiple of 4)
    while (packet.len() - length_pos + 2) % 4 != 0 {
        packet.push(0);
    }

    // Update flowset length
    let flowset_length = (packet.len() - length_pos + 2) as u16;
    packet[length_pos..length_pos + 2].copy_from_slice(&flowset_length.to_be_bytes());

    Ok(packet)
}

/// Map human-readable field names to NetFlow V9 field type IDs
fn field_name_to_id(name: &str) -> Option<u16> {
    match name {
        "IN_BYTES" => Some(1),
        "IN_PKTS" => Some(2),
        "FLOWS" => Some(3),
        "PROTOCOL" => Some(4),
        "SRC_TOS" => Some(5),
        "TCP_FLAGS" => Some(6),
        "L4_SRC_PORT" => Some(7),
        "IPV4_SRC_ADDR" => Some(8),
        "SRC_MASK" => Some(9),
        "INPUT_SNMP" => Some(10),
        "L4_DST_PORT" => Some(11),
        "IPV4_DST_ADDR" => Some(12),
        "DST_MASK" => Some(13),
        "OUTPUT_SNMP" => Some(14),
        "IPV4_NEXT_HOP" => Some(15),
        "SRC_AS" => Some(16),
        "DST_AS" => Some(17),
        "BGP_IPV4_NEXT_HOP" => Some(18),
        "MUL_DST_PKTS" => Some(19),
        "MUL_DST_BYTES" => Some(20),
        "LAST_SWITCHED" => Some(21),
        "FIRST_SWITCHED" => Some(22),
        "OUT_BYTES" => Some(23),
        "OUT_PKTS" => Some(24),
        _ => None,
    }
}
