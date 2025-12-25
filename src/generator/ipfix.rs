use crate::config::schema::{IPFixConfig, IPFixFlowSet as ConfigIPFixFlowSet};
use crate::error::{NetflowError, Result};
use crate::generator::field_serializer::{
    get_field_value, ipfix_field_id_to_name, serialize_field_value,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build IPFIX packets from configuration
/// Generates proper template and data flowsets
pub fn build_ipfix_packets(config: IPFixConfig) -> Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();

    // Get header values
    let (export_time, mut sequence_number, observation_domain_id) = get_header_values(&config)?;

    // Separate templates and data flowsets
    let mut templates = Vec::new();
    let mut data_flowsets = Vec::new();

    for flowset in &config.flowsets {
        match flowset {
            ConfigIPFixFlowSet::Template {
                template_id,
                fields,
            } => {
                templates.push((*template_id, fields.clone()));
            }
            ConfigIPFixFlowSet::Data {
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
            export_time,
            sequence_number,
            observation_domain_id,
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
            export_time,
            sequence_number,
            observation_domain_id,
            template_id,
            template_fields,
            &records,
        )?;
        packets.push(data_packet);
        sequence_number += 1;
    }

    if packets.is_empty() {
        return Err(NetflowError::Generation(
            "IPFIX configuration must contain at least one template or data flowset".to_string(),
        ));
    }

    Ok(packets)
}

fn get_header_values(config: &IPFixConfig) -> Result<(u32, u32, u32)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NetflowError::Generation(format!("Failed to get system time: {}", e)))?;

    let export_time = if let Some(ref h) = config.header {
        h.export_time.unwrap_or_else(|| {
            u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
        })
    } else {
        u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
    };

    let sequence_number = if let Some(ref h) = config.header {
        h.sequence_number.unwrap_or(0)
    } else {
        0
    };

    let observation_domain_id = if let Some(ref h) = config.header {
        h.observation_domain_id.unwrap_or(1)
    } else {
        1
    };

    Ok((export_time, sequence_number, observation_domain_id))
}

fn build_template_packet(
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
    templates: &[(u16, Vec<crate::config::schema::IPFixTemplateField>)],
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // IPFIX Header (16 bytes)
    packet.extend_from_slice(&10u16.to_be_bytes()); // Version (10 for IPFIX)

    // Length placeholder (will update later)
    let length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    packet.extend_from_slice(&export_time.to_be_bytes());
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&observation_domain_id.to_be_bytes());

    // Template Set
    for (template_id, fields) in templates {
        let set_id = 2u16; // 2 indicates template set
        packet.extend_from_slice(&set_id.to_be_bytes());

        // Set length placeholder
        let set_length_pos = packet.len();
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Template ID and field count
        packet.extend_from_slice(&template_id.to_be_bytes());
        let field_count = u16::try_from(fields.len()).map_err(|_| {
            NetflowError::Generation("Too many fields in template (max 65535)".to_string())
        })?;
        packet.extend_from_slice(&field_count.to_be_bytes());

        // Template fields
        for field in fields {
            let field_type = field_name_to_id(&field.field_type).ok_or_else(|| {
                NetflowError::Generation(format!("Unknown field type: {}", field.field_type))
            })?;
            packet.extend_from_slice(&field_type.to_be_bytes());
            packet.extend_from_slice(&field.field_length.to_be_bytes());
        }

        // Add padding if needed (set length must be multiple of 4)
        while packet
            .len()
            .checked_sub(set_length_pos)
            .and_then(|v| v.checked_add(2))
            .map(|v| v % 4 != 0)
            .unwrap_or(false)
        {
            packet.push(0);
        }

        // Update set length
        let set_length = packet
            .len()
            .checked_sub(set_length_pos)
            .and_then(|v| v.checked_add(2))
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| NetflowError::Generation("Set length overflow".to_string()))?;
        let end_pos = set_length_pos
            .checked_add(2)
            .ok_or_else(|| NetflowError::Generation("Array index overflow".to_string()))?;
        packet[set_length_pos..end_pos].copy_from_slice(&set_length.to_be_bytes());
    }

    // Update total packet length
    let total_length = u16::try_from(packet.len())
        .map_err(|_| NetflowError::Generation("Packet length exceeds u16::MAX".to_string()))?;
    let end_pos = length_pos
        .checked_add(2)
        .ok_or_else(|| NetflowError::Generation("Array index overflow".to_string()))?;
    packet[length_pos..end_pos].copy_from_slice(&total_length.to_be_bytes());

    Ok(packet)
}

fn build_data_packet(
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
    template_id: u16,
    template_fields: &[crate::config::schema::IPFixTemplateField],
    records: &[serde_yaml::Value],
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // IPFIX Header (16 bytes)
    packet.extend_from_slice(&10u16.to_be_bytes()); // Version

    // Length placeholder (will update later)
    let length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    packet.extend_from_slice(&export_time.to_be_bytes());
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&observation_domain_id.to_be_bytes());

    // Data Set
    packet.extend_from_slice(&template_id.to_be_bytes()); // Set ID = Template ID

    // Set length placeholder
    let set_length_pos = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());

    // Serialize each record
    for record in records {
        for field in template_fields {
            let field_type = field_name_to_id(&field.field_type).ok_or_else(|| {
                NetflowError::Generation(format!("Unknown field type: {}", field.field_type))
            })?;
            let field_name = ipfix_field_id_to_name(field_type);

            // Get field value from record or use zero
            let value =
                get_field_value(record, field_name).unwrap_or(serde_yaml::Value::Number(0.into()));

            // Serialize the field value
            let bytes = serialize_field_value(&value, field.field_length);
            packet.extend_from_slice(&bytes);
        }
    }

    // Add padding if needed (set length must be multiple of 4)
    while packet
        .len()
        .checked_sub(set_length_pos)
        .and_then(|v| v.checked_add(2))
        .map(|v| v % 4 != 0)
        .unwrap_or(false)
    {
        packet.push(0);
    }

    // Update set length
    let set_length = packet
        .len()
        .checked_sub(set_length_pos)
        .and_then(|v| v.checked_add(2))
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| NetflowError::Generation("Set length overflow".to_string()))?;
    let set_end_pos = set_length_pos
        .checked_add(2)
        .ok_or_else(|| NetflowError::Generation("Array index overflow".to_string()))?;
    packet[set_length_pos..set_end_pos].copy_from_slice(&set_length.to_be_bytes());

    // Update total packet length
    let total_length = u16::try_from(packet.len())
        .map_err(|_| NetflowError::Generation("Packet length exceeds u16::MAX".to_string()))?;
    let length_end_pos = length_pos
        .checked_add(2)
        .ok_or_else(|| NetflowError::Generation("Array index overflow".to_string()))?;
    packet[length_pos..length_end_pos].copy_from_slice(&total_length.to_be_bytes());

    Ok(packet)
}

/// Map human-readable field names to IPFIX field type IDs (IANA Information Elements)
fn field_name_to_id(name: &str) -> Option<u16> {
    match name {
        "octetDeltaCount" => Some(1),
        "packetDeltaCount" => Some(2),
        "deltaFlowCount" => Some(3),
        "protocolIdentifier" => Some(4),
        "ipClassOfService" => Some(5),
        "tcpControlBits" => Some(6),
        "sourceTransportPort" => Some(7),
        "sourceIPv4Address" => Some(8),
        "sourceIPv4PrefixLength" => Some(9),
        "ingressInterface" => Some(10),
        "destinationTransportPort" => Some(11),
        "destinationIPv4Address" => Some(12),
        "destinationIPv4PrefixLength" => Some(13),
        "egressInterface" => Some(14),
        "ipNextHopIPv4Address" => Some(15),
        "bgpSourceAsNumber" => Some(16),
        "bgpDestinationAsNumber" => Some(17),
        "bgpNextHopIPv4Address" => Some(18),
        "flowEndSysUpTime" => Some(21),
        "flowStartSysUpTime" => Some(22),
        _ => None,
    }
}
