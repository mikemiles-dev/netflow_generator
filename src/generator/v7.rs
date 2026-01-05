use crate::config::schema::V7Config;
use crate::error::{NetflowError, Result};
use netflow_parser::static_versions::v7::{FlowSet, Header, V7};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a NetFlow V7 packet from configuration
pub fn build_v7_packet(config: V7Config) -> Result<Vec<u8>> {
    if config.flowsets.is_empty() {
        return Err(NetflowError::Generation(
            "V7 configuration must contain at least one flowset".to_string(),
        ));
    }

    // Build header with defaults where needed
    let header = build_header(&config)?;

    // Build flowsets
    let flowsets: Vec<FlowSet> = config
        .flowsets
        .iter()
        .map(|fs| FlowSet {
            src_addr: fs.src_addr,
            dst_addr: fs.dst_addr,
            next_hop: fs.next_hop,
            input: fs.input,
            output: fs.output,
            d_pkts: fs.d_pkts,
            d_octets: fs.d_octets,
            first: fs.first,
            last: fs.last,
            src_port: fs.src_port,
            dst_port: fs.dst_port,
            flags_fields_valid: fs.flags,
            tcp_flags: fs.tcp_flags,
            protocol_number: fs.protocol,
            protocol_type: netflow_parser::protocol::ProtocolTypes::from(fs.protocol),
            tos: fs.tos,
            src_as: fs.src_as,
            dst_as: fs.dst_as,
            src_mask: fs.src_mask,
            dst_mask: fs.dst_mask,
            flags_fields_invalid: fs.flags2,
            router_src: fs.router_src,
        })
        .collect();

    // Create V7 packet
    let v7 = V7 { header, flowsets };

    // Serialize to bytes
    Ok(v7.to_be_bytes())
}

fn build_header(config: &V7Config) -> Result<Header> {
    let count = u16::try_from(config.flowsets.len())
        .map_err(|_| NetflowError::Generation("Too many flowsets (max 65535)".to_string()))?;

    // Get current Unix timestamp for defaults
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| NetflowError::Generation(format!("Failed to get system time: {}", e)))?;

    let unix_secs = if let Some(ref h) = config.header {
        h.unix_secs
            .unwrap_or_else(|| u32::try_from(now.as_secs()).unwrap_or(u32::MAX))
    } else {
        u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
    };

    let unix_nsecs = if let Some(ref h) = config.header {
        h.unix_nsecs.unwrap_or(0)
    } else {
        0
    };

    let sys_up_time = if let Some(ref h) = config.header {
        h.sys_up_time.unwrap_or(360000)
    } else {
        360000 // Default to 6 minutes
    };

    let flow_sequence = if let Some(ref h) = config.header {
        h.flow_sequence.unwrap_or(0)
    } else {
        0
    };

    let reserved = if let Some(ref h) = config.header {
        h.reserved.unwrap_or(0)
    } else {
        0
    };

    Ok(Header {
        version: 7,
        count,
        sys_up_time,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        reserved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::V7FlowSet as ConfigV7FlowSet;
    use netflow_parser::NetflowParser;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_v7_packet() {
        let config = V7Config {
            header: None,
            flowsets: vec![ConfigV7FlowSet {
                src_addr: Ipv4Addr::new(10, 1, 1, 5),
                dst_addr: Ipv4Addr::new(172, 16, 0, 100),
                next_hop: Ipv4Addr::new(10, 1, 1, 1),
                input: 10,
                output: 20,
                d_pkts: 250,
                d_octets: 150000,
                first: 350000,
                last: 360000,
                src_port: 12345,
                dst_port: 80,
                flags: 0,
                tcp_flags: 0x02,
                protocol: 6,
                tos: 0,
                src_as: 64512,
                dst_as: 64513,
                src_mask: 16,
                dst_mask: 24,
                flags2: 0,
                router_src: Ipv4Addr::new(10, 1, 1, 254),
            }],
        };

        let packet = build_v7_packet(config).unwrap();

        // Verify packet can be parsed back
        let mut parser = NetflowParser::default();
        let parsed = parser.parse_bytes(&packet);
        assert_eq!(parsed.packets.len(), 1);
    }
}
