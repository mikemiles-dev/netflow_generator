use crate::config::schema::V5Config;
use crate::error::{NetflowError, Result};
use netflow_parser::static_versions::v5::{FlowSet, Header, V5};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a NetFlow V5 packet from configuration
pub fn build_v5_packet(config: V5Config) -> Result<Vec<u8>> {
    if config.flowsets.is_empty() {
        return Err(NetflowError::Generation(
            "V5 configuration must contain at least one flowset".to_string(),
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
            pad1: 0,
            tcp_flags: fs.tcp_flags,
            protocol_number: fs.protocol,
            protocol_type: netflow_parser::protocol::ProtocolTypes::from(fs.protocol),
            tos: fs.tos,
            src_as: fs.src_as,
            dst_as: fs.dst_as,
            src_mask: fs.src_mask,
            dst_mask: fs.dst_mask,
            pad2: 0,
        })
        .collect();

    // Create V5 packet
    let v5 = V5 { header, flowsets };

    // Serialize to bytes
    Ok(v5.to_be_bytes())
}

fn build_header(config: &V5Config) -> Result<Header> {
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

    let engine_type = if let Some(ref h) = config.header {
        h.engine_type.unwrap_or(0)
    } else {
        0
    };

    let engine_id = if let Some(ref h) = config.header {
        h.engine_id.unwrap_or(0)
    } else {
        0
    };

    let sampling_interval = if let Some(ref h) = config.header {
        h.sampling_interval.unwrap_or(0)
    } else {
        0
    };

    Ok(Header {
        version: 5,
        count,
        sys_up_time,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::V5FlowSet as ConfigV5FlowSet;
    use netflow_parser::NetflowParser;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_v5_packet() {
        let config = V5Config {
            header: None,
            flowsets: vec![ConfigV5FlowSet {
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
        };

        let packet = build_v5_packet(config).unwrap();

        // Verify packet can be parsed back
        let mut parser = NetflowParser::default();
        let parsed = parser.parse_bytes(&packet);
        assert_eq!(parsed.len(), 1);
    }
}
