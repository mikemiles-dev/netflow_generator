use crate::error::{NetflowError, Result};
use std::net::{SocketAddr, UdpSocket};

/// Send packets via UDP
pub fn send_udp(packets: &[Vec<u8>], destination: SocketAddr, verbose: bool) -> Result<()> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| NetflowError::Network(format!("Failed to bind UDP socket: {}", e)))?;

    if verbose {
        println!("Bound UDP socket to {}", socket.local_addr().unwrap());
        println!("Sending {} packet(s) to {}", packets.len(), destination);
    }

    // Send each packet
    for (i, packet) in packets.iter().enumerate() {
        socket
            .send_to(packet, destination)
            .map_err(|e| NetflowError::Network(format!("Failed to send packet: {}", e)))?;

        if verbose {
            let packet_num = i.checked_add(1).unwrap_or(i);
            println!(
                "Sent packet {} ({} bytes) to {}",
                packet_num,
                packet.len(),
                destination
            );
        }
    }

    if verbose {
        println!("Successfully sent all packets");
    }

    Ok(())
}

/// Write packets to a pcap file
pub fn write_to_file(
    packets: &[Vec<u8>],
    path: &std::path::Path,
    destination: SocketAddr,
    verbose: bool,
) -> Result<()> {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    use std::fs::File;
    use std::time::{SystemTime, UNIX_EPOCH};

    let file = File::create(path)?;

    // Create pcap writer with default header
    let pcap_header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut pcap_writer = PcapWriter::with_header(file, pcap_header)
        .map_err(|e| NetflowError::Io(std::io::Error::other(e)))?;

    if verbose {
        println!(
            "Writing {} packet(s) to {:?} in pcap format",
            packets.len(),
            path
        );
    }

    // Source IP for our packets (arbitrary)
    let src_ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
    let src_port: u16 = 12345;

    for (i, netflow_payload) in packets.iter().enumerate() {
        // Get current timestamp as Duration since EPOCH
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        // Build the complete packet: Ethernet + IP + UDP + NetFlow payload
        let packet_data = build_udp_packet(src_ip, src_port, destination, netflow_payload)?;

        let pcap_packet = PcapPacket {
            timestamp,
            orig_len: u32::try_from(packet_data.len()).map_err(|_| {
                NetflowError::InvalidPacket("Packet size exceeds u32::MAX".to_string())
            })?,
            data: std::borrow::Cow::Borrowed(&packet_data),
        };

        pcap_writer
            .write_packet(&pcap_packet)
            .map_err(|e| NetflowError::Io(std::io::Error::other(e)))?;

        if verbose {
            let packet_num = i.checked_add(1).unwrap_or(i);
            println!("Wrote packet {} ({} bytes)", packet_num, packet_data.len());
        }
    }

    if verbose {
        println!("Successfully wrote all packets to pcap file");
    }

    Ok(())
}

/// Build a complete UDP packet with Ethernet, IP, and UDP headers
fn build_udp_packet(
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dest: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();

    // Extract destination IP and port
    let (dest_ip, dest_port) = match dest {
        SocketAddr::V4(addr) => (*addr.ip(), addr.port()),
        SocketAddr::V6(_) => {
            return Err(NetflowError::InvalidDestination(
                "IPv6 not supported for pcap export".to_string(),
            ));
        }
    };

    // Ethernet header (14 bytes)
    // Destination MAC: 00:00:00:00:00:02
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    // Source MAC: 00:00:00:00:00:01
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // EtherType: 0x0800 (IPv4)
    packet.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes minimum)
    let ip_total_length = 20_usize
        .checked_add(8)
        .and_then(|v| v.checked_add(payload.len()))
        .ok_or_else(|| NetflowError::InvalidPacket("IP total length overflow".to_string()))?;

    let ip_total_length_u16 = u16::try_from(ip_total_length)
        .map_err(|_| NetflowError::InvalidPacket("IP total length exceeds u16::MAX".to_string()))?;

    packet.push(0x45); // Version (4) + IHL (5)
    packet.push(0x00); // DSCP + ECN
    packet.extend_from_slice(&ip_total_length_u16.to_be_bytes()); // Total length
    packet.extend_from_slice(&[0x00, 0x00]); // Identification
    packet.extend_from_slice(&[0x40, 0x00]); // Flags (DF) + Fragment offset
    packet.push(64); // TTL
    packet.push(17); // Protocol (UDP)
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (placeholder)
    packet.extend_from_slice(&src_ip.octets()); // Source IP
    packet.extend_from_slice(&dest_ip.octets()); // Destination IP

    // Calculate IP checksum
    let ip_checksum = calculate_checksum(&packet[14..34])?;
    let checksum_bytes = ip_checksum.to_be_bytes();
    packet[24] = checksum_bytes[0];
    packet[25] = checksum_bytes[1];

    // UDP header (8 bytes)
    let udp_length = 8_usize
        .checked_add(payload.len())
        .ok_or_else(|| NetflowError::InvalidPacket("UDP length overflow".to_string()))?;

    let udp_length_u16 = u16::try_from(udp_length)
        .map_err(|_| NetflowError::InvalidPacket("UDP length exceeds u16::MAX".to_string()))?;

    packet.extend_from_slice(&src_port.to_be_bytes()); // Source port
    packet.extend_from_slice(&dest_port.to_be_bytes()); // Destination port
    packet.extend_from_slice(&udp_length_u16.to_be_bytes()); // Length
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (optional for IPv4, set to 0)

    // Payload (NetFlow data)
    packet.extend_from_slice(payload);

    Ok(packet)
}

/// Calculate IP checksum
fn calculate_checksum(data: &[u8]) -> Result<u16> {
    let mut sum: u32 = 0;

    // Sum up 16-bit words
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.checked_add(u32::from(word)).ok_or_else(|| {
            NetflowError::InvalidPacket("Checksum calculation overflow".to_string())
        })?;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        let low = sum & 0xFFFF;
        let high = sum >> 16;
        sum = low
            .checked_add(high)
            .ok_or_else(|| NetflowError::InvalidPacket("Checksum fold overflow".to_string()))?;
    }

    // One's complement - safe because sum is guaranteed to fit in u16 after folding
    let sum_u16 = u16::try_from(sum)
        .map_err(|_| NetflowError::InvalidPacket("Checksum exceeds u16::MAX".to_string()))?;

    Ok(!sum_u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn test_send_udp() {
        // Create a test receiver
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        // Send a test packet
        let test_packet = vec![0x00, 0x05, 0x00, 0x01]; // Simple V5 header start
        send_udp(std::slice::from_ref(&test_packet), receiver_addr, false).unwrap();

        // Receive and verify
        let mut buf = [0u8; 1024];
        let (size, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], &test_packet[..]);
    }
}
