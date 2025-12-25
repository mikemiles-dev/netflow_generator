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
            println!(
                "Sent packet {} ({} bytes) to {}",
                i + 1,
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

/// Write packets to a file
pub fn write_to_file(packets: &[Vec<u8>], path: &std::path::Path, verbose: bool) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(path)?;

    if verbose {
        println!("Writing {} packet(s) to {:?}", packets.len(), path);
    }

    for (i, packet) in packets.iter().enumerate() {
        file.write_all(packet)?;

        if verbose {
            println!("Wrote packet {} ({} bytes)", i + 1, packet.len());
        }
    }

    if verbose {
        println!("Successfully wrote all packets to file");
    }

    Ok(())
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
