use aya::maps::HashMap;
use aya::Bpf;
use clap::Parser;
use log::info;
use pnet::packet::tcp::MutableTcpPacket;
use serde::Deserialize;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp;
use pnet::packet::Packet;
use std::borrow::BorrowMut;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Deserialize)]
pub struct TcpIn {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpOut {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct UdpIn {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpOut {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub dns: Option<Vec<String>>,
    pub tcp_in: Option<TcpIn>,
    pub tcp_out: Option<TcpOut>,
    pub udp_in: Option<UdpIn>,
    pub udp_out: Option<UdpOut>,
}

impl AppConfig {
    pub fn len(&self) -> u16 {
        let mut len: u16 = 0;
        if let Some(dns) = &self.dns {
            len += dns.len() as u16;
        }
        if let Some(tcp) = &self.tcp_in {
            if let Some(n) = &tcp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &tcp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(tcp) = &self.tcp_out {
            if let Some(n) = &tcp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &tcp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(udp) = &self.udp_in {
            if let Some(n) = &udp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &udp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(udp) = &self.udp_out {
            if let Some(n) = &udp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &udp.dport {
                len += n.len() as u16;
            }
        }
        len
    }
    pub fn is_empty(&self) -> bool {
        self.len().eq(&0)
    }
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    pub iface: String,
    #[clap(short, long, default_value = "/etc/sfw/sfwconfig.toml")]
    pub config: String,
}

pub fn load_config(
    bpf: &mut Bpf,
    config: &AppConfig,
) -> Result<(), anyhow::Error> {
    if let Some(dns) = &config.dns {
        let mut dns_list: HashMap<_, u32, u8> =
            HashMap::try_from(bpf.map_mut("DNS_ADDR").unwrap())?;
        for k in dns {
            let ip_addrs: Ipv4Addr = k.parse().unwrap();
            let addrs: u32 = ip_addrs.to_bits();
            info!("allowed DNS IP: {:}", ip_addrs.to_string());
            _ = dns_list.insert(addrs, 0x1, 0);
        }
    }
    if let Some(tcp) = &config.tcp_in {
        if let Some(n) = &tcp.sport {
            let mut tcp_in_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("TCP_IN_SPORT").unwrap())?;
            for port in 0..=65535 {
                _ = tcp_in_port.remove(&port);
            }
            for port in n {
                info!("Allow incomming from tcp port: {:?}", port);
                tcp_in_port.insert(port, 1u8, 0)?;
            }
        }
        if let Some(n) = &tcp.dport {
            let mut tcp_in_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("TCP_IN_DPORT").unwrap())?;
            for port in 0..=65535 {
                _ = tcp_in_port.remove(&port);
            }
            for port in n {
                info!("Allow incomming to tcp port: {:?}", port);
                tcp_in_port.insert(port, 1u8, 0)?;
            }
        }
    }
    if let Some(tcp) = &config.tcp_out {
        if let Some(n) = &tcp.sport {
            let mut tcp_out_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("TCP_OUT_SPORT").unwrap())?;
            for port in 0..=65535 {
                _ = tcp_out_port.remove(&port);
            }
            for port in n {
                info!("Allow outgoing from tcp port: {:?}", port);
                tcp_out_port.insert(port, 1u8, 0)?;
            }
        }
        if let Some(n) = &tcp.dport {
            let mut tcp_out_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("TCP_OUT_DPORT").unwrap())?;
            for port in 0..=65535 {
                _ = tcp_out_port.remove(&port);
            }
            for port in n {
                info!("Allow outgoing to tcp port: {:?}", port);
                tcp_out_port.insert(port, 1u8, 0)?;
            }
        }
    }
    if let Some(udp) = &config.udp_in {
        if let Some(n) = &udp.sport {
            let mut udp_in_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("UDP_IN_SPORT").unwrap())?;
            for port in 0..=65535 {
                _ = udp_in_port.remove(&port);
            }
            for port in n {
                info!("Allow incomming from udp port {:?}", port);
                udp_in_port.insert(port, 1u8, 0)?;
            }
        }
        if let Some(n) = &udp.dport {
            let mut udp_in_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("UDP_IN_DPORT").unwrap())?;
            for port in 0..=65535 {
                _ = udp_in_port.remove(&port);
            }
            for port in n {
                info!("Allow incomming to udp port {:?}", port);
                udp_in_port.insert(port, 1u8, 0)?;
            }
        }
    }
    if let Some(udp) = &config.udp_out {
        if let Some(n) = &udp.sport {
            let mut udp_out_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("UDP_OUT_SPORT").unwrap())?;
            for port in 0..=65535 {
                _ = udp_out_port.remove(&port);
            }
            for port in n {
                info!("Allow outgoing from udp port {:?}", port);
                udp_out_port.insert(port, 1u8, 0)?;
            }
        }
        if let Some(n) = &udp.dport {
            let mut udp_out_port: HashMap<_, u16, u8> =
                HashMap::try_from(bpf.map_mut("UDP_OUT_DPORT").unwrap())?;
            for port in 0..=65535 {
                _ = udp_out_port.remove(&port);
            }
            for port in n {
                info!("Allow outgoing to udp port {:?}", port);
                udp_out_port.insert(port, 1u8, 0)?;
            }
        }
    }
    info!("Done parsing config!");
    Ok(())
}

// syn packet and ack packet extracted from wireshark
static SYN_PACKET: [u8; 40] = [
    0xd9, 0x3e, 0x00, 0x50, 0xd7, 0x52, 0x75, 0x4a, 0x00, 0x00, 0x00, 0x00,
    0xa0, 0x02, 0xfa, 0xf0, 0x12, 0x5a, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
    0x04, 0x02, 0x08, 0x0a, 0xa6, 0x98, 0x44, 0xd8, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x03, 0x07,
];
static ACK_PACKET: [u8; 32] = [
    0xd9, 0x3e, 0x00, 0x50, 0xd7, 0x52, 0x75, 0x4b, 0x7a, 0xfe, 0x79, 0x69,
    0x80, 0x10, 0x01, 0xf6, 0x12, 0x52, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
    0xa6, 0x98, 0x44, 0xd9, 0xd3, 0x54, 0x02, 0x0e,
];

pub static IP4_SYNBUF: [u8; 60] = [0u8; 60];
pub static IP4_ACKBUF: [u8; 52] = [0u8; 52];

pub fn create_tcp_syn_packet(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    empty_buf: &mut [u8; 60],
) -> MutableIpv4Packet {
    //load packet template into mutable packet to edit source, dest and checksum
    let mut syn_template = SYN_PACKET;
    let mut tcp_syn =
        MutableTcpPacket::new(&mut syn_template).expect("valid packet");
    tcp_syn.set_source(src_port);
    tcp_syn.set_destination(dst_port);
    // TODO get and set seq from real packet
    tcp_syn.set_sequence(seq);
    let check =
        tcp::ipv4_checksum(&tcp_syn.to_immutable(), &src_addr, &dst_addr);
    tcp_syn.set_checksum(check);

    // Convert packet back into bytes array as rust Vec
    let syn_packet_vec = tcp_syn.packet().to_vec();

    let ipv4_tcppayload = pnet::packet::ipv4::Ipv4 {
        version: 4,
        header_length: 5,
        dscp: 0,
        ecn: 1,
        total_length: 60,
        identification: 15,
        flags: 2,
        fragment_offset: 0,
        ttl: 64,
        next_level_protocol: IpNextHeaderProtocol::new(6),
        checksum: 0,
        source: src_addr,
        destination: dst_addr,
        options: Vec::new(),
        payload: syn_packet_vec, //Payload TCP
    };

    let mut ipv4_packet =
        MutableIpv4Packet::new(empty_buf.borrow_mut()).unwrap();
    ipv4_packet.populate(&ipv4_tcppayload);
    let checks = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checks);
    ipv4_packet
}

pub fn create_tcp_ack_packet(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    empty_buf: &mut [u8; 52],
) -> MutableIpv4Packet {
    //load packet template into mutable packet to edit source, dest and checksum
    let mut ack_template = ACK_PACKET;
    let mut tcp_ack =
        MutableTcpPacket::new(&mut ack_template).expect("valid packet");
    tcp_ack.set_source(src_port);
    tcp_ack.set_destination(dst_port);
    // TODO get and set seq from real packet
    tcp_ack.set_sequence(seq);
    tcp_ack.set_acknowledgement(ack_seq);
    let check =
        tcp::ipv4_checksum(&tcp_ack.to_immutable(), &src_addr, &dst_addr);
    tcp_ack.set_checksum(check);

    // Convert packet back into bytes array as rust Vec
    let ack_packet_vec = tcp_ack.packet().to_vec();

    let ipv4_tcppayload = pnet::packet::ipv4::Ipv4 {
        version: 4,
        header_length: 5,
        dscp: 0,
        ecn: 1,
        total_length: 52,
        identification: 16,
        flags: 2,
        fragment_offset: 0,
        ttl: 64,
        next_level_protocol: IpNextHeaderProtocol::new(6),
        checksum: 0,
        source: src_addr,
        destination: dst_addr,
        options: Vec::new(),
        payload: ack_packet_vec, //Payload TCP
    };

    let mut ipv4_packet =
        MutableIpv4Packet::new(empty_buf.borrow_mut()).unwrap();
    ipv4_packet.populate(&ipv4_tcppayload);
    let checks = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checks);
    ipv4_packet
}
