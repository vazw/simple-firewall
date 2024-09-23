use aya::maps::HashMap;
use aya::Bpf;
use clap::Parser;
use log::info;
use serde::Deserialize;

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
