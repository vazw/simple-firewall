#![no_std]
#![no_main]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod helper;
mod tc;
mod xdp;
use aya_log_ebpf::info;
use helper::*;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, map, xdp},
    maps::{HashMap, RingBuf},
    programs::{TcContext, XdpContext},
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use simple_firewall_common::ConnectionState;

use crate::tc::egress::{
    handle_icmp_egress, handle_tcp_egress, handle_udp_egress,
};
use crate::xdp::ingress::{handle_icmp_xdp, handle_tcp_xdp, handle_udp_xdp};

//UP TO 100 in config length
const CONFIG_MAP_SIZE: u32 = 65536;

// This should be enough for all port on a system
#[map(name = "CONNECTIONS")]
static CONNECTIONS: HashMap<u32, ConnectionState> =
    HashMap::with_max_entries(u16::MAX as u32 + 1, 0);

//Reserve 1MiB of RingBuf
#[map(name = "NEW")]
static NEW: RingBuf = RingBuf::with_byte_size(1048576, 0);

#[map(name = "TCP_IN_SPORT")]
static TCP_IN_SPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);
#[map(name = "TCP_IN_DPORT")]
static TCP_IN_DPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);

#[map(name = "TCP_OUT_SPORT")]
static TCP_OUT_SPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);
#[map(name = "TCP_OUT_DPORT")]
static TCP_OUT_DPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);

#[map(name = "UDP_IN_SPORT")]
static UDP_IN_SPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);
#[map(name = "UDP_IN_DPORT")]
static UDP_IN_DPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);

#[map(name = "UDP_OUT_SPORT")]
static UDP_OUT_SPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);
#[map(name = "UDP_OUT_DPORT")]
static UDP_OUT_DPORT: HashMap<u16, u8> =
    HashMap::with_max_entries(CONFIG_MAP_SIZE, 0);

#[map(name = "DNS_ADDR")]
static DNS_ADDR: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

#[map(name = "TEMPORT")]
static TEMPORT: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn sfw(ctx: XdpContext) -> u32 {
    match try_simple_firewall(ctx) {
        Ok(ret) => ret,
        Err(e) => e,
    }
}

fn try_simple_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: &EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv: &Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let remote_addr = ipv.src_addr();
            let host_addr = ipv.dst_addr();
            let protocal = ipv.proto;
            // Won't mess with DNS, mulicast and Broadcast
            // Let local broadcast and multicast pass
            if host_addr.is_multicast() || ethhdr.dst_addr.eq(&[255,255,255,255,255,255])
                || matches!(host_addr.octets(), [.., 255])
                || (remote_addr.is_multicast() || matches!(remote_addr.octets(), [.., 255]))
            {
                info!(
                    &ctx,
                    "INGRESS Broadcast PASS {:i} -> {:i}",
                    remote_addr.to_bits(),
                    host_addr.to_bits()
                );
                return Ok(xdp_action::XDP_PASS);
            }
            match protocal {
                IpProto::Tcp => {
                    handle_tcp_xdp(ctx, host_addr, remote_addr, protocal)
                }
                IpProto::Udp => {
                    handle_udp_xdp(ctx, host_addr, remote_addr, protocal)
                }
                IpProto::Gre => {
                    // let header = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    aya_log_ebpf::debug!(&ctx, "GRE tunnelling🥰");
                    Ok(xdp_action::XDP_PASS)
                }
                IpProto::Icmp => handle_icmp_xdp(ctx, host_addr, remote_addr),
                IpProto::Sctp => {
                    // let header = Sctp
                    aya_log_ebpf::debug!(&ctx, "Sctp ?");
                    Ok(xdp_action::XDP_PASS)
                }
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
        // EtherType
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[classifier]
pub fn sfw_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(e) => e,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, i32> {
    let eth_hdr: &EthHdr = unsafe { tc_ptr_at(&ctx, 0) }?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: &Ipv4Hdr = unsafe { tc_ptr_at(&ctx, EthHdr::LEN)? };
            let host_addr = ipv4hdr.src_addr();
            let remote_addr = ipv4hdr.dst_addr();
            let protocal = ipv4hdr.proto;
            if host_addr.is_multicast() || eth_hdr.dst_addr.eq(&[255,255,255,255,255,255])
                || matches!(host_addr.octets(), [.., 255])
                || (remote_addr.is_multicast() || matches!(remote_addr.octets(), [.., 255]))
            {
                info!(
                    &ctx,
                    "EGRESS Broadcast PASS {:i} -> {:i}",
                    remote_addr.to_bits(),
                    host_addr.to_bits()
                );
                return Ok(TC_ACT_PIPE);
            }
            match ipv4hdr.proto {
                IpProto::Icmp => {
                    handle_icmp_egress(ctx, host_addr, remote_addr, protocal)
                }
                IpProto::Tcp => {
                    handle_tcp_egress(ctx, host_addr, remote_addr, protocal)
                }
                IpProto::Udp => {
                    handle_udp_egress(ctx, host_addr, remote_addr, protocal)
                }
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
