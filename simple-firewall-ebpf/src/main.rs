#![no_std]
#![no_main]

mod helper;
mod tc;
mod xdp;
use helper::*;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, RingBuf},
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

// Allocated 20KB for connection
#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: HashMap<u32, ConnectionState> =
    HashMap::with_max_entries(10_000, 0);
#[map(name = "UNKNOWN")]
static mut UNKNOWN: HashMap<u32, ConnectionState> =
    HashMap::with_max_entries(256, 0);
#[map(name = "CONBUF")]
static CONBUF: RingBuf = RingBuf::with_byte_size(16_777_216, 0);

#[map(name = "TCP_IN_SPORT")]
static mut TCP_IN_SPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);
#[map(name = "TCP_IN_DPORT")]
static mut TCP_IN_DPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);

#[map(name = "TCP_OUT_SPORT")]
static mut TCP_OUT_SPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);
#[map(name = "TCP_OUT_DPORT")]
static mut TCP_OUT_DPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);

#[map(name = "UDP_IN_SPORT")]
static mut UDP_IN_SPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);
#[map(name = "UDP_IN_DPORT")]
static mut UDP_IN_DPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);

#[map(name = "UDP_OUT_SPORT")]
static mut UDP_OUT_SPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);
#[map(name = "UDP_OUT_DPORT")]
static mut UDP_OUT_DPORT: Array<u8> =
    Array::with_max_entries(u16::MAX as u32 + 1, 0);

#[map(name = "DNS_ADDR")]
static mut DNS_ADDR: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

#[map(name = "TEMPORT")]
static mut TEMPORT: Array<u8> = Array::with_max_entries(u16::MAX as u32 + 1, 0);

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
            if (host_addr.is_private()
                || host_addr.is_unspecified()
                || matches!(host_addr.octets(), [.., 255]))
                && (remote_addr.is_multicast()
                    || matches!(remote_addr.octets(), [.., 255]))
            // || remote_addr.is_private())
            {
                return Ok(xdp_action::XDP_PASS);
            }
            if host_addr.is_multicast()
                && (remote_addr.is_multicast() || remote_addr.is_private())
            {
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
