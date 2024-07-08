#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::{mem, net::Ipv4Addr};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, Session};

const PROTOCAL_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN;

#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: HashMap<u64, u32> = HashMap::with_max_entries(512, 0);

#[map(name = "IAP")]
static mut IAP: HashMap<u16, u16> = HashMap::with_max_entries(24, 0);
#[map(name = "UDPIAP")]
static mut UDP_IAP: HashMap<u16, u16> = HashMap::with_max_entries(24, 0);
#[map(name = "OAP")]
static mut OAP: HashMap<u16, u16> = HashMap::with_max_entries(24, 0);
#[map(name = "UDPOAP")]
static mut UDP_OAP: HashMap<u16, u16> = HashMap::with_max_entries(24, 0);
#[map(name = "ALLST")]
static mut ALLST: HashMap<u32, u32> = HashMap::with_max_entries(24, 0);

#[map(name = "TEMPORT")]
static mut TEMPORT: HashMap<u16, u8> = HashMap::with_max_entries(8, 0);

#[map(name = "NEW")]
static mut NEW: PerfEventArray<Connection> = PerfEventArray::with_max_entries(1600, 0);
#[map(name = "DEL")]
static mut DEL: PerfEventArray<Session> = PerfEventArray::with_max_entries(800, 0);
#[map(name = "HOST")]
static mut HOST: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    let data = (start + offset) as *const T;
    let data_ = unsafe { data.as_ref().ok_or(xdp_action::XDP_PASS)? };
    Ok(data_)
}

#[inline(always)]
fn is_requested(session: &u64) -> bool {
    unsafe { CONNECTIONS.get(session).is_some() }
}

#[inline(always)]
fn add_request(session: &u64) {
    unsafe {
        let _ = CONNECTIONS.insert(session, &0u32, 0);
    }
}

#[inline(always)]
fn tcp_port_allowed_in(port: &u16) -> bool {
    unsafe { IAP.get(port).is_some() }
}

#[inline(always)]
fn tcp_port_allowed_out(port: &u16) -> bool {
    unsafe { OAP.get(port).is_some() }
}

#[inline(always)]
fn udp_port_allowed_in(port: &u16) -> bool {
    unsafe { UDP_IAP.get(port).is_some() }
}

#[inline(always)]
fn udp_port_allowed_out(port: &u16) -> bool {
    unsafe { UDP_OAP.get(port).is_some() }
}

#[inline(always)]
fn ip_addr_allowed(addrs: &u32) -> bool {
    unsafe { ALLST.get(addrs).is_some() }
}

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;

#[xdp]
pub fn sfw(ctx: XdpContext) -> u32 {
    match try_simple_firewall(ctx) {
        Ok(ret) => ret,
        Err(e) => e,
    }
}

fn try_simple_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: &EthHdr = unsafe { ptr_at(&ctx, 0)? }; //
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv: &Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let src_ip = ipv.src_addr();
            let dst_ip = ipv.dst_addr();
            let protocal = ipv.proto;
            // Won't mess with DNS
            if src_ip.is_private() && dst_ip.is_multicast() {
                return Ok(xdp_action::XDP_PASS);
            }
            // let size = unsafe { (*ipv).tot_len };
            match protocal {
                IpProto::Tcp => handle_tcp_xdp(ctx, src_ip, dst_ip, protocal),
                IpProto::Udp => handle_udp_xdp(ctx, src_ip, dst_ip, protocal),
                IpProto::Gre => {
                    // let header = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    info!(&ctx, "GRE tunnelling🥰");
                    Ok(xdp_action::XDP_PASS)
                }
                IpProto::Icmp => handle_icmp_xdp(ctx, src_ip, dst_ip),
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
        // EtherType
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn handle_tcp_xdp(
    ctx: XdpContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let header: &TcpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    // external port comming from outside
    let port = u16::from_be(header.source);
    // someone reaching to internal port
    let port_to = u16::from_be(header.dest);
    let connection = Connection {
        state: 2,
        src_ip: src_ip.to_bits(),
        dst_ip: dst_ip.to_bits(),
        src_port: port,
        dst_port: port_to,
        protocal: protocal as u8,
    };
    let session = &connection.ingress_session();
    if is_requested(&session.to_u64()) {
        debug!(
            &ctx,
            "ESTABLISHED on TCP with {:i}:{}",
            src_ip.to_bits(),
            port,
        );
        if header.rst() == 1 {
            debug!(
                &ctx,
                "Closing {:i}:{} on TCP", session.src_ip, session.src_port
            );
            _ = unsafe { CONNECTIONS.remove(&session.to_u64()) };
            unsafe { DEL.output(&ctx, session, 0) };
        }
        Ok(xdp_action::XDP_PASS)
    } else if tcp_port_allowed_in(&port_to) {
        debug!(
            &ctx,
            "TCP {:i}:{} ===> {:i}:{}",
            src_ip.to_bits(),
            port,
            dst_ip.to_bits(),
            port_to
        );
        Ok(xdp_action::XDP_PASS)
    } else {
        debug!(
            &ctx,
            "TCP_DROP! {:i}:{} -x-> {:i}:{}",
            src_ip.to_bits(),
            port,
            dst_ip.to_bits(),
            port_to,
        );
        Ok(xdp_action::XDP_DROP)
    }
}

fn handle_udp_xdp(
    ctx: XdpContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let header: &UdpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    // external port comming from outside
    let port = u16::from_be(header.source);
    // Allow to acsess is_broadcast request
    if unsafe { TEMPORT.get(&port).is_some() } {
        _ = unsafe { TEMPORT.remove(&port) };
        return Ok(xdp_action::XDP_PASS);
    }
    // someone reaching to internal port
    let port_to = u16::from_be(header.dest);
    let connection = Connection {
        state: 2,
        src_ip: src_ip.to_bits(),
        dst_ip: dst_ip.to_bits(),
        src_port: port,
        dst_port: port_to,
        protocal: protocal as u8,
    };
    let session = &connection.ingress_session();
    if is_requested(&session.to_u64()) {
        debug!(
            &ctx,
            "UDP ESTABLISHED on {:i}:{}", session.src_ip, session.src_port
        );
        Ok(xdp_action::XDP_PASS)
    } else if port == 53 && ip_addr_allowed(&src_ip.to_bits()) {
        // DNS Reslover let her in
        // add_request(&connection.ingress_session(), &connection);
        debug!(
            &ctx,
            "DNS! {:i}:{} <=== {:i}:{}",
            dst_ip.to_bits(),
            port_to,
            src_ip.to_bits(),
            port
        );
        // debug!(&ctx, "len {} check {}", syn, ack);
        // debug!(
        //     &ctx,
        //     "check {} tot_len {} frag_off {} ttl {} tos {} id {}",
        //     check,
        //     tot_len,
        //     frag_off,
        //     ttl,
        //     tos,
        //     id,
        // );
        Ok(xdp_action::XDP_PASS)
    } else if udp_port_allowed_in(&port_to) {
        debug!(
            &ctx,
            "UDP IN! {:i}:{} <=== {:i}:{}",
            dst_ip.to_bits(),
            port_to,
            src_ip.to_bits(),
            port,
        );
        return Ok(xdp_action::XDP_PASS);
    } else {
        debug!(
            &ctx,
            "UDP DROP! {:i}:{} -x-> {:i}:{}",
            src_ip.to_bits(),
            port,
            dst_ip.to_bits(),
            port_to
        );
        return Ok(xdp_action::XDP_DROP);
    }
}

fn handle_icmp_xdp(ctx: XdpContext, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Result<u32, u32> {
    let header: &IcmpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let icmp_type: u8 = header.type_;
    let icmp_text = match icmp_type {
        0 => "ECHO REPLY",
        3 => "PORT UNREACH",
        8 => "ECHO REQUEST",
        11 => "Time OUT",
        _ => "{icmp_type}",
    };
    debug!(
        &ctx,
        "ICMP {} {:i} -> {:i} ",
        icmp_text,
        src_ip.to_bits(),
        dst_ip.to_bits()
    );
    match icmp_type {
        ICMP_ECHO_REQUEST => Ok(xdp_action::XDP_DROP),
        ICMP_DEST_UNREACH => Ok(xdp_action::XDP_PASS),
        ICMP_ECHO_REPLY => Ok(xdp_action::XDP_PASS),
        ICMP_TIME_EXCEEDED => Ok(xdp_action::XDP_PASS),
        _ => Ok(xdp_action::XDP_DROP),
    }
}

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};

#[inline(always)]
unsafe fn tc_ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<&T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(TC_ACT_PIPE);
    }
    let data = (start + offset) as *const T;
    let data_ = unsafe { data.as_ref().ok_or(TC_ACT_PIPE)? };
    Ok(data_)
}

// #[inline(always)]
// unsafe fn ptr_mut<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i32> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = mem::size_of::<T>();
//     if start + offset + len > end {
//         return Err(TC_ACT_PIPE);
//     }
//     Ok((start + offset) as *mut T)
// }

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
            let src_ip = ipv4hdr.src_addr();
            let dst_ip = ipv4hdr.dst_addr();
            let protocal = ipv4hdr.proto;
            match ipv4hdr.proto {
                IpProto::Icmp => handle_icmp_egress(ctx, src_ip, dst_ip, protocal),
                IpProto::Tcp => handle_tcp_egress(ctx, src_ip, dst_ip, protocal),
                IpProto::Udp => handle_udp_egress(ctx, src_ip, dst_ip, protocal),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

pub fn handle_udp_egress(
    ctx: TcContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocal: IpProto,
) -> Result<i32, i32> {
    let udp_hdr: &UdpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let src_port = u16::from_be(udp_hdr.source);
    let dst_port = u16::from_be(udp_hdr.dest);
    if dst_ip.is_broadcast() {
        _ = unsafe { TEMPORT.insert(&dst_port, &0u8, 0) };
        return Ok(TC_ACT_PIPE);
    }
    let connection = Connection {
        state: 2,
        src_ip: src_ip.to_bits(),
        dst_ip: dst_ip.to_bits(),
        src_port,
        dst_port,
        protocal: protocal as u8,
    };
    // let ses = Session {
    //     src_ip: dst_ip,
    //     src_port: dst_port,
    //     protocol: protocal as u8,
    // };
    let session = &connection.egress_session();
    unsafe { NEW.output(&ctx, &connection, 0) };
    if dst_port == 53 && ip_addr_allowed(&dst_ip.to_bits()) {
        // DNS Reslover let her in
        // add_request(&connection.ingress_session(), &connection);
        debug!(
            &ctx,
            "DNS! {:i}:{} ==> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
    } else if udp_port_allowed_out(&dst_port) {
        debug!(
            &ctx,
            "UDP OUT! {:i}:{} ==> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
        if !is_requested(&session.to_u64()) {
            info!(
                &ctx,
                "UDP Bind {:i}:{} -> {:i}:{}",
                src_ip.to_bits(),
                src_port,
                dst_ip.to_bits(),
                dst_port,
            );
            add_request(&session.to_u64());
        }
        // } else {
        //     Ok(TC_ACT_SHOT)
    }
    // Just forward our request outside!!
    Ok(TC_ACT_PIPE)
}

pub fn handle_tcp_egress(
    ctx: TcContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocal: IpProto,
) -> Result<i32, i32> {
    // gather the TCP header
    // let size = unsafe { (*ip_hdr).tot_len };
    let tcp_hdr: &TcpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let src_port = u16::from_be(tcp_hdr.source);
    let dst_port = u16::from_be(tcp_hdr.dest);
    // The source identifier
    let connection = Connection {
        state: 2,
        src_ip: src_ip.to_bits(),
        dst_ip: dst_ip.to_bits(),
        src_port,
        dst_port,
        protocal: protocal as u8,
    };
    let ses = &connection.egress_session();
    // Maybe here??
    if tcp_hdr.rst() == 1 {
        if unsafe { CONNECTIONS.get(&ses.to_u64()).is_some() } {
            info!(&ctx, "Closing {:i}:{} on TCP", ses.src_ip, ses.src_port);
            // unsafe { DEL.output(&ctx, &connection, 0) };
            _ = unsafe { CONNECTIONS.remove(&ses.to_u64()) };
            unsafe { DEL.output(&ctx, ses, 0) };
        }
    } else if tcp_port_allowed_out(&dst_port) {
        // add_request(&session, &connection);
        unsafe { NEW.output(&ctx, &connection, 0) };
        if !is_requested(&ses.to_u64()) {
            info!(
                &ctx,
                "TCP Bind {:i}:{} -> {:i}:{}",
                src_ip.to_bits(),
                src_port,
                dst_ip.to_bits(),
                dst_port,
            );
            add_request(&ses.to_u64());
        }
    }
    Ok(TC_ACT_PIPE)
    // } else {
    //     info!(
    //         &ctx,
    //         "Not alloed {:i}:{} -x- {:i}:{}",
    //         src_ip.to_bits(),
    //         src_port,
    //         dst_ip.to_bits(),
    //         dst_port,
    //     );
    //     Ok(TC_ACT_SHOT)
    // }
}

pub fn handle_icmp_egress(
    ctx: TcContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    _: IpProto,
) -> Result<i32, i32> {
    let icmp_hdr: &IcmpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let icmp_type: u8 = icmp_hdr.type_;

    debug!(
        &ctx,
        "ICMP {} {:i} -> {:i} ",
        icmp_type,
        src_ip.to_bits(),
        dst_ip.to_bits()
    );

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
