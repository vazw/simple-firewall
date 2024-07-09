// #![allow(unused)]
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, PerfEventArray},
    programs::XdpContext,
};

use core::{mem, net::Ipv4Addr};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, ConnectionState, TCPState};

const PROTOCAL_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN;
const LOCAL_BROADCAST: u32 = 3232236031;

#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: HashMap<u64, ConnectionState> =
    HashMap::with_max_entries(512, 0);

#[map(name = "TCP_IN_SPORT")]
static mut TCP_IN_SPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);
#[map(name = "TCP_IN_DPORT")]
static mut TCP_IN_DPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);

#[map(name = "TCP_OUT_SPORT")]
static mut TCP_OUT_SPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);
#[map(name = "TCP_OUT_DPORT")]
static mut TCP_OUT_DPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);

#[map(name = "UDP_IN_SPORT")]
static mut UDP_IN_SPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);
#[map(name = "UDP_IN_DPORT")]
static mut UDP_IN_DPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);

#[map(name = "UDP_OUT_SPORT")]
static mut UDP_OUT_SPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);
#[map(name = "UDP_OUT_DPORT")]
static mut UDP_OUT_DPORT: HashMap<u16, u8> = HashMap::with_max_entries(24, 0);

#[map(name = "DNS_ADDR")]
static mut DNS_ADDR: HashMap<u32, u8> = HashMap::with_max_entries(24, 0);

#[map(name = "TEMPORT")]
static mut TEMPORT: HashMap<u16, u8> = HashMap::with_max_entries(8, 0);

#[map(name = "NEW")]
static mut NEW: PerfEventArray<u64> = PerfEventArray::with_max_entries(1600, 0);
#[map(name = "DEL")]
static mut DEL: PerfEventArray<u64> = PerfEventArray::with_max_entries(800, 0);
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
fn add_request(session: &u64, connection_state: &ConnectionState) {
    unsafe {
        let _ = CONNECTIONS.insert(session, connection_state, 0);
    }
}

#[inline(always)]
fn tcp_sport_in(port: &u16) -> bool {
    unsafe { TCP_IN_SPORT.get(port).is_some() }
}
#[inline(always)]
fn tcp_dport_in(port: &u16) -> bool {
    unsafe { TCP_IN_DPORT.get(port).is_some() }
}

#[inline(always)]
fn tcp_sport_out(port: &u16) -> bool {
    unsafe { TCP_OUT_SPORT.get(port).is_some() }
}
#[inline(always)]
fn tcp_dport_out(port: &u16) -> bool {
    unsafe { TCP_OUT_DPORT.get(port).is_some() }
}

#[inline(always)]
fn udp_sport_in(port: &u16) -> bool {
    unsafe { UDP_IN_SPORT.get(port).is_some() }
}
#[inline(always)]
fn udp_dport_in(port: &u16) -> bool {
    unsafe { UDP_IN_DPORT.get(port).is_some() }
}

#[inline(always)]
fn udp_sport_out(port: &u16) -> bool {
    unsafe { UDP_OUT_SPORT.get(port).is_some() }
}

#[inline(always)]
fn udp_dport_out(port: &u16) -> bool {
    unsafe { UDP_OUT_DPORT.get(port).is_some() }
}

#[inline(always)]
fn ip_addr_allowed(addrs: &u32) -> bool {
    unsafe { DNS_ADDR.get(addrs).is_some() }
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
            if src_ip.is_private()
                && (dst_ip.is_multicast()
                    || dst_ip.to_bits() == LOCAL_BROADCAST)
            {
                return Ok(xdp_action::XDP_PASS);
            }
            // let size = unsafe { (*ipv).tot_len };
            match protocal {
                IpProto::Tcp => handle_tcp_xdp(ctx, src_ip, dst_ip, protocal),
                IpProto::Udp => handle_udp_xdp(ctx, src_ip, dst_ip, protocal),
                IpProto::Gre => {
                    // let header = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    //#[cfg(debug_assertions)]
                    aya_log_ebpf::debug!(&ctx, "GRE tunnelling🥰");
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
    let connection = Connection::ingress(
        src_ip.to_bits(),
        port,
        dst_ip.to_bits(),
        port_to,
        protocal as u8,
    );
    let session = &connection.into_session().to_u64();
    if is_requested(session) {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "ESTABLISHED on TCP with {:i}:{}",
            src_ip.to_bits(),
            port,
        );
        if update_tcp_conns_xdp(&ctx, header, session) {
            Ok(xdp_action::XDP_PASS)
        } else {
            aya_log_ebpf::info!(
                &ctx,
                "Closing {:i}:{} on TCP",
                connection.src_ip,
                connection.src_port
            );
            Ok(xdp_action::XDP_DROP)
        }
    } else if tcp_dport_in(&port_to) || tcp_sport_in(&port) {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "TCP {:i}:{} ===> {:i}:{}",
            src_ip.to_bits(),
            port,
            dst_ip.to_bits(),
            port_to
        );
        add_request(session, &connection.into_state_listen());
        unsafe { NEW.output(&ctx, session, 0) };
        Ok(xdp_action::XDP_PASS)
    } else {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
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
    let connection = Connection::ingress(
        src_ip.to_bits(),
        port,
        dst_ip.to_bits(),
        port_to,
        protocal as u8,
    );
    let session = &connection.into_session();
    if is_requested(&session.to_u64()) {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "UDP ESTABLISHED on {:i}:{}",
            session.src_ip,
            session.src_port
        );
        Ok(xdp_action::XDP_PASS)
    } else if port == 53 && ip_addr_allowed(&src_ip.to_bits()) {
        // DNS Reslover let her in
        // add_request(&connection.ingress_session(), &connection);
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "DNS! {:i}:{} <== {:i}:{}",
            dst_ip.to_bits(),
            port_to,
            src_ip.to_bits(),
            port
        );
        Ok(xdp_action::XDP_PASS)
    } else if udp_dport_in(&port_to) || udp_sport_in(&port) {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "UDP IN! {:i}:{} <=== {:i}:{}",
            dst_ip.to_bits(),
            port_to,
            src_ip.to_bits(),
            port,
        );
        return Ok(xdp_action::XDP_PASS);
    } else {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
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

fn handle_icmp_xdp(
    ctx: XdpContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<u32, u32> {
    let header: &IcmpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let icmp_type: u8 = header.type_;
    // if cfg!(debug_assertions) {
    let icmp_text = match icmp_type {
        0 => "ECHO REPLY",
        3 => "PORT UNREACH",
        8 => "ECHO REQUEST",
        11 => "Time OUT",
        _ => "{icmp_type}",
    };
    aya_log_ebpf::debug!(
        &ctx,
        "ICMP {} {:i} -> {:i} ",
        icmp_text,
        src_ip.to_bits(),
        dst_ip.to_bits()
    );
    // }
    match icmp_type {
        ICMP_ECHO_REQUEST => Ok(xdp_action::XDP_DROP),
        ICMP_DEST_UNREACH => Ok(xdp_action::XDP_PASS),
        ICMP_ECHO_REPLY => Ok(xdp_action::XDP_PASS),
        ICMP_TIME_EXCEEDED => Ok(xdp_action::XDP_PASS),
        _ => Ok(xdp_action::XDP_DROP),
    }
}

use aya_ebpf::{
    bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext,
};

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
                IpProto::Icmp => {
                    handle_icmp_egress(ctx, src_ip, dst_ip, protocal)
                }
                IpProto::Tcp => {
                    handle_tcp_egress(ctx, src_ip, dst_ip, protocal)
                }
                IpProto::Udp => {
                    handle_udp_egress(ctx, src_ip, dst_ip, protocal)
                }
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
    let connection = Connection::egress(
        src_ip.to_bits(),
        src_port,
        dst_ip.to_bits(),
        dst_port,
        protocal as u8,
    );
    // let ses = Session {
    //     src_ip: dst_ip,
    //     src_port: dst_port,
    //     protocol: protocal as u8,
    // };
    let session = &connection.into_session();
    if is_requested(&session.to_u64()) {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP ESTABLISHED! {:i}:{} ==> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
        Ok(TC_ACT_PIPE)
    } else if dst_port == 53 && ip_addr_allowed(&dst_ip.to_bits()) {
        // DNS Reslover let her in
        // add_request(&connection.ingress_session(), &connection);
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "DNS! {:i}:{} ==> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
        Ok(TC_ACT_PIPE)
    } else if udp_dport_out(&dst_port) || udp_sport_out(&src_port) {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "UDP OUT! {:i}:{} ==> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "UDP Bind {:i}:{} -> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port,
        );
        unsafe { NEW.output(&ctx, &session.to_u64(), 0) };
        add_request(&session.to_u64(), &connection.into_state());
        Ok(TC_ACT_PIPE)
        // } else {
        //     Ok(TC_ACT_SHOT)
    } else {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "UDP OUT! {:i}:{} -x- {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port
        );
        Ok(TC_ACT_SHOT)
    }
    // Just forward our request outside!!
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
    let connection = Connection::egress(
        src_ip.to_bits(),
        src_port,
        dst_ip.to_bits(),
        dst_port,
        protocal as u8,
    );
    let ses = &connection.into_session();
    // Maybe here??
    if is_requested(&ses.to_u64()) {
        if update_tcp_conns(&ctx, tcp_hdr, &ses.to_u64()) {
            aya_log_ebpf::info!(
                &ctx,
                "Closing {:i}:{} on TCP",
                ses.src_ip,
                ses.src_port
            );
        }
        Ok(TC_ACT_PIPE)
    } else if tcp_dport_out(&dst_port) || tcp_sport_out(&src_port) {
        // add_request(&session, &connection);
        unsafe { NEW.output(&ctx, &ses.to_u64(), 0) };
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "TCP Bind {:i}:{} -> {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port,
        );
        add_request(&ses.to_u64(), &connection.into_state());
        Ok(TC_ACT_PIPE)
    } else {
        //#[cfg(debug_assertions)]
        aya_log_ebpf::debug!(
            &ctx,
            "Not allowed {:i}:{} -x- {:i}:{}",
            src_ip.to_bits(),
            src_port,
            dst_ip.to_bits(),
            dst_port,
        );
        Ok(TC_ACT_SHOT)
    }
}

pub fn handle_icmp_egress(
    ctx: TcContext,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    _: IpProto,
) -> Result<i32, i32> {
    // if cfg!(debug_assertions) {
    let icmp_hdr: &IcmpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let icmp_type: u8 = icmp_hdr.type_;

    aya_log_ebpf::debug!(
        &ctx,
        "ICMP {} {:i} -> {:i} ",
        icmp_type,
        src_ip.to_bits(),
        dst_ip.to_bits()
    );
    // }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
pub fn process_tcp_state_transition(
    hdr: &TcpHdr,
    connection_state: &mut ConnectionState,
) -> (bool, bool) {
    let syn = hdr.syn() != 0;
    let ack = hdr.ack() != 0;
    let fin = hdr.fin() != 0;
    let rst = hdr.rst() != 0;
    let current_time = unsafe { bpf_ktime_get_ns() };
    let mut action = true;

    if rst {
        connection_state.tcp_state = TCPState::Closed;
        return (true, action);
    }
    // Check for SYN-ACK flood
    if syn && ack {
        if current_time - connection_state.last_syn_ack_time > 1_000_000_000 {
            // 1 second in nanoseconds
            connection_state.syn_ack_count = 1;
            connection_state.last_syn_ack_time = current_time;
        } else {
            connection_state.syn_ack_count += 1;
            if connection_state.syn_ack_count > 10000 {
                // Threshold
                action = false; // Drop the packet
            }
        }
    };

    match connection_state.tcp_state {
        TCPState::Closed => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynSent;
                return (true, action);
            }
        }
        TCPState::Listen => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynReceived;
                return (true, action);
            }
        }
        TCPState::SynReceived => {
            if ack && !syn {
                connection_state.tcp_state = TCPState::Established;
                return (true, action);
            }
        }
        TCPState::SynSent => {
            if syn && ack {
                connection_state.tcp_state = TCPState::Established;
                return (true, action);
            }
        }
        TCPState::Established => {
            if fin {
                connection_state.tcp_state = TCPState::FinWait1;
                return (true, action);
            }
        }
        TCPState::FinWait1 => {
            if fin && ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return (true, action);
            }
            if fin {
                connection_state.tcp_state = TCPState::Closing;
                return (true, action);
            }
            if ack {
                connection_state.tcp_state = TCPState::FinWait2;
                return (true, action);
            }
        }
        TCPState::FinWait2 => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return (true, action);
            }
        }
        TCPState::Closing => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return (true, action);
            }
        }
        TCPState::TimeWait => {
            if ack {
                connection_state.tcp_state = TCPState::Closed;
                return (true, action);
            }
        }
        _ => {}
    }
    (false, action)
}

// Modifies the map tracking TCP connections based on the current state
// of the TCP connection and the incoming TCP packet's header.
#[inline(always)]
pub fn update_tcp_conns(
    ctx: &TcContext,
    hdr: &TcpHdr,
    session_key: &u64,
) -> bool {
    if let Some(connection_state) = unsafe { CONNECTIONS.get(session_key) } {
        let mut connection_state = *connection_state;
        let (transitioned, action) =
            process_tcp_state_transition(hdr, &mut connection_state);
        if transitioned && connection_state.tcp_state == TCPState::Closed {
            unsafe { DEL.output(ctx, session_key, 0) };
            _ = unsafe { CONNECTIONS.remove(session_key) };
            return action;
        };
        // If the connection has not reached the Closed state yet, but it did transition to a new state,
        // then record the new state.
        if transitioned {
            _ = unsafe {
                CONNECTIONS.insert(session_key, &connection_state, 0_u64)
            };
            return action;
        }
    }
    true
}
#[inline(always)]
pub fn update_tcp_conns_xdp(
    ctx: &XdpContext,
    hdr: &TcpHdr,
    session_key: &u64,
) -> bool {
    if let Some(connection_state) = unsafe { CONNECTIONS.get(session_key) } {
        let mut connection_state = *connection_state;
        let (transitioned, action) =
            process_tcp_state_transition(hdr, &mut connection_state);
        if transitioned && connection_state.tcp_state == TCPState::Closed {
            unsafe { DEL.output(ctx, session_key, 0) };
            _ = unsafe { CONNECTIONS.remove(session_key) };
            return action;
        };
        // If the connection has not reached the Closed state yet, but it did transition to a new state,
        // then record the new state.
        if transitioned {
            _ = unsafe {
                CONNECTIONS.insert(session_key, &connection_state, 0_u64)
            };
            return action;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
