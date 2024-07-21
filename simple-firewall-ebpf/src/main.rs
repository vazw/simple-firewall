#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_SHOT},
    helpers::{bpf_csum_diff, bpf_ktime_get_ns},
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
// 192.168.1.255
const LOCAL_BROADCAST: u32 = 3232236031;
// 255.255.255.255
const BROADCAST: u32 = 4294967295;

// Allocated 20KB for connection
#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: HashMap<u32, ConnectionState> =
    HashMap::with_max_entries(10_000, 0);
#[map(name = "UNKNOWN")]
static mut UNKNOWN: HashMap<u32, ConnectionState> =
    HashMap::with_max_entries(256, 0);
// #[map(name = "KNOWN")]
// static mut KNOWN: HashMap<u32, ConnectionState> =
//     HashMap::with_max_entries(256, 0);

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

#[map(name = "NEW")]
static mut NEW: PerfEventArray<Connection> =
    PerfEventArray::with_max_entries(1600, 0);
#[map(name = "DEL")]
static mut DEL: PerfEventArray<Connection> =
    PerfEventArray::with_max_entries(800, 0);

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
unsafe fn ptr_at_mut<T>(
    ctx: &XdpContext,
    offset: usize,
) -> Result<*mut T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

// Session using remoteIP
#[inline(always)]
fn is_requested(session: &u32) -> Result<*mut ConnectionState, ()> {
    unsafe {
        if let Some(cons) = CONNECTIONS.get_ptr_mut(session) {
            if !(*cons).tcp_state.eq(&TCPState::Closed) {
                return Ok(cons);
            } else {
                return Err(());
            }
        }
        Err(())
    }
}

// pub const BPF_ANY = 0;
// pub const BPF_NOEXIST = 1;
// pub const BPF_EXIST = 2;

#[inline(always)]
fn add_request(session: &u32, connection_state: &ConnectionState) -> bool {
    unsafe { CONNECTIONS.insert(session, connection_state, 0).is_ok() }
}

#[inline(always)]
fn tcp_sport_in(port: u16) -> bool {
    unsafe { TCP_IN_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
fn tcp_dport_in(port: u16) -> bool {
    unsafe { TCP_IN_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
fn tcp_sport_out(port: u16) -> bool {
    unsafe { TCP_OUT_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
fn tcp_dport_out(port: u16) -> bool {
    unsafe { TCP_OUT_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
fn udp_sport_in(port: u16) -> bool {
    unsafe { UDP_IN_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
fn udp_dport_in(port: u16) -> bool {
    unsafe { UDP_IN_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
fn udp_sport_out(port: u16) -> bool {
    unsafe { UDP_OUT_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
fn udp_dport_out(port: u16) -> bool {
    unsafe { UDP_OUT_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
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
            let remote_addr = ipv.src_addr();
            let host_addr = ipv.dst_addr();
            let protocal = ipv.proto;
            // Won't mess with DNS, mulicast and Broadcast
            if (host_addr.is_private()
                || host_addr.is_unspecified()
                || host_addr.is_multicast()
                || host_addr.to_bits() == BROADCAST)
                && (remote_addr.is_multicast()
                    || remote_addr.to_bits() == LOCAL_BROADCAST
                    || remote_addr.is_private())
            {
                return Ok(xdp_action::XDP_PASS);
            }
            // let size = unsafe { (*ipv).tot_len };
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

fn handle_tcp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let ipv: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    let header_mut: *mut TcpHdr = unsafe { ptr_at_mut(&ctx, PROTOCAL_OFFSET)? };
    // Playing with header
    // let total_len = unsafe { (*ipv).tot_len };
    // let ip_len = unsafe { (*ipv).ihl() * 4 };
    // let header_len = unsafe { (*header_mut).doff() * 4 };
    // let header_sums = unsafe { (*ipv).check };
    // aya_log_ebpf::info!(
    //     &ctx,
    //     "from {:i} header checksum:{}",
    //     host_addr.to_bits(),
    //     header_sums
    // );
    if let Some(header) = unsafe { header_mut.as_ref() } {
        // let data_off = header.doff();
        // external host_port comming from outside
        let remote_port = u16::from_be(header.source);
        // someone reaching to internal host_port
        let host_port = u16::from_be(header.dest);
        let connection = Connection::ingress(
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
            protocal as u8,
        );
        let sums_key = connection.into_session();
        if let Ok(connection_state) = is_requested(&sums_key) {
            if unsafe {
                // (*connection_state).remote_ip.eq(&connection.remote_addr)
                !(*connection_state).tcp_state.eq(&TCPState::Closed)
            } {
                let transitioned = unsafe {
                    process_tcp_state_transition(
                        header,
                        &mut (*connection_state),
                    )
                };
                aya_log_ebpf::debug!(
                    &ctx,
                    "ESTABLISHED on TCP with {:i}:{}",
                    remote_addr.to_bits(),
                    remote_port,
                );

                if transitioned
                    && unsafe {
                        (*connection_state).tcp_state.eq(&TCPState::Closed)
                    }
                {
                    unsafe { DEL.output(&ctx, &connection, 0) };
                }
                Ok(xdp_action::XDP_PASS)
            } else {
                let transitioned = unsafe {
                    process_tcp_state_transition(
                        header,
                        &mut (*connection_state),
                    )
                };
                if transitioned
                    && unsafe {
                        !(*connection_state).tcp_state.eq(&TCPState::Closed)
                    }
                {
                    Ok(xdp_action::XDP_PASS)
                } else if transitioned
                    && unsafe {
                        (*connection_state).tcp_state.eq(&TCPState::Listen)
                    }
                {
                    let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
                    let src_mac = unsafe { (*ethdr).src_addr };
                    let dst_mac = unsafe { (*ethdr).dst_addr };
                    unsafe {
                        (*header_mut).set_ack(0);
                        (*header_mut).set_syn(0);
                        (*header_mut).set_rst(1);
                        (*header_mut).dest = connection.remote_port.to_be();
                        (*header_mut).source = connection.host_port.to_be();
                        (*header_mut).ack_seq = 0;
                        (*header_mut).seq = 0;
                        (*ethdr).src_addr = dst_mac;
                        (*ethdr).dst_addr = src_mac;
                        (*ipv).dst_addr = connection.remote_addr.to_be();
                        (*ipv).src_addr = connection.host_addr.to_be();
                        (*ipv).check = 0;
                        let full_sum = bpf_csum_diff(
                            mem::MaybeUninit::zeroed().assume_init(),
                            0,
                            ipv as *mut u32,
                            Ipv4Hdr::LEN as u32,
                            0,
                        ) as u64;
                        (*ipv).check = csum_fold_helper(full_sum);
                        // (*header_mut).check -= 17u16.to_be();
                        // Manual padding checksum :D
                        (*header_mut).check += 12u16.to_be();
                    };
                    Ok(xdp_action::XDP_TX)
                } else {
                    Ok(xdp_action::XDP_DROP)
                }
            }
        } else if let Some(connection_state) =
            // Known and unkown connections
            // will be handle here with agressive tcp rst on first try
            unsafe {
                UNKNOWN.get_ptr_mut(&connection.remote_addr)
            }
        {
            aya_log_ebpf::info!(
                &ctx,
                "UNKNOWN on TCP from {:i}:{}",
                remote_addr.to_bits(),
                remote_port,
            );
            let transitioned =
                unsafe { agressive_tcp_rst(header, &mut (*connection_state)) };
            if transitioned.eq(&TCPState::Established) {
                aya_log_ebpf::info!(&ctx, "Established",);
                unsafe {
                    (*header_mut).set_ack(0);
                    (*header_mut).set_syn(0);
                    (*header_mut).set_rst(1);
                    // Manual padding checksum :D
                    (*header_mut).check += 12u16.to_be();
                    if CONNECTIONS
                        .insert(&sums_key, &connection.into_state_listen(), 0)
                        .is_ok()
                    {
                        aya_log_ebpf::info!(&ctx, "Added new con",);
                    }
                    if UNKNOWN.remove(&connection.remote_addr).is_ok() {
                        aya_log_ebpf::info!(&ctx, "removed from unkown",);
                    }
                    NEW.output(&ctx, &connection, 0);
                };
            } else if transitioned.eq(&TCPState::SynReceived) {
                aya_log_ebpf::info!(&ctx, "SynReceived",);
                unsafe {
                    (*header_mut).set_syn(1);
                    (*header_mut).check -= 17u16.to_be();
                    (*header_mut).set_ack(1);
                };
            }
            // } else {
            //     unsafe {
            //         (*header_mut).set_syn(0);
            //         (*header_mut).set_syn(0);
            //         (*header_mut).set_ack(0);
            //         (*header_mut).set_rst(1);
            //         (*header_mut).set_psh(0);
            //         (*header_mut).check += 12u16.to_be();
            //     }
            //     aya_log_ebpf::debug!(&ctx, "unknown state",);
            //     return Ok(xdp_action::XDP_TX);
            // }
            let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
            let src_mac = unsafe { (*ethdr).src_addr };
            let dst_mac = unsafe { (*ethdr).dst_addr };
            unsafe {
                (*ethdr).src_addr = dst_mac;
                (*ethdr).dst_addr = src_mac;
                (*ipv).dst_addr = connection.remote_addr.to_be();
                (*header_mut).dest = connection.remote_port.to_be();
                (*ipv).src_addr = connection.host_addr.to_be();
                (*header_mut).source = connection.host_port.to_be();
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
                (*header_mut).seq = 0;
                (*ipv).check = 0;
                let full_sum = bpf_csum_diff(
                    mem::MaybeUninit::zeroed().assume_init(),
                    0,
                    ipv as *mut u32,
                    Ipv4Hdr::LEN as u32,
                    0,
                ) as u64;
                (*ipv).check = csum_fold_helper(full_sum);
            }
            Ok(xdp_action::XDP_TX)
        } else if tcp_dport_in(host_port) || tcp_sport_in(remote_port) {
            aya_log_ebpf::info!(
                &ctx,
                "TCP {:i}:{} <== {:i}:{}",
                host_addr.to_bits(),
                host_port,
                remote_addr.to_bits(),
                remote_port,
            );
            let transitioned = unsafe {
                agressive_tcp_rst(header, &mut connection.into_state_listen())
            };
            if transitioned.eq(&TCPState::SynReceived) {
                unsafe {
                    _ = UNKNOWN.insert(
                        &connection.remote_addr,
                        &connection.into_state_synreceived(),
                        0,
                    )
                };
            }

            let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
            let src_mac = unsafe { (*ethdr).src_addr };
            let dst_mac = unsafe { (*ethdr).dst_addr };
            let ipv: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
            unsafe {
                (*header_mut).set_ack(1);
                (*header_mut).set_syn(1);
                (*ethdr).src_addr = dst_mac;
                (*ethdr).dst_addr = src_mac;
                (*ipv).dst_addr = connection.remote_addr.to_be();
                (*header_mut).dest = connection.remote_port.to_be();
                (*ipv).src_addr = connection.host_addr.to_be();
                (*header_mut).source = connection.host_port.to_be();
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
                (*header_mut).seq = 0;
                (*ipv).check = 0;
                let full_sum = bpf_csum_diff(
                    mem::MaybeUninit::zeroed().assume_init(),
                    0,
                    ipv as *mut u32,
                    Ipv4Hdr::LEN as u32,
                    0,
                ) as u64;
                (*ipv).check = csum_fold_helper(full_sum);
                (*header_mut).check -= 17u16.to_be();
            }
            Ok(xdp_action::XDP_TX)
        } else {
            aya_log_ebpf::debug!(
                &ctx,
                "TCP DROP! {:i}:{} -x- {:i}:{}",
                host_addr.to_bits(),
                host_port,
                remote_addr.to_bits(),
                remote_port,
            );
            Ok(xdp_action::XDP_DROP)
        }
    } else {
        Err(xdp_action::XDP_PASS)
    }
}

fn handle_udp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let header: &UdpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    // external host_port comming from outside
    let remote_port = u16::from_be(header.source);
    // Allow to acsess is_broadcast request
    if let Some(port_) = unsafe { TEMPORT.get_ptr_mut(remote_port as u32) } {
        if unsafe { (*port_).eq(&0x1) } {
            unsafe { *port_ = 0xff };
            return Ok(xdp_action::XDP_PASS);
        }
    }
    // someone reaching to internal host_port
    let host_port = u16::from_be(header.dest);
    let connection = Connection::ingress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
    );
    let sum_key = connection.into_session();
    if is_requested(&sum_key).is_ok() {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP ESTABLISHED on {:i}:{}",
            connection.remote_addr,
            connection.remote_port
        );
        Ok(xdp_action::XDP_PASS)
    } else if udp_dport_in(remote_port) || udp_sport_in(host_port) {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP IN! {:i}:{} <=== {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        return Ok(xdp_action::XDP_PASS);
    } else {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP DROP! {:i}:{} -x- {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port
        );
        return Ok(xdp_action::XDP_DROP);
    }
}

fn handle_icmp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
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
        host_addr.to_bits(),
        remote_addr.to_bits()
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

pub fn handle_udp_egress(
    ctx: TcContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<i32, i32> {
    let udp_hdr: &UdpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let host_port = u16::from_be(udp_hdr.source);
    let remote_port = u16::from_be(udp_hdr.dest);
    if remote_addr.is_broadcast() {
        if let Some(port_) = unsafe { TEMPORT.get_ptr_mut(remote_port as u32) }
        {
            unsafe { *port_ = 0x1 };
        }
        return Ok(TC_ACT_PIPE);
    }
    let connection = Connection::egress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
    );
    let sum_key = connection.into_session();
    if is_requested(&sum_key).is_ok() {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP ESTABLISHED! {:i}:{} ==> {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port
        );
        Ok(TC_ACT_PIPE)
    } else if remote_port == 53 && ip_addr_allowed(&remote_addr.to_bits()) {
        add_request(&sum_key, &connection.into_state_sent());
        aya_log_ebpf::debug!(
            &ctx,
            "DNS! {:i}:{} ==> {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port
        );
        Ok(TC_ACT_PIPE)
    } else if udp_dport_out(remote_port) || udp_sport_out(host_port) {
        add_request(&sum_key, &connection.into_state_sent());
        aya_log_ebpf::debug!(
            &ctx,
            "UDP Bind {:i}:{} -> {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        unsafe { NEW.output(&ctx, &connection, 0) };
        Ok(TC_ACT_PIPE)
    } else {
        aya_log_ebpf::debug!(
            &ctx,
            "UDP OUT! {:i}:{} -x- {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port
        );
        Ok(TC_ACT_SHOT)
    }
    // Just forward our request outside!!
}

pub fn handle_tcp_egress(
    ctx: TcContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<i32, i32> {
    // gather the TCP header
    // let size = unsafe { (*ip_hdr).tot_len };
    let tcp_hdr: &TcpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let host_port = u16::from_be(tcp_hdr.source);
    let remote_port = u16::from_be(tcp_hdr.dest);
    // The source identifier
    let connection = Connection::egress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
    );
    let sums_key = connection.into_session();
    if let Ok(connection_state) = is_requested(&sums_key) {
        let transitioned = unsafe {
            process_tcp_state_transition(tcp_hdr, &mut (*connection_state))
        };
        if transitioned
            && unsafe { (*connection_state).tcp_state.eq(&TCPState::Closed) }
        {
            unsafe { DEL.output(&ctx, &connection, 0) };
        }
        aya_log_ebpf::debug!(
            &ctx,
            "ESTABLISHED on TCP with {:i}:{}",
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(TC_ACT_PIPE)
    } else if tcp_dport_out(remote_port) || tcp_sport_out(host_port) {
        add_request(&sums_key, &connection.into_state_sent());
        unsafe { NEW.output(&ctx, &connection, 0) };
        aya_log_ebpf::debug!(
            &ctx,
            "TCP Bind {:i}:{} -> {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        // } else {
        //     aya_log_ebpf::debug!(
        //         &ctx,
        //         "TCP Bind {:i}:{} -> {:i}:{} Failed",
        //         host_addr.to_bits(),
        //         host_port,
        //         remote_addr.to_bits(),
        //         remote_port,
        //     );
        // }
        Ok(TC_ACT_PIPE)
    } else {
        aya_log_ebpf::debug!(
            &ctx,
            "Not allowed {:i}:{} -x- {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(TC_ACT_SHOT)
    }
}

pub fn handle_icmp_egress(
    ctx: TcContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    _: IpProto,
) -> Result<i32, i32> {
    // if cfg!(debug_assertions) {
    let icmp_hdr: &IcmpHdr = unsafe { tc_ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let icmp_type: u8 = icmp_hdr.type_;

    aya_log_ebpf::debug!(
        &ctx,
        "ICMP {} {:i} -> {:i} ",
        icmp_type,
        host_addr.to_bits(),
        remote_addr.to_bits()
    );
    // }

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
unsafe fn process_tcp_state_transition(
    hdr: &TcpHdr,
    connection_state: &mut ConnectionState,
) -> bool {
    let syn = hdr.syn() != 0;
    let ack = hdr.ack() != 0;
    let fin = hdr.fin() != 0;
    let rst = hdr.rst() != 0;
    let psh = hdr.psh() != 0;

    if rst {
        connection_state.tcp_state = TCPState::Closed;
        return true;
    }
    // Check for SYN-ACK flood
    if syn && ack {
        let current_time = unsafe { bpf_ktime_get_ns() };
        // 1 second in nanoseconds
        if current_time - connection_state.last_syn_ack_time > 1_000_000_000 {
            connection_state.syn_ack_count = 1;
            connection_state.last_syn_ack_time = current_time;
        } else {
            connection_state.syn_ack_count += 1;
            // Threshold
            if connection_state.syn_ack_count > 100 {
                connection_state.tcp_state = TCPState::Closed;
                return true;
            }
        }
    };

    match connection_state.tcp_state {
        TCPState::Closed => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynSent;
                return true;
            }
        }
        TCPState::Listen => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynReceived;
                return true;
            }
        }
        TCPState::SynReceived => {
            if ack && !syn {
                connection_state.tcp_state = TCPState::Established;
                return true;
            }
        }
        TCPState::SynSent => {
            if syn && ack {
                connection_state.tcp_state = TCPState::Established;
                return true;
            }
        }
        TCPState::Established => {
            if fin {
                connection_state.tcp_state = TCPState::FinWait1;
                return true;
            } else if psh && ack {
                connection_state.tcp_state = TCPState::Listen;
                return true;
            }
        }
        TCPState::FinWait1 => {
            if fin && ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
            if fin {
                connection_state.tcp_state = TCPState::Closing;
                return true;
            }
            if ack {
                connection_state.tcp_state = TCPState::FinWait2;
                return true;
            }
        }
        TCPState::FinWait2 => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::Closing => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::TimeWait => {
            if ack {
                connection_state.tcp_state = TCPState::Closed;
                return true;
            }
        }
        _ => {}
    }
    false
}

#[inline(always)]
unsafe fn agressive_tcp_rst(
    hdr: &TcpHdr,
    connection_state: &mut ConnectionState,
) -> TCPState {
    let syn = hdr.syn() != 0;
    let ack = hdr.ack() != 0;
    let rst = hdr.rst() != 0;

    match connection_state.tcp_state {
        TCPState::Listen => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynReceived;
                TCPState::SynReceived
            } else {
                TCPState::Closed
            }
        }
        TCPState::SynReceived => {
            if (ack && !syn) || rst {
                connection_state.tcp_state = TCPState::Established;
                TCPState::Established
            } else {
                TCPState::SynReceived
            }
        }
        _ => TCPState::Closed,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
