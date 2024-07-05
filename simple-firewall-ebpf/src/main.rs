#![no_std]
#![no_main]

mod cpus;
use cpus::CPUS;

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::bpf_map_lookup_percpu_elem,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::{mem, ptr::addr_of_mut};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, IcmpPacket, Session};

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
#[map(name = "RATE")]
static mut RATE: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);
#[map(name = "RATE_LIMIT")]
static mut RATE_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "HOST")]
static mut HOST: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "CONS")]
static mut CONNECTIONS: HashMap<Session, Connection> = HashMap::with_max_entries(512, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    Ok((start + offset) as *const T)
}

fn is_requested(session: &Session) -> bool {
    // if let Some(con) = unsafe { CONNECTIONS.get(connection) } {
    //     con.eq(connection)
    // } else {
    //     false
    // }
    unsafe { CONNECTIONS.get(session).is_some() }
}

fn add_request(session: &Session, connection: &Connection) {
    if unsafe { CONNECTIONS.get(session).is_none() } {
        unsafe {
            let _ = CONNECTIONS.insert(session, connection, 0);
        }
    }
}

fn rate_add() {
    if let Some(counter) = unsafe { RATE.get_ptr_mut(0) } {
        unsafe {
            *counter += 1;
        }
    }
}

fn rate_limit() -> bool {
    if let Some(rate) = unsafe { RATE_LIMIT.get(0) } {
        let all_rate = get_total_cpu_counter();
        all_rate.ge(rate)
    } else {
        true
    }
}

fn tcp_port_allowed_in(port: &u16) -> bool {
    unsafe { IAP.get(port).is_some() }
}
fn tcp_port_allowed_out(port: &u16) -> bool {
    unsafe { OAP.get(port).is_some() }
}
fn udp_port_allowed_in(port: &u16) -> bool {
    unsafe { UDP_IAP.get(port).is_some() }
}
fn udp_port_allowed_out(port: &u16) -> bool {
    unsafe { UDP_OAP.get(port).is_some() }
}
fn ip_addr_allowed(addrs: &u32) -> bool {
    unsafe { ALLST.get(addrs).is_some() }
}

#[inline(always)]
fn get_total_cpu_counter() -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..CPUS {
        let c = unsafe {
            bpf_map_lookup_percpu_elem(
                addr_of_mut!(RATE) as *mut _ as *mut c_void,
                &0 as *const _ as *const c_void,
                cpu,
            )
        };

        if !c.is_null() {
            unsafe {
                let counter = &mut *(c as *mut u32);
                sum += *counter;
            }
        }
    }
    sum
}

// const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
// const ICMP_TIME_EXCEEDED: u8 = 11;

#[xdp]
pub fn sfw(ctx: XdpContext) -> u32 {
    match try_simple_firewall(ctx) {
        Ok(ret) => ret,
        Err(e) => e,
    }
}

fn try_simple_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let src_ip = u32::from_be(unsafe { (*ipv).src_addr });
            let dst_ip = u32::from_be(unsafe { (*ipv).dst_addr });
            // let size = unsafe { (*ipv).tot_len };
            match unsafe { (*ipv).proto } {
                IpProto::Gre => {
                    // let header = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    info!(&ctx, "GRE tunnelling🥰");
                    Ok(xdp_action::XDP_PASS)
                }
                IpProto::Icmp => {
                    let header: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let icmp_type: u8 = unsafe { (*header).type_ };
                    info!(&ctx, "ICMP {} {:i} -> {:i} ", icmp_type, src_ip, dst_ip);
                    match icmp_type {
                        ICMP_ECHO_REQUEST => Ok(xdp_action::XDP_DROP),
                        _ => Ok(xdp_action::XDP_DROP),
                    }
                }
                IpProto::Tcp => {
                    let header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    // external port comming from outside
                    let port = u16::from_be(unsafe { (*header).source });
                    // someone reaching to internal port
                    let port_to = u16::from_be(unsafe { (*header).dest });
                    let connection = Connection {
                        state: 2,
                        src_ip,
                        dst_ip,
                        src_port: port,
                        dst_port: port_to,
                        protocol: 6,
                    };
                    let session = Session {
                        src_ip,
                        src_port: port,
                        protocol: 6,
                    };

                    if let Some(tcp_hdr_ref) = unsafe { header.as_ref() } {
                        // info!(&ctx, "con {:i}:{}", connection.src_ip, connection.src_port);
                        // info!(
                        //     &ctx,
                        //     "ack {}| cwr {}| ece {}| fin {}| psh {}| rst {}| syn {}| urg{}",
                        //     tcp_hdr_ref.ack(),
                        //     tcp_hdr_ref.cwr(),
                        //     tcp_hdr_ref.ece(),
                        //     tcp_hdr_ref.fin(),
                        //     tcp_hdr_ref.psh(),
                        //     tcp_hdr_ref.rst(),
                        //     tcp_hdr_ref.syn(),
                        //     tcp_hdr_ref.urg()
                        // );
                        if tcp_hdr_ref.rst() == 1 {
                            let if_connected = unsafe { CONNECTIONS.get(&session) };
                            if if_connected.is_some() {
                                debug!(
                                    &ctx,
                                    "Closing {:i}:{} on TCP", session.src_ip, session.src_port
                                );
                                _ = unsafe { CONNECTIONS.remove(&session) };
                                //let it pass
                                return Ok(xdp_action::XDP_PASS);
                            }
                        }
                    };

                    if is_requested(&session) {
                        debug!(
                            &ctx,
                            "ESTABLISHED on {:i}:{}", connection.src_ip, connection.src_port
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else if tcp_port_allowed_in(&port) || tcp_port_allowed_out(&port_to) {
                        // add_request(&session, &connection);
                        debug!(
                            &ctx,
                            "TCP {:i}:{} ===> {:i}:{}", src_ip, port, dst_ip, port_to
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else {
                        debug!(
                            &ctx,
                            "TCP_DROP! {:i}:{} -x-> {:i}:{}", src_ip, port, dst_ip, port_to,
                        );
                        // info!(
                        //     &ctx,
                        //     "Session is {:i}:{} {}",
                        //     session.src_ip,
                        //     session.src_port,
                        //     session.protocol
                        // );
                        Ok(xdp_action::XDP_DROP)
                    }
                }

                IpProto::Udp => {
                    let header: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    // external port comming from outside
                    let port = u16::from_be(unsafe { (*header).source });
                    // someone reaching to internal port
                    let port_to = u16::from_be(unsafe { (*header).dest });
                    let connection = Connection {
                        state: 2,
                        src_ip,
                        dst_ip,
                        src_port: port,
                        dst_port: port_to,
                        protocol: 0x11,
                    };
                    let session = Session {
                        src_ip,
                        src_port: port,
                        protocol: 0x11,
                    };

                    if is_requested(&session) {
                        rate_add();
                        debug!(
                            &ctx,
                            "UDP ESTABLISHED on {:i}:{}", connection.src_ip, connection.src_port
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else if port == 53 && ip_addr_allowed(&src_ip) {
                        // DNS Reslover let her in
                        add_request(&session, &connection);
                        debug!(
                            &ctx,
                            "DNS! {:i}:{} <=== {:i}:{}", dst_ip, port_to, src_ip, port
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
                    } else if udp_port_allowed_out(&port_to) {
                        debug!(
                            &ctx,
                            "UDP OUT! {:i}:{} ===> {:i}:{}", src_ip, port, dst_ip, port_to
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else if udp_port_allowed_in(&port) {
                        if !rate_limit() {
                            rate_add();
                            add_request(&session, &connection);
                            debug!(
                                &ctx,
                                "UDP IN! {:i}:{} <=== {:i}:{}", dst_ip, port_to, src_ip, port,
                            );
                            return Ok(xdp_action::XDP_PASS);
                        } else {
                            debug!(
                                &ctx,
                                "RATE LIMITTED! {:i}:{} -x-> {:i}:{}",
                                src_ip,
                                port,
                                dst_ip,
                                port_to
                            );
                            return Ok(xdp_action::XDP_DROP);
                        }
                    } else {
                        debug!(
                            &ctx,
                            "UDP DROP! {:i}:{} -x-> {:i}:{}", src_ip, port, dst_ip, port_to
                        );
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
                _ => Ok(xdp_action::XDP_PASS),
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};

#[inline(always)]
unsafe fn ptr_mut<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_SHOT);
    }
    Ok((start + offset) as *mut T)
}

#[map(name = "NEW")]
static mut NEW: PerfEventArray<Connection> = PerfEventArray::with_max_entries(1024, 0);
#[map(name = "DEL")]
static mut DEL: PerfEventArray<Session> = PerfEventArray::with_max_entries(1024, 0);

#[classifier]
pub fn sfw_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(e) => e,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, i32> {
    let eth_hdr: *const EthHdr = unsafe { ptr_mut(&ctx, 0) }?;
    match unsafe { *eth_hdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_mut(&ctx, EthHdr::LEN)? };
            match unsafe { *ipv4hdr }.proto {
                IpProto::Icmp => handle_icmp_egress(ctx),
                IpProto::Tcp => handle_tcp_egress(ctx),
                IpProto::Udp => handle_udp_egress(ctx),
                _ => Ok(TC_ACT_PIPE),
            }
        }
        _ => Ok(TC_ACT_PIPE),
    }
}

pub fn handle_udp_egress(ctx: TcContext) -> Result<i32, i32> {
    // gather the TCP header
    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_mut(&ctx, EthHdr::LEN)? };
    // let size = unsafe { (*ip_hdr).tot_len };

    let udp_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let udp_hdr: *mut UdpHdr = unsafe { ptr_mut(&ctx, udp_header_offset)? };

    let src_ip = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let src_port = u16::from_be(unsafe { (*udp_hdr).source });
    let dst_ip = u32::from_be(unsafe { (*ip_hdr).dst_addr });
    let dst_port = u16::from_be(unsafe { (*udp_hdr).dest });
    let connection = Connection {
        state: 2,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: 0x11,
    };
    unsafe { NEW.output(&ctx, &connection, 0) };
    // Just forward our request outside!!
    Ok(TC_ACT_PIPE)
}
pub fn handle_tcp_egress(ctx: TcContext) -> Result<i32, i32> {
    // gather the TCP header
    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_mut(&ctx, EthHdr::LEN)? };
    // let size = unsafe { (*ip_hdr).tot_len };

    let tcp_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let tcp_hdr: *mut TcpHdr = unsafe { ptr_mut(&ctx, tcp_header_offset)? };

    let src_ip = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let src_port = u16::from_be(unsafe { (*tcp_hdr).source });
    let dst_ip = u32::from_be(unsafe { (*ip_hdr).dst_addr });
    let dst_port = u16::from_be(unsafe { (*tcp_hdr).dest });
    // The source identifier
    debug!(
        &ctx,
        "TCP request {:i}:{} -> {:i}:{}", src_ip, src_port, dst_ip, dst_port,
    );
    let connection = Connection {
        state: 2,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: 6,
    };
    let ses = Session {
        src_ip: dst_ip,
        src_port: dst_port,
        protocol: 6,
    };
    let tcp_hdr_ref = unsafe { tcp_hdr.as_ref().ok_or(TC_ACT_PIPE)? };
    if tcp_hdr_ref.rst() == 1 {
        let if_connected = unsafe { CONNECTIONS.get(&ses) };
        if if_connected.is_some() {
            debug!(&ctx, "Closing {:i}:{} on TCP", ses.src_ip, ses.src_port);
            unsafe { DEL.output(&ctx, &ses, 0) };
        }
    } else {
        unsafe { NEW.output(&ctx, &connection, 0) };
    }
    // Just forward our request outside!!
    Ok(TC_ACT_PIPE)
}

pub fn handle_icmp_egress(ctx: TcContext) -> Result<i32, i32> {
    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_mut(&ctx, EthHdr::LEN)? };

    let icmp_header_offset = EthHdr::LEN + Ipv4Hdr::LEN;

    let icmp_hdr: *mut IcmpHdr = unsafe { ptr_mut(&ctx, icmp_header_offset)? };
    let icmp_type: u8 = unsafe { (*icmp_hdr).type_ };

    let src_ip = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_ip = u32::from_be(unsafe { (*ip_hdr).dst_addr });

    info!(&ctx, "ICMP {} {:i} -> {:i} ", icmp_type, src_ip, dst_ip);

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
