#![no_std]
#![no_main]

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
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, Session};

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
static mut CONNECTIONS: HashMap<Session, Connection> = HashMap::with_max_entries(2048, 0);

const CPUS: u32 = 12;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
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

#[xdp]
pub fn sfw(ctx: XdpContext) -> u32 {
    match try_simple_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_simple_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let ip_addr = u32::from_be(unsafe { (*ipv).src_addr });
            let ip_addr_to = u32::from_be(unsafe { (*ipv).dst_addr });
            match unsafe { (*ipv).proto } {
                IpProto::Tcp => {
                    let header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    // external port comming from outside
                    let port = u16::from_be(unsafe { (*header).source });
                    // someone reaching to internal port
                    let port_to = u16::from_be(unsafe { (*header).dest });
                    let connection = Connection {
                        state: 2,
                        src_ip: ip_addr,
                        dst_ip: ip_addr_to,
                        src_port: port,
                        dst_port: port_to,
                        protocol: 6,
                    };
                    let session = Session {
                        src_ip: ip_addr,
                        src_port: port,
                        protocol: 6,
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
                            "TCP {:i}:{} ===> {:i}:{}", ip_addr, port, ip_addr_to, port_to
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else {
                        debug!(
                            &ctx,
                            "TCP_DROP! {:i}:{} -x-> {:i}:{}", ip_addr, port, ip_addr_to, port_to,
                        );
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
                        src_ip: ip_addr,
                        dst_ip: ip_addr_to,
                        src_port: port,
                        dst_port: port_to,
                        protocol: 0x11,
                    };
                    let session = Session {
                        src_ip: ip_addr,
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
                    } else if port == 53 && ip_addr_allowed(&ip_addr) {
                        // DNS Reslover let her in
                        add_request(&session, &connection);
                        debug!(
                            &ctx,
                            "DNS! {:i}:{} <=== {:i}:{}", ip_addr_to, port_to, ip_addr, port
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
                            "UDP OUT! {:i}:{} ===> {:i}:{}", ip_addr, port, ip_addr_to, port_to
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else if udp_port_allowed_in(&port) {
                        if !rate_limit() {
                            rate_add();
                            add_request(&session, &connection);
                            debug!(
                                &ctx,
                                "UDP IN! {:i}:{} <=== {:i}:{}", ip_addr_to, port_to, ip_addr, port,
                            );
                            return Ok(xdp_action::XDP_PASS);
                        } else {
                            debug!(
                                &ctx,
                                "RATE LIMITTED! {:i}:{} -x-> {:i}:{}",
                                ip_addr,
                                port,
                                ip_addr_to,
                                port_to
                            );
                            return Ok(xdp_action::XDP_DROP);
                        }
                    } else {
                        debug!(
                            &ctx,
                            "UDP DROP! {:i}:{} -x-> {:i}:{}", ip_addr, port, ip_addr_to, port_to
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
mod binding;

use crate::binding::{sock, sock_common};

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map(name = "NEW")]
static mut NEW: PerfEventArray<Connection> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        _ => 1u32,
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = unsafe { bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)? };
    match sk_common.skc_family {
        AF_INET => {
            // match unsafe {(*sock).sk_type} {
            //
            // }
            let src_ip =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let src_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dst_ip: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let dst_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            // let type_ = unsafe { sk_common.__bindgen_anon_4.skc_bind_node };
            let connection = Connection {
                state: 2,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: 6,
            };
            debug!(
                &ctx,
                "AF_INET {:i}:{} -> {:i}:{}",
                src_ip,
                src_port,
                dst_ip,
                dst_port //, type_
            );
            unsafe { NEW.output(&ctx, &connection, 0) };
            Ok(0)
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            debug!(
                &ctx,
                "AF_INET6 {:i} -> {:i}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
