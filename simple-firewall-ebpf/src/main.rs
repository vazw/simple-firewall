#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::bpf_map_lookup_percpu_elem,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
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
        rate.ge(&all_rate)
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
pub fn simple_firewall(ctx: XdpContext) -> u32 {
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
                    if tcp_port_allowed_in(&port) || tcp_port_allowed_out(&port_to) {
                        debug!(
                            &ctx,
                            "TCP {:i}:{} >> {:i}:{}", ip_addr, port, ip_addr_to, port_to,
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else {
                        info!(
                            &ctx,
                            "TCP_DROP! {:i}:{} -x- {:i}:{}", ip_addr, port, ip_addr_to, port_to,
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
                    if port == 53 && ip_addr_allowed(&ip_addr) {
                        // DNS Reslover let her in
                        debug!(
                            &ctx,
                            "DNS! {:i}:{} >> {:i}:{}", ip_addr, port, ip_addr_to, port_to,
                        );
                        Ok(xdp_action::XDP_PASS)
                    } else if udp_port_allowed_in(&port) || udp_port_allowed_out(&port_to) {
                        if !rate_limit() {
                            rate_add();
                            debug!(
                                &ctx,
                                "allowed UDP! {:i}:{} >> {:i}:{}",
                                ip_addr,
                                port,
                                ip_addr_to,
                                port_to,
                            );
                            return Ok(xdp_action::XDP_PASS);
                        } else {
                            info!(
                                &ctx,
                                "RATE LIMITTED! {:i}:{} -x- {:i}:{}",
                                ip_addr,
                                port,
                                ip_addr_to,
                                port_to
                            );
                            return Ok(xdp_action::XDP_DROP);
                        }
                    } else {
                        info!(
                            &ctx,
                            "UDP_DROP! {:i}:{} -x- {:i}:{}", ip_addr, port, ip_addr_to, port_to
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
