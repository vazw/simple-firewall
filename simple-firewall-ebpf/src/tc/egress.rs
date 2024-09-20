use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    programs::TcContext,
};

use core::net::Ipv4Addr;
use network_types::{icmp::IcmpHdr, ip::IpProto, tcp::TcpHdr, udp::UdpHdr};
use simple_firewall_common::{Connection, TCPState};

use crate::{helper::*, CONNECTIONS, TEMPORT};

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
            _ = unsafe { CONNECTIONS.remove(&sums_key) };
            aya_log_ebpf::info!(
                &ctx,
                "EGRESS Closing TCP to {:i}:{}",
                remote_addr.to_bits(),
                remote_port,
            );
        }
        aya_log_ebpf::info!(
            &ctx,
            "ESTABLISHED on TCP with {:i}:{}",
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(TC_ACT_PIPE)
    } else if tcp_dport_out(remote_port) || tcp_sport_out(host_port) {
        add_request(&sums_key, &connection.into_state_sent());
        aya_log_ebpf::info!(
            &ctx,
            "TCP Bind {:i}:{} -> {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(TC_ACT_PIPE)
    } else {
        aya_log_ebpf::info!(
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
