use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    programs::TcContext,
};

use core::net::Ipv4Addr;
use network_types::{icmp::IcmpHdr, ip::IpProto, tcp::TcpHdr, udp::UdpHdr};
use simple_firewall_common::{Connection, TCPState};

use crate::{helper::*, CONNECTIONS, NEW, TEMPORT, UNKNOWN};

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
        _ = unsafe { TEMPORT.insert(&remote_port, &1, 0) };
        return Ok(TC_ACT_PIPE);
    }
    let connection = Connection::egress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
        0,
        0,
        0,
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
    let tcp_flag: u8 = tcp_hdr._bitfield_1.get(8, 6u8) as u8;
    // The source identifier
    let connection = Connection::egress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
        tcp_flag,
        u32::from_be(tcp_hdr.seq),
        u32::from_be(tcp_hdr.ack_seq),
    );
    let sums_key = connection.into_session();
    if let Ok(connection_state) = is_requested(&sums_key) {
        let transitioned = unsafe {
            process_tcp_state_transition(
                false,
                &mut (*connection_state),
                tcp_flag,
            )
        };
        unsafe { (*connection_state).last_tcp_flag = tcp_flag };
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
    } else if unsafe { UNKNOWN.get(&sums_key).is_some() } && 18u8.eq(&tcp_flag)
    {
        aya_log_ebpf::info!(
            &ctx,
            "Recieved syn ack from server on TCP with {:i}:{}",
            remote_addr.to_bits(),
            remote_port,
        );
        unsafe { NEW.output(&ctx, &connection, 0) };
        if unsafe { UNKNOWN.remove(&connection.remote_addr).is_ok() } {
            aya_log_ebpf::info!(&ctx, "removed from unkown",);
        }
        Ok(TC_ACT_SHOT)
    } else if (tcp_dport_out(remote_port) || tcp_sport_out(host_port))
        // filter syn for connect or push ack for rst only
        && (2u8.eq(&tcp_flag) || 24u8.eq(&tcp_flag))
    {
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
