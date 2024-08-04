use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_csum_diff, programs::XdpContext,
};

use core::{mem, net::Ipv4Addr};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, TCPState};

use crate::{helper::*, CONNECTIONS, DEL, NEW, TEMPORT, UNKNOWN};

pub fn handle_tcp_xdp(
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
        let ip_len: u32 = (header.doff() as u32) << 2;
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
        if let Some(connection_state) =
            unsafe { CONNECTIONS.get_ptr_mut(&sums_key) }
        {
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
                        // (*header_mut).check += 12u16.to_be();
                        let mut l4_csum: u64 = 0;
                        let pseudo_header = [
                            (connection.host_addr.to_be() >> 16),
                            (connection.host_addr.to_be() & 0xFFFF),
                            (connection.remote_addr.to_be() >> 16),
                            (connection.remote_addr.to_be() & 0xFFFF),
                            6u32.to_be(), // Protocol (TCP) in the correct position
                            ip_len.to_be(), // TCP length in network byte order
                        ];
                        // Calculate checksum for pseudo-header
                        l4_csum += bpf_csum_diff(
                            mem::MaybeUninit::zeroed().assume_init(),
                            0,
                            pseudo_header.as_ptr() as *mut u32,
                            pseudo_header.len() as u32 * 4,
                            0,
                        ) as u64;
                        (*header_mut).check = 0;
                        l4_csum += l4_csum_helper(&ctx);
                        (*header_mut).check = csum_fold_helper(l4_csum);
                    };
                    Ok(xdp_action::XDP_TX)
                } else {
                    Ok(xdp_action::XDP_DROP)
                }
            }
        } else if let Some(connection_state) =
            // new connections
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
            let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
            let src_mac = unsafe { (*ethdr).src_addr };
            let dst_mac = unsafe { (*ethdr).dst_addr };
            unsafe {
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
                let mut l4_csum: u64 = 0;
                let pseudo_header = [
                    (connection.host_addr.to_be() >> 16),
                    (connection.host_addr.to_be() & 0xFFFF),
                    (connection.remote_addr.to_be() >> 16),
                    (connection.remote_addr.to_be() & 0xFFFF),
                    6u32.to_be(), // Protocol (TCP) in the correct position
                    ip_len.to_be(), // TCP length in network byte order
                ];
                // Calculate checksum for pseudo-header
                l4_csum += bpf_csum_diff(
                    mem::MaybeUninit::zeroed().assume_init(),
                    0,
                    pseudo_header.as_ptr() as *mut u32,
                    pseudo_header.len() as u32 * 4,
                    0,
                ) as u64;
                (*header_mut).dest = connection.remote_port.to_be();
                (*header_mut).source = connection.host_port.to_be();
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
                (*header_mut).seq = 0;
                let ex = (*header_mut).check;
                (*header_mut).check = 0;
                l4_csum += l4_csum_helper(&ctx);
                (*header_mut).check = csum_fold_helper(l4_csum);
                aya_log_ebpf::info!(
                    &ctx,
                    "Check sum expect: {} Got: {} Diff: {}:{} total: {}",
                    ex,
                    (*header_mut).check,
                    ex as i32 - (*header_mut).check as i32,
                    ex - (*header_mut).check,
                    (*ipv).tot_len.to_be()
                );
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

                let mut l4_csum: u64 = 0;
                let pseudo_header = [
                    (connection.host_addr.to_be() >> 16),
                    (connection.host_addr.to_be() & 0xFFFF),
                    (connection.remote_addr.to_be() >> 16),
                    (connection.remote_addr.to_be() & 0xFFFF),
                    6u32.to_be(), // Protocol (TCP) in the correct position
                    ip_len.to_be(), // TCP length in network byte order
                ];
                // Calculate checksum for pseudo-header
                l4_csum += bpf_csum_diff(
                    mem::MaybeUninit::zeroed().assume_init(),
                    0,
                    pseudo_header.as_ptr() as *mut u32,
                    pseudo_header.len() as u32 * 4,
                    0,
                ) as u64;
                (*header_mut).set_ack(1);
                (*header_mut).set_syn(1);
                (*header_mut).dest = connection.remote_port.to_be();
                (*header_mut).source = connection.host_port.to_be();
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
                (*header_mut).seq = 0;
                let ex = (*header_mut).check - 17u16.to_be();
                (*header_mut).check = 0;
                l4_csum += l4_csum_helper(&ctx);
                (*header_mut).check = csum_fold_helper(l4_csum);
                aya_log_ebpf::info!(
                    &ctx,
                    "Check sum expect: {} Got: {} Diff: {}:{}",
                    ex,
                    (*header_mut).check,
                    ex as i32 - (*header_mut).check as i32,
                    ex - (*header_mut).check,
                );
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

pub fn handle_udp_xdp(
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

pub fn handle_icmp_xdp(
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