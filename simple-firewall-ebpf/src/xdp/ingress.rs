use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_csum_diff, programs::XdpContext,
};
use aya_log_ebpf::info;

use core::{mem, net::Ipv4Addr};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use simple_firewall_common::{Connection, TCPState};

use crate::{helper::*, CONNECTIONS, TEMPORT, UNKNOWN};

pub fn handle_tcp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let ipv: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    let header: &TcpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    let tcp_flag: u32 = header._bitfield_1.get(8, 8u8) as u32;
    // let ip_len: u32 = (header.doff() as u32) << 2;

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
    // match CONBUF.reserve::<[u8; 16]>(0) {
    //     Some(mut event) => {
    //         unsafe {
    //             ptr::write_unaligned(event.as_mut_ptr() as *mut _, connection);
    //         }
    //         event.submit(0);
    //     }
    //     None => {
    //         info!(&ctx, "Connot reserve ringbuffer");
    //     }
    // };
    let sums_key = connection.into_session();
    let header_mut: *mut TcpHdr = unsafe { ptr_at_mut(&ctx, PROTOCAL_OFFSET)? };
    if let Some(connection_state) =
        unsafe { CONNECTIONS.get_ptr_mut(&sums_key) }
    {
        let transitioned = unsafe {
            process_tcp_state_transition(header, &mut (*connection_state))
        };
        if transitioned {
            if unsafe { (*connection_state).tcp_state.eq(&TCPState::Closed) } {
                _ = unsafe { CONNECTIONS.remove(&sums_key) };
                info!(
                    &ctx,
                    "Closing TCP to {:i}:{}",
                    remote_addr.to_bits(),
                    remote_port,
                );
                Ok(xdp_action::XDP_PASS)
            } else if unsafe {
                (*connection_state).tcp_state.eq(&TCPState::Listen)
            } {
                let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
                unsafe {
                    mem::swap(&mut (*ethdr).src_addr, &mut (*ethdr).dst_addr);
                    mem::swap(&mut (*ipv).src_addr, &mut (*ipv).dst_addr);
                    mem::swap(
                        &mut (*header_mut).source,
                        &mut (*header_mut).dest,
                    );
                    (*ipv).check = 0;
                    let full_sum = bpf_csum_diff(
                        mem::MaybeUninit::zeroed().assume_init(),
                        0,
                        ipv as *mut u32,
                        Ipv4Hdr::LEN as u32,
                        0,
                    ) as u64;
                    (*ipv).check = csum_fold_helper(full_sum);

                    if (*header_mut).ack() != 0 {
                        (*header_mut).set_ack(0);
                    }
                    if (*header_mut).syn() != 0 {
                        (*header_mut).set_syn(0);
                    }
                    if (*header_mut).psh() != 0 {
                        (*header_mut).set_psh(0);
                    }
                    if (*header_mut).fin() != 0 {
                        (*header_mut).set_fin(0);
                    }
                    if (*header_mut).rst() != 1 {
                        (*header_mut).set_rst(1);
                    }
                    if let Some(check) = csum_diff(
                        &header.ack_seq,
                        &0u32,
                        !((*header_mut).check as u32),
                    ) {
                        (*header_mut).check = csum_fold(check);
                        (*header_mut).ack_seq = 0;
                    }
                    if let Some(check) = csum_diff(
                        &header.seq,
                        &0u32,
                        !((*header_mut).check as u32),
                    ) {
                        (*header_mut).check = csum_fold(check);
                        (*header_mut).seq = 0;
                    }
                    let new_flag: u32 =
                        (*header_mut)._bitfield_1.get(8, 8u8) as u32;
                    if let Some(check) = csum_diff(
                        &tcp_flag.to_be(),
                        &new_flag.to_be(),
                        !((*header_mut).check as u32),
                    ) {
                        (*header_mut).check = csum_fold(check);
                    }
                };
                info!(
                    &ctx,
                    "XDP::TX TCP Incorrect state to {:i}:{}",
                    remote_addr.to_bits(),
                    remote_port,
                );
                Ok(xdp_action::XDP_TX)
            } else {
                info!(
                    &ctx,
                    "Pass Connection TCP to {:i}:{}",
                    remote_addr.to_bits(),
                    remote_port,
                );
                Ok(xdp_action::XDP_PASS)
            }
        // Not transitioned
        } else if unsafe { (*connection_state).tcp_state.eq(&TCPState::Closed) }
        {
            info!(
                &ctx,
                "Drop Closed TCP to {:i}:{}",
                remote_addr.to_bits(),
                remote_port,
            );
            Ok(xdp_action::XDP_DROP)
        } else {
            info!(
                &ctx,
                "Pass unchanged TCP to {:i}:{}",
                remote_addr.to_bits(),
                remote_port,
            );
            Ok(xdp_action::XDP_PASS)
        }
    } else if let Some(connection_state) =
        // new connections
        // will be handle here with agressive tcp rst on first try
        unsafe { UNKNOWN.get_ptr_mut(&connection.remote_addr) }
    {
        info!(
            &ctx,
            "UNKNOWN on TCP from {:i}:{}",
            remote_addr.to_bits(),
            remote_port,
        );
        let transitioned =
            unsafe { agressive_tcp_rst(header, &mut (*connection_state)) };
        if transitioned.eq(&TCPState::Established) {
            info!(&ctx, "Established",);
            unsafe {
                if (*header_mut).ack() != 0 {
                    (*header_mut).set_ack(0);
                }
                if (*header_mut).syn() != 0 {
                    (*header_mut).set_syn(0);
                }
                if (*header_mut).rst() != 1 {
                    (*header_mut).set_rst(1);
                }
                if CONNECTIONS
                    .insert(&sums_key, &connection.into_state_listen(), 0)
                    .is_ok()
                {
                    info!(&ctx, "Added new con",);
                }
                if UNKNOWN.remove(&connection.remote_addr).is_ok() {
                    info!(&ctx, "removed from unkown",);
                }
            };
        } else if transitioned.eq(&TCPState::SynReceived) {
            info!(&ctx, "SynReceived",);
            unsafe {
                if (*header_mut).ack() != 1 {
                    (*header_mut).set_ack(1);
                }
                if (*header_mut).syn() != 1 {
                    (*header_mut).set_syn(1);
                }
            };
        }
        let ethdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
        unsafe {
            mem::swap(&mut (*ethdr).src_addr, &mut (*ethdr).dst_addr);
            mem::swap(&mut (*ipv).src_addr, &mut (*ipv).dst_addr);
            mem::swap(&mut (*header_mut).source, &mut (*header_mut).dest);
            (*ipv).check = 0;
            let full_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                ipv as *mut u32,
                Ipv4Hdr::LEN as u32,
                0,
            ) as u64;
            (*ipv).check = csum_fold_helper(full_sum);

            let new_flag: u32 = (*header_mut)._bitfield_1.get(8, 8u8) as u32;
            if let Some(check) = csum_diff(
                &tcp_flag.to_be(),
                &new_flag.to_be(),
                !((*header_mut).check as u32),
            ) {
                (*header_mut).check = csum_fold(check);
            }
            if let Some(check) = csum_diff(
                &header.ack_seq,
                &(u32::from_be((*header_mut).seq) + 1).to_be(),
                !((*header_mut).check as u32),
            ) {
                (*header_mut).check = csum_fold(check);
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
            }
            if let Some(check) =
                csum_diff(&header.seq, &0u32, !((*header_mut).check as u32))
            {
                (*header_mut).check = csum_fold(check);
                (*header_mut).seq = 0;
            }
        }
        Ok(xdp_action::XDP_TX)
    } else if (tcp_dport_in(host_port) || tcp_sport_in(remote_port))
        && header.syn() != 0
        && header.ack() == 0
    {
        info!(
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
        unsafe {
            mem::swap(&mut (*ethdr).src_addr, &mut (*ethdr).dst_addr);
            mem::swap(&mut (*ipv).src_addr, &mut (*ipv).dst_addr);
            mem::swap(&mut (*header_mut).source, &mut (*header_mut).dest);
            (*ipv).check = 0;
            let full_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                ipv as *mut u32,
                Ipv4Hdr::LEN as u32,
                0,
            ) as u64;
            (*ipv).check = csum_fold_helper(full_sum);

            if (*header_mut).ack() == 0 {
                (*header_mut).set_ack(1);
            }
            if (*header_mut).syn() == 0 {
                (*header_mut).set_syn(1);
            }

            let new_flag: u32 = (*header_mut)._bitfield_1.get(8, 8u8) as u32;
            if let Some(check) = csum_diff(
                &tcp_flag.to_be(),
                &new_flag.to_be(),
                !((*header_mut).check as u32),
            ) {
                (*header_mut).check = csum_fold(check);
            }

            if let Some(check) = csum_diff(
                &header.ack_seq,
                &(u32::from_be((*header_mut).seq) + 1).to_be(),
                !((*header_mut).check as u32),
            ) {
                (*header_mut).check = csum_fold(check);
                (*header_mut).ack_seq =
                    (u32::from_be((*header_mut).seq) + 1).to_be();
            }
            if let Some(check) =
                csum_diff(&header.seq, &0, !((*header_mut).check as u32))
            {
                (*header_mut).check = csum_fold(check);
                (*header_mut).seq = 0;
            }
        }
        info!(
            &ctx,
            "XDP::TX TCP to {:i}:{}",
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(xdp_action::XDP_TX)
    } else {
        aya_log_ebpf::info!(
            &ctx,
            "TCP DROP! {:i}:{} -x- {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        Ok(xdp_action::XDP_DROP)
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
