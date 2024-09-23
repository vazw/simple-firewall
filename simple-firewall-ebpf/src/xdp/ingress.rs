use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_csum_diff, bpf_ktime_get_ns, bpf_tcp_raw_check_syncookie_ipv4,
        bpf_tcp_raw_gen_syncookie_ipv4,
    },
    programs::XdpContext,
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

use crate::{helper::*, CONNECTIONS, NEW, TEMPORT};

// TCP Struct
// Doff = 4bit int represent 32Bit Word
// +----------------------------+---------------------------+
// |    Source Port (16 bits)   |Destination Port (16 bits) |
// +----------------------------+---------------------------+
// |                Sequence Number (32 bits)               |
// +----------------------------+---------------------------+
// |            Acknowledgment Number (32 bits)             |
// +----------------------------+---------------------------+
// | Doff |Reserved |U|A|P|R|S|F|   Window Size             |
// |4bits |(6 bits) | (6 bits)  |         (16 bits)         |
// +----------------------------+---------------------------+
// |    Checksum (16 bits)      |  Urgent Pointer (16 bits) |
// +----------------------------+---------------------------+
// |        Options (if any Doff length)                    |
// +----------------------------+---------------------------+
// |                                                        |
// |                        Data...                         |
// |                                                        |
// +--------------------------------------------------------+
pub fn handle_tcp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
) -> Result<u32, u32> {
    let ipv: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    let total_length = unsafe { (*ipv).tot_len };
    let header: &TcpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET)? };
    // get all flag at once by loading U|A|P|R|S|F in bits orders as u8
    let tcp_flag: u8 = header._bitfield_1.get(8, 6u8) as u8;

    let remote_port = u16::from_be(header.source);
    // someone reaching to internal host_port
    let host_port = u16::from_be(header.dest);
    let connection = Connection::ingress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
        tcp_flag,
    );
    let sums_key = connection.into_session();
    let header_mut: *mut TcpHdr = unsafe { ptr_at_mut(&ctx, PROTOCAL_OFFSET)? };
    if let Some(connection_state) =
        unsafe { CONNECTIONS.get_ptr_mut(&sums_key) }
    {
        let current_time = unsafe { bpf_ktime_get_ns() };
        if (current_time - unsafe { (*connection_state).last_syn_ack_time })
            .gt(&1_000_000_000)
        {
            unsafe {
                NEW.output(&ctx, &connection, 0);
                (*connection_state).last_syn_ack_time = current_time;
            }
        }
        let transitioned = unsafe {
            process_tcp_state_transition(
                true,
                &mut (*connection_state),
                tcp_flag,
            )
        };
        unsafe { (*connection_state).last_tcp_flag = tcp_flag };
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
            _ = unsafe { CONNECTIONS.remove(&sums_key) };
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
    } else if 16u8.eq(&tcp_flag) {
        let check = unsafe {
            bpf_tcp_raw_check_syncookie_ipv4(
                ipv as *mut _,
                header_mut as *mut _,
            ) as u32
        };
        if check.eq(&0) {
            info!(
                &ctx,
                "Correct cookies on TCP from {:i}:{} creating connection",
                remote_addr.to_bits(),
                remote_port,
            );
            unsafe { NEW.output(&ctx, &connection, 0) };
            unsafe {
                if CONNECTIONS
                    .insert(&sums_key, &connection.into_state_listen(), 0)
                    .is_ok()
                {
                    info!(&ctx, "Added new con");
                }
            }
            Ok(xdp_action::XDP_PASS)
        } else {
            info!(
                &ctx,
                "Incorect cookies on TCP from {:i}:{} DROP",
                remote_addr.to_bits(),
                remote_port,
            );
            Ok(xdp_action::XDP_DROP)
        }
    } else if (tcp_dport_in(host_port) || tcp_sport_in(remote_port))
        && 2u8.eq(&tcp_flag)
    {
        info!(
            &ctx,
            "TCP {:i}:{} <== {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        let cookie = unsafe {
            bpf_tcp_raw_gen_syncookie_ipv4(
                ipv as *mut _,
                header_mut as *mut _,
                TcpHdr::LEN as u32,
            )
        } as u32;

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

            let new_flag: u32 = (*header_mut)._bitfield_1.get(8, 6u8) as u32;
            if let Some(check) = csum_diff(
                &(tcp_flag as u32).to_be(),
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
                csum_diff(&header.seq, &cookie, !((*header_mut).check as u32))
            {
                (*header_mut).check = csum_fold(check);
                (*header_mut).seq = cookie;
            }
            info!(
                &ctx,
                "XDP::TX TCP to {:i}:{} cookies {} tcp doff {} total {}",
                remote_addr.to_bits(),
                remote_port,
                cookie,
                header.doff() * 4,
                total_length
            );
        }
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
    if unsafe { TEMPORT.get(&remote_port).is_some() } {
        _ = unsafe { TEMPORT.remove(&remote_port) };
        return Ok(xdp_action::XDP_PASS);
    }
    // someone reaching to internal host_port
    let host_port = u16::from_be(header.dest);
    let connection = Connection::ingress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocal as u8,
        0,
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
