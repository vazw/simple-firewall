use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_csum_diff, bpf_ktime_get_ns, bpf_tcp_raw_check_syncookie_ipv4,
        bpf_tcp_raw_gen_syncookie_ipv4, r#gen::{bpf_xdp_adjust_tail, bpf_xdp_get_buff_len},
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
// Doff = 4bit int represent how many 32Bit Word of TCP header length
// TOTAL TCP HEADER LENGTH = Doff * 4 min=20 max=60
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
// |        Options (if any Doff length)                    | // XDP PROGRAM
// +----------------------------+---------------------------+ // CAN NOT
// |                                                        | // ACCESS OPTIONS
// |                        Data...                         |
// |                                                        |
// +--------------------------------------------------------+
// # Verifier not happy with TCP header options
// https://github.com/gamemann/XDP-TCP-Header-Options?tab=readme-ov-file

pub fn handle_tcp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocol: IpProto,
) -> Result<u32, u32> {
    let ipv: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN) }?;
    // let total_length = u16::from_be(unsafe { (*ipv).tot_len }) as u32;
    let header: &TcpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET) }?;
    // get all flag at once by loading U|A|P|R|S|F in bits orders as u8le
    let tcp_flag: u8 = header._bitfield_1.get(8, 6u8) as u8;

    let remote_port = u16::from_be(header.source);
    // someone reaching to internal host_port
    let host_port = u16::from_be(header.dest);
    let connection = Connection::ingress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocol as u8,
        tcp_flag,
    );
    let sums_key = connection.into_session();
    let header_mut: *mut TcpHdr = unsafe { ptr_at_mut(&ctx, PROTOCAL_OFFSET)? };
    if let Some(connection_state) = CONNECTIONS.get_ptr_mut(&sums_key) {
        if unsafe { bpf_ktime_get_ns() - (*connection_state).last_syn_ack_time }
            > 10_000_000_000
        {
            _ = NEW.output(&connection, 0);
        }
        let transitioned = unsafe {
            process_tcp_state_transition(
                true,
                &mut (*connection_state),
                tcp_flag,
            )
        };
        unsafe { *connection_state }.last_tcp_flag = tcp_flag;
        if transitioned {
            if unsafe { *connection_state }.tcp_state.eq(&TCPState::Closed) {
                _ = CONNECTIONS.remove(&sums_key);
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
        } else if unsafe { *connection_state }.tcp_state.eq(&TCPState::Closed) {
            _ = CONNECTIONS.remove(&sums_key);
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
            // 0 if iph and th are a valid SYN cookie ACK.
            // On failure -EACCES if th_len is invalid.
            // (OS error: 13 permission denied)
            bpf_tcp_raw_check_syncookie_ipv4(
                ipv as *mut _,
                header_mut as *mut _,
            ) as i64
        };
        let cookie = (u32::from_be(header.ack_seq) - 1) as u32;

        info!(&ctx, "cookies {} check {}", cookie, check);

        if 0i64.eq(&check) {
            info!(
                &ctx,
                "Correct cookies on TCP from {:i}:{} creating connection",
                remote_addr.to_bits(),
                remote_port,
            );
            _ = NEW.output(&connection, 0);
            if CONNECTIONS
                .insert(&sums_key, &connection.into_state_listen(), 0)
                .is_ok()
            {
                info!(&ctx, "Added new con");
            }
            Ok(xdp_action::XDP_PASS)
        } else {
            info!(
                &ctx,
                "Incorect cookies on TCP from {:i}:{} DROP got {}",
                remote_addr.to_bits(),
                remote_port,
                check
            );
            Ok(xdp_action::XDP_DROP)
        }
    } else if (tcp_dport_in(host_port) || tcp_sport_in(remote_port))
        && 2u8.eq(&tcp_flag)
    {
        info!(
            &ctx,
            "TCP {:i}:{} <== {:i}:{} size {}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
            ctx.data_end() - ctx.data()
        );
        let ether_len = size_of::<EthHdr>();
        let current_xdp_len =
            unsafe { bpf_xdp_get_buff_len(ctx.ctx) } - (ether_len + Ipv4Hdr::LEN) as u64;
        let tcp_len = (header.doff() * 4) as u32;
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, 60i32 - current_xdp_len as i32) };
        if 0.ne(&ret) {
            info!(&ctx, "Cannot Adjust_Tail");
            return Err(xdp_action::XDP_ABORTED);
        }
        let start = ctx.data();
        let end = ctx.data_end();
        if start + ether_len + Ipv4Hdr::LEN + 60usize > end {
            info!(
                &ctx,
                "Packet too short for max TCP options after adjust_tail"
            );
            return Err(xdp_action::XDP_ABORTED);
        }
        // let ether = unsafe { ptr_at_mut::<EthHdr>(&ctx, 0)? };
        let ipv = unsafe { ptr_at_mut::<Ipv4Hdr>(&ctx, ether_len)? };
        let header = unsafe { ptr_at_mut::<TcpHdr>(&ctx, ether_len + Ipv4Hdr::LEN)? };
        let header_ref = unsafe { ptr_at::<TcpHdr>(&ctx, ether_len + Ipv4Hdr::LEN)? };
        let raw_cookie = unsafe {
            bpf_tcp_raw_gen_syncookie_ipv4(
                ipv as *mut _,
                header as *mut _,
                tcp_len, // (header.doff() * 4) as u32,
            )
        } as i64;
        // On failure, the returned value is one of the following:
        // -EINVAL if th_len is invalid. (OS error: 22)
        if raw_cookie < 0 {
            info!(&ctx, "raw_cookie {}", raw_cookie);
            return Err(xdp_action::XDP_ABORTED);
        };
        let cookie = unsafe { mem::transmute::<i64, CookieResult>(raw_cookie) };
        info!(
            &ctx,
            "cookie seq:{} mss:{}", cookie.seq, cookie.mss
        );
        let tcp_options_offset = ether_len + Ipv4Hdr::LEN + TcpHdr::LEN;
        let tcp_options = timestamp_cookie(&ctx, header_ref, tcp_options_offset);
        unsafe {
            let doff = make_tcp_options(
                &ctx,
                tcp_options_offset,
                tcp_options.tsecr,
                tcp_options.tsval,
                tcp_options.wscale,
                cookie.mss,
            );
            (*header).set_doff(5 + doff);
            let tcp_len = (*header).doff() * 4;
            if tcp_len > 60 {
                return Err(xdp_action::XDP_ABORTED);
            }

            let new_len = (size_of::<Ipv4Hdr>() as u16) + tcp_len;

            let ether = ptr_at_mut::<EthHdr>(&ctx, 0)?;
            let ipv = ptr_at_mut::<Ipv4Hdr>(&ctx, ether_len)?;
            let header = ptr_at_mut::<TcpHdr>(&ctx, ether_len + Ipv4Hdr::LEN)?;

            mem::swap(&mut (*ether).src_addr, &mut (*ether).dst_addr);
            mem::swap(&mut (*ipv).src_addr, &mut (*ipv).dst_addr);
            mem::swap(&mut (*header).source, &mut (*header).dest);
            (*ipv).set_total_len(new_len);
            (*ipv).ttl = DEFAULT_TTL.to_be();
            (*ipv).tos = 0;
            (*ipv).set_id(0);
            (*ipv).set_checksum(0);

            // set syn-ack
            (*header)._bitfield_1.set(8, 6, 18);
            if tcp_options.tsecr != 0 && (tcp_options.tsval & (1u32 << 5).to_be() != 0) {
                (*header).set_ece(1);
            }
            (*header).ack_seq = (u32::from_be((*header).seq) + 1).to_be();
            (*header).seq = cookie.seq.to_be();
            (*header).window = 65160u16.to_be();
            (*header).urg_ptr = 0;
            (*header).check = 0;

            let full_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                ipv as *mut u32,
                Ipv4Hdr::LEN as u32,
                0,
            ) as u64;
            (*ipv).check = csum_fold_helper(full_sum).to_le_bytes();

            if ctx.data() + ether_len + Ipv4Hdr::LEN + tcp_len as usize > ctx.data_end() {
                return Err(xdp_action::XDP_ABORTED);
            }
            let tcp_header_sum = bpf_csum_diff(
                mem::MaybeUninit::zeroed().assume_init(),
                0,
                (ctx.data() + ether_len + Ipv4Hdr::LEN) as *mut u32,
                tcp_len as u32,
                0,
            );
            if tcp_header_sum < 0 {
                info!(&ctx, "Error Checksum: {}", tcp_header_sum);
                return Err(xdp_action::XDP_ABORTED);
            }
            let tcp_sum = csum_ipv4_magic(
                (*ipv).src_addr().to_bits().to_be(),
                (*ipv).dst_addr().to_bits().to_be(),
                tcp_len.to_be(),
                6u8,
                tcp_header_sum as u64,
            );
            (*header).check = tcp_sum;

            let new_len = (EthHdr::LEN + Ipv4Hdr::LEN + tcp_len as usize) as i32;
            let new_data_end_target = ctx.data() as i32 + new_len; // Calculate target absolute end address
            let current_data_end_absolute = ctx.data_end() as i32; // Get current absolute end address

            let adjust_delta_2 = new_data_end_target - current_data_end_absolute;
            let ret = bpf_xdp_adjust_tail(ctx.ctx, adjust_delta_2);
            if 0.ne(&ret) {
                info!(&ctx, "Cannot Adjust_Tail (second)");
                return Err(xdp_action::XDP_ABORTED);
            }
        }
        info!(
            &ctx,
            "XDP::TX TCP host:{:i}:{} to remote:{:i}:{} cookies {}",
            connection.host_addr,
            connection.remote_addr,
            connection.remote_addr,
            connection.remote_port,
            cookie.seq,
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
    protocol: IpProto,
) -> Result<u32, u32> {
    let header: &UdpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET) }?;
    // external host_port comming from outside
    let remote_port = header.source();
    // Allow to acsess is_broadcast request
    if unsafe { TEMPORT.get(&remote_port) }.is_some() {
        _ = TEMPORT.remove(&remote_port);
        return Ok(xdp_action::XDP_PASS);
    }
    // someone reaching to internal host_port
    let host_port = header.dest();
    let connection = Connection::ingress(
        host_addr.to_bits(),
        host_port,
        remote_addr.to_bits(),
        remote_port,
        protocol as u8,
        0,
    );
    let sum_key = connection.into_session();
    if let Ok(connection_state) = is_requested(&sum_key) {
        let current_time = unsafe { bpf_ktime_get_ns() };
        if current_time - unsafe { *connection_state }.last_syn_ack_time
            > 10_000_000_000
        {
            unsafe { (*connection_state).last_syn_ack_time = current_time };
            _ = NEW.output(&connection, 0);
        }
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
        // Dont let anyone ping :D
        ICMP_ECHO_REQUEST => Ok(xdp_action::XDP_DROP),
        ICMP_DEST_UNREACH => Ok(xdp_action::XDP_PASS),
        ICMP_ECHO_REPLY => Ok(xdp_action::XDP_PASS),
        ICMP_TIME_EXCEEDED => Ok(xdp_action::XDP_PASS),
        _ => Ok(xdp_action::XDP_DROP),
    }
}

