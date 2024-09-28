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
use simple_firewall_common::{Connection, SynCookie, TCPState};

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
//
pub fn handle_tcp_xdp(
    ctx: XdpContext,
    host_addr: Ipv4Addr,
    remote_addr: Ipv4Addr,
    protocal: IpProto,
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
        protocal as u8,
        tcp_flag,
    );
    let sums_key = connection.into_session();
    let header_mut: *mut TcpHdr = unsafe { ptr_at_mut(&ctx, PROTOCAL_OFFSET)? };
    if let Some(connection_state) = CONNECTIONS.get_ptr_mut(&sums_key) {
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
        let cookie = if check != -13 {
            check
        } else {
            ((u32::from_be(header.ack_seq) - 1) as u32
                - connection.into_session() as u32) as i64
        };

        info!(&ctx, "cookies {} check {}", cookie, check);

        if 0i64.eq(&cookie) {
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
            "TCP {:i}:{} <== {:i}:{}",
            host_addr.to_bits(),
            host_port,
            remote_addr.to_bits(),
            remote_port,
        );
        // let pk_len = (ctx.data_end() - ctx.data() - PROTOCAL_OFFSET) as u32;
        // let thl = (header.doff() * 4) as u32;
        // let cookie = if pk_len < thl {
        //     let diff = thl - pk_len;
        //     unsafe { bpf_xdp_adjust_tail(ctx.ctx, diff as i32) };
        //     unsafe {
        //         bpf_tcp_raw_gen_syncookie_ipv4(
        //             ipv as *mut _,
        //             header_mut as *mut _,
        //             thl,
        //         ) as u32
        //     }
        // } else {
        // };

        //Create cookie before changing header
        let raw_cookie = unsafe {
            bpf_tcp_raw_gen_syncookie_ipv4(
                ipv as *mut _,
                header_mut as *mut _,
                (header.doff() * 4) as u32,
            )
        } as i64;
        // On failure, the returned value is one of the following:
        // -EINVAL if th_len is invalid. (OS error: 22)
        let cookie = if raw_cookie != -22 {
            unsafe { mem::transmute::<i64, SynCookie>(raw_cookie) }
        } else {
            SynCookie::new(connection.into_session(), 1460)
        };
        info!(
            &ctx,
            "gen cookie got {} -> {}::{}", raw_cookie, cookie.seq, cookie.mss
        );
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

            info!(&ctx, "Cookie seq: {}, mss {}", cookie.seq, cookie.mss);
            if header.doff() > 5 {
                //recalc the checksum
                let mut option_offset =
                    EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
                for _ in 0..100 {
                    if option_offset as u16 >= { *ipv }.tot_len {
                        break;
                    }
                    if ptr_at_mut::<*mut u8>(&ctx, option_offset).is_err() {
                        break;
                    }
                    let option_type_pointer: *mut u8 =
                        ptr_at_mut(&ctx, option_offset)?;
                    let option_type = u8::from_be(*option_type_pointer);
                    if option_type == 0 {
                        break;
                    }
                    if option_type == 1 {
                        option_offset += 1;
                        continue;
                    }
                    if ptr_at_mut::<*mut u8>(&ctx, option_offset + 1).is_err() {
                        break;
                    }
                    let option_len_pointer: *mut u8 =
                        ptr_at_mut(&ctx, option_offset + 1)?;
                    let option_len = u8::from_be(*option_len_pointer);
                    info!(&ctx, "{} {}", option_type, option_len);
                    if option_type == 2 {
                        let mss: *mut u16 =
                            ptr_at_mut(&ctx, option_offset + 2usize)?;
                        if let Some(check) = csum_diff(
                            &(*mss),
                            &cookie.mss.to_be(),
                            !((*header_mut).check as u32),
                        ) {
                            (*header_mut).check = csum_fold(check);
                            *mss = cookie.mss.to_be();
                        }
                    }
                    if option_type != 8 {
                        option_offset += option_len as usize;
                        continue;
                    }

                    let option_data_timestamp_pointer: *mut u32 =
                        ptr_at_mut(&ctx, option_offset + 2_usize)?;

                    let option_data_timestamp_echo_pointer: *mut u32 =
                        ptr_at_mut(&ctx, option_offset + 6_usize)?;

                    if let Some(check) = csum_diff(
                        &(*option_data_timestamp_echo_pointer),
                        &(*option_data_timestamp_pointer),
                        !((*header_mut).check as u32),
                    ) {
                        (*header_mut).check = csum_fold(check);
                        *option_data_timestamp_echo_pointer =
                            *option_data_timestamp_pointer;
                    }

                    let tsval = (bpf_ktime_get_ns() >> 16) as u32;
                    if let Some(check) = csum_diff(
                        &(*option_data_timestamp_echo_pointer),
                        &tsval.to_be(),
                        !((*header_mut).check as u32),
                    ) {
                        (*header_mut).check = csum_fold(check);
                        (*option_data_timestamp_pointer) = tsval.to_be();
                    }

                    option_offset += option_len as usize;
                    break;
                }
            }
            if let Some(check) = csum_diff(
                &header.seq,
                &cookie.seq.to_be(),
                !((*header_mut).check as u32),
            ) {
                (*header_mut).check = csum_fold(check);
                (*header_mut).seq = cookie.seq.to_be();
            }
            info!(
                &ctx,
                "XDP::TX TCP to {:i}:{} cookies {}",
                remote_addr.to_bits(),
                remote_port,
                cookie.seq,
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
    let header: &UdpHdr = unsafe { ptr_at(&ctx, PROTOCAL_OFFSET) }?;
    // external host_port comming from outside
    let remote_port = u16::from_be(header.source);
    // Allow to acsess is_broadcast request
    if unsafe { TEMPORT.get(&remote_port) }.is_some() {
        _ = TEMPORT.remove(&remote_port);
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
        // Dont let anyone ping :D
        ICMP_ECHO_REQUEST => Ok(xdp_action::XDP_DROP),
        ICMP_DEST_UNREACH => Ok(xdp_action::XDP_PASS),
        ICMP_ECHO_REPLY => Ok(xdp_action::XDP_PASS),
        ICMP_TIME_EXCEEDED => Ok(xdp_action::XDP_PASS),
        _ => Ok(xdp_action::XDP_DROP),
    }
}
