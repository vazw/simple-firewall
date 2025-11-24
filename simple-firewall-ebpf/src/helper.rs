use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::programs::TcContext;
use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_ktime_get_ns, programs::XdpContext,
};
use network_types::tcp::TcpHdr;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

use core::mem;
use simple_firewall_common::{ConnectionState, TCPState};

use crate::{
    CONNECTIONS, DNS_ADDR, TCP_IN_DPORT, TCP_IN_SPORT, TCP_OUT_DPORT,
    TCP_OUT_SPORT, UDP_IN_DPORT, UDP_IN_SPORT, UDP_OUT_DPORT, UDP_OUT_SPORT,
};

pub const PROTOCAL_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

// pub const PROTOCAL_OFFSET_VLAN: usize = EthVlanHdrQ::LEN + Ipv4Hdr::LEN;
pub const MAX_TCP_LEN: usize = 60; // 60 is max TCP header size
pub const TCPOPT_NOP: u8 = 1;
pub const TCPOPT_EOL: u8 = 0;
pub const TCPOPT_MSS: u8 = 2;
pub const TCPOPT_WINDOW: u8 = 3;
pub const TCPOPT_SACK_PERM: u8 = 4;
pub const TCPOPT_TIMESTAMP: u8 = 8;
pub const TS_OPT_WSCALE_MASK: u32 = 0xf;
pub const TS_OPT_SACK: u32 = 1 << 4;
pub const TS_OPT_ECN: u32 = 1 << 5;
pub const TSMASK: u32 = (1 << 6) - 1;
pub const TCP_MAX_WSCALE: u8 = 14;
pub const TCPOLEN_MSS: u8 = 4;
pub const TCPOLEN_WINDOW: u8 = 3;
pub const TCPOLEN_SACK_PERM: u8 = 2;
pub const TCPOLEN_TIMESTAMP: u8 = 10;
pub const DEFAULT_WSCALE: u8 = 7;
pub const DEFAULT_TTL: u8 = 64;
pub const ETH_P_8021Q: u16 = 0x8100; /* 802.1Q VLAN Extended Header  */
pub const ETH_P_8021AD: u16 = 0x88A8; /* 802.1ad Service VLAN		*/

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    let data = (start + offset) as *const T;
    let data_ = unsafe { data.as_ref().ok_or(xdp_action::XDP_PASS)? };
    Ok(data_)
}

#[inline(always)]
pub unsafe fn ptr_at_mut<T>(
    ctx: &XdpContext,
    offset: usize,
) -> Result<*mut T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(xdp_action::XDP_PASS);
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
pub unsafe fn tc_ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<&T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(TC_ACT_PIPE);
    }
    let data = (start + offset) as *const T;
    let data_ = unsafe { data.as_ref().ok_or(TC_ACT_PIPE)? };
    Ok(data_)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOptionsContext {
    pub tsval: u32,
    pub tsecr: u32,
    pub wscale: u8,
    pub sack_perm: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CookieResult {
    pub mss: u16,
    __pading: u16,
    pub seq: u32,
}
// urg ack psh rst syn fin
// U   A   P   R   S   F
// 32  16  8   4   2   1
// …with this combination we can get what we care:
// 1 = fin
// 2 = syn
// 4 = rst
// 16 = ack
// 17 fin ack
// 18 = syn ack
//
#[inline(always)]
pub unsafe fn process_tcp_state_transition(
    is_ingress: bool,
    connection_state: &mut ConnectionState,
    tcp_flag: u8,
) -> bool {
    // close on reset
    if 4u8.eq(&tcp_flag) && !connection_state.tcp_state.eq(&TCPState::Listen) {
        connection_state.tcp_state = TCPState::Closed;
        return true;
    }
    // Check for SYN-ACK flood
    if 2u8.eq(&tcp_flag) | 18u8.eq(&tcp_flag) {
        let current_time = unsafe { bpf_ktime_get_ns() };
        // 1 second in nanoseconds
        if current_time - connection_state.last_syn_ack_time > 1_000_000_000 {
            connection_state.syn_ack_count = 1;
            connection_state.last_syn_ack_time = current_time;
        } else {
            connection_state.syn_ack_count += 1;
            // Threshold
            if connection_state.syn_ack_count > 100 {
                connection_state.tcp_state = TCPState::Closed;
                return true;
            }
        }
    };

    match connection_state.tcp_state {
        TCPState::Closed => {
            if 2u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::SynSent;
                return true;
            }
        }
        TCPState::Listen => {
            if 2u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::SynReceived;
                return true;
            }
        }
        TCPState::SynReceived => {
            if is_ingress {
                if 16u8.eq(&tcp_flag) {
                    connection_state.tcp_state = TCPState::Established;
                    return true;
                } else if 4u8.eq(&tcp_flag) {
                    connection_state.tcp_state = TCPState::Listen;
                    return true;
                }
            }
        }
        TCPState::SynSent => {
            if 18u8.eq(&tcp_flag) && is_ingress {
                connection_state.tcp_state = TCPState::Established;
                return true;
            }
        }
        TCPState::Established => {
            if is_ingress {
                if 1u8.eq(&tcp_flag) {
                    connection_state.tcp_state = TCPState::FinWait1;
                    return true;
                }
                // GOT RESET FROM TIME TO TIME WITH THIS SHIT
                // else if 18u8.eq(&tcp_flag) {
                //     // THIS IS CUSTOM HANDLER INDICATED THAT THIS SOMETHIONG IS WORNG
                //     // AND FIREWALL SHOULD PROCESS THIS CONNECTION AGAIN WITH RESET
                //     connection_state.tcp_state = TCPState::Closed;
                //     return false;
                // }
            } else if 16u8.eq(&tcp_flag)
                && 1u8.eq(&connection_state.last_tcp_flag)
            {
                connection_state.tcp_state = TCPState::CloseWait;
                return true;
            }
        }
        TCPState::FinWait1 => {
            if 16u8.eq(&tcp_flag) && 17u8.eq(&connection_state.last_tcp_flag) {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
            if 16u8.eq(&tcp_flag) && 1u8.eq(&connection_state.last_tcp_flag) {
                connection_state.tcp_state = TCPState::Closing;
                return true;
            }
            if 16u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::FinWait2;
                return true;
            }
        }
        TCPState::FinWait2 => {
            if 16u8.eq(&tcp_flag) && 1u8.eq(&connection_state.last_tcp_flag) {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::Closing => {
            if 16u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::TimeWait | TCPState::LastAck => {
            if 16u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::Closed;
                return true;
            }
        }
        TCPState::CloseWait => {
            if !is_ingress && 1u8.eq(&tcp_flag) {
                connection_state.tcp_state = TCPState::LastAck;
                return true;
            }
        }
    }
    false
}

// #[inline(always)]
// pub unsafe fn agressive_tcp_rst(
//     hdr: &TcpHdr,
//     connection_state: &mut ConnectionState,
// ) -> TCPState {
//     let syn = hdr.syn() != 0;
//     let ack = hdr.ack() != 0;
//     let rst = hdr.rst() != 0;
//
//     match connection_state.tcp_state {
//         TCPState::Listen => {
//             if syn && !ack {
//                 connection_state.tcp_state = TCPState::SynReceived;
//                 TCPState::SynReceived
//             } else {
//                 TCPState::Closed
//             }
//         }
//         TCPState::SynReceived => {
//             if (ack && !syn) || rst {
//                 connection_state.tcp_state = TCPState::Established;
//                 TCPState::Established
//             } else {
//                 TCPState::SynReceived
//             }
//         }
//         _ => TCPState::Closed,
//     }
// }

// Session using remoteIP
#[inline(always)]
pub fn is_requested(session: &u32) -> Result<*mut ConnectionState, ()> {
    unsafe {
        if let Some(cons) = CONNECTIONS.get_ptr_mut(session) {
            if !(*cons).tcp_state.eq(&TCPState::Closed) {
                return Ok(cons);
            } else {
                return Err(());
            }
        }
        Err(())
    }
}

// pub const BPF_ANY = 0;
// pub const BPF_NOEXIST = 1;
// pub const BPF_EXIST = 2;

#[inline(always)]
pub fn add_request(session: &u32, connection_state: &ConnectionState) -> bool {
    CONNECTIONS.insert(session, connection_state, 0).is_ok()
}

#[inline(always)]
pub fn tcp_sport_in(port: u16) -> bool {
    unsafe { TCP_IN_SPORT.get(&port) }.is_some()
}
#[inline(always)]
pub fn tcp_dport_in(port: u16) -> bool {
    unsafe { TCP_IN_DPORT.get(&port) }.is_some()
}

#[inline(always)]
pub fn tcp_sport_out(port: u16) -> bool {
    unsafe { TCP_OUT_SPORT.get(&port) }.is_some()
}
#[inline(always)]
pub fn tcp_dport_out(port: u16) -> bool {
    unsafe { TCP_OUT_DPORT.get(&port) }.is_some()
}

#[inline(always)]
pub fn udp_sport_in(port: u16) -> bool {
    unsafe { UDP_IN_SPORT.get(&port) }.is_some()
}
#[inline(always)]
pub fn udp_dport_in(port: u16) -> bool {
    unsafe { UDP_IN_DPORT.get(&port) }.is_some()
}

#[inline(always)]
pub fn udp_sport_out(port: u16) -> bool {
    unsafe { UDP_OUT_SPORT.get(&port) }.is_some()
}

#[inline(always)]
pub fn udp_dport_out(port: u16) -> bool {
    unsafe { UDP_OUT_DPORT.get(&port) }.is_some()
}

#[inline(always)]
pub fn ip_addr_allowed(addrs: &u32) -> bool {
    unsafe { DNS_ADDR.get(addrs) }.is_some()
}

#[inline(always)]
pub fn csum_fold(mut csum: u32) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline(always)]
pub fn csum_fold_helper(mut sum: u64) -> u16 {
    sum = (sum & 0xffffffff) + (sum >> 32);
    sum = (sum & 0xffffffff) + (sum >> 32);
    csum_fold(sum as u32)
}

#[inline(always)]
pub fn csum_ipv4_magic(saddr: u32, daddr: u32, len: u16, proto: u8, csum: u64) -> u16 {
    let mut sum: u64 = csum;

    sum += saddr as u64;
    sum += daddr as u64;

    sum += (proto as u64) << 8;
    sum += len as u64;

    csum_fold_helper(sum)
}

#[inline(always)]
pub fn time_get_ms() -> u32 {
    (unsafe { bpf_ktime_get_ns() } / 1_000_000) as u32
}

#[inline(always)]
pub fn timestamp_cookie(ctx: &XdpContext, tcp_hdr: &TcpHdr, offset: usize) -> TcpOptionsContext {
    let mut options_off = offset;
    let mut context = TcpOptionsContext {
        tsval: time_get_ms() & !TSMASK,
        wscale: DEFAULT_WSCALE,
        ..Default::default()
    };
    for _ in 0..7 {
        let Ok(option_kind) = (unsafe { ptr_at::<u8>(ctx, options_off) }) else {
            break;
        };
        if *option_kind == TCPOPT_EOL {
            break;
        }
        if *option_kind == TCPOPT_NOP {
            options_off += 1;
            continue;
        }
        let Ok(option_len) = (unsafe { ptr_at::<u8>(ctx, options_off + 1) }) else {
            break;
        };
        if *option_len < 2 {
            break;
        };
        match *option_kind {
            TCPOPT_WINDOW => {
                if *option_len == TCPOLEN_WINDOW {
                    let Ok(wscale) = (unsafe { ptr_at::<u8>(ctx, options_off + 2) }) else {
                        break;
                    };
                    context.wscale = if TCP_MAX_WSCALE > wscale.to_le() {
                        *wscale
                    } else {
                        TCP_MAX_WSCALE
                    };
                }
            }
            TCPOPT_TIMESTAMP => {
                if *option_len == TCPOLEN_TIMESTAMP {
                    let Ok(tsecr) = (unsafe { ptr_at::<u32>(ctx, options_off + 2) }) else {
                        break;
                    };
                    context.tsecr = *tsecr;
                }
            }
            TCPOPT_SACK_PERM => {
                if *option_len == TCPOLEN_SACK_PERM {
                    context.sack_perm = true;
                }
            }
            _ => {}
        }
        options_off += *option_len as usize;
    }
    context.tsval |= (context.wscale as u32) & TS_OPT_WSCALE_MASK;
    if context.sack_perm {
        context.tsval |= TS_OPT_SACK;
    }
    if tcp_hdr.ece() != 0 && tcp_hdr.cwr() != 0 {
        context.tsval |= TS_OPT_ECN;
    }
    context.tsval = context.tsval.to_be();
    context
}

/// # Safety
/// need to grow buffer using bpf_adjust_tail() to length limit
#[inline(always)]
pub unsafe fn make_tcp_options(
    ctx: &XdpContext,
    start_offset: usize,
    tsecr: u32,
    tsval: u32,
    wscale: u8,
    mss: u16,
) -> u16 {
    let mut curent_offset = start_offset;
    let mut doff = 0;
    let Ok(data_ptr) = ptr_at_mut::<u32>(ctx, curent_offset) else {
        return doff;
    };

    *data_ptr = ((TCPOPT_MSS as u32) << 24 | ((TCPOLEN_MSS as u32) << 16) | (mss as u32)).to_be();
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    if tsecr == 0 {
        return doff;
    }

    let Ok(data_ptr) = ptr_at_mut::<u32>(ctx, curent_offset) else {
        return doff;
    };
    if (tsval & (1u32 << 4).to_be()) != 0 {
        *data_ptr = ((TCPOPT_SACK_PERM as u32) << 24
            | (TCPOLEN_SACK_PERM as u32) << 16
            | (TCPOPT_TIMESTAMP as u32) << 8
            | TCPOLEN_TIMESTAMP as u32)
            .to_be();
    } else {
        *data_ptr = ((TCPOPT_NOP as u32) << 24
            | (TCPOPT_NOP as u32) << 16
            | (TCPOPT_TIMESTAMP as u32) << 8
            | TCPOLEN_TIMESTAMP as u32)
            .to_be();
    }
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    let Ok(data_ptr) = ptr_at_mut::<u32>(ctx, curent_offset) else {
        return doff;
    };
    *data_ptr = tsval;
    curent_offset += mem::size_of::<u32>();
    doff += 1;
    let Ok(data_ptr) = ptr_at_mut::<u32>(ctx, curent_offset) else {
        return doff;
    };
    *data_ptr = tsecr;
    curent_offset += mem::size_of::<u32>();
    doff += 1;

    let Ok(data_ptr) = ptr_at_mut::<u32>(ctx, curent_offset) else {
        return doff;
    };
    if (tsval & 0xfu32.to_be()) != 0xfu32.to_be() {
        *data_ptr = ((TCPOPT_NOP as u32) << 24
            | (TCPOPT_WINDOW as u32) << 16
            | (TCPOLEN_WINDOW as u32) << 8
            | wscale as u32)
            .to_be();
        doff += 1;
    }
    doff
}
