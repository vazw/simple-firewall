use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::programs::TcContext;
use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_ktime_get_ns, programs::XdpContext,
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

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
// use simple_firewall_common::{Connection, ConnectionState, TCPState};
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
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

// Max header length
const MAX_CSUM_WORDS: usize = 375;
#[inline(always)]
pub fn l4_csum_helper(ctx: &XdpContext) -> u64 {
    let mut s: u64 = 0;
    let offset = PROTOCAL_OFFSET;
    // start at tcp header
    let data = ctx.data() + offset;
    // end at last tcp options
    let data_end = ctx.data_end();
    // let data_end = data + 60;
    for i in 0..MAX_CSUM_WORDS {
        if data + 4 * i + 4 > data_end {
            if let Ok(word) =
                unsafe { bpf_probe_read_kernel((data + 4 * i) as *const u16) }
            {
                s += word as u64;
            } else if let Ok(word) =
                unsafe { bpf_probe_read_kernel((data + 4 * i) as *const u8) }
            {
                s += word as u64;
            }
            if let Ok(word) = unsafe {
                bpf_probe_read_kernel((data + 4 * i + 2) as *const u8)
            } {
                s += word as u64;
            }
            break;
        }
        // READ 4 Bytes at a time.
        if let Ok(word) =
            unsafe { bpf_probe_read_kernel((data + 4 * i) as *const u32) }
        {
            s += word as u64;
        }
    }
    s
}

#[inline(always)]
pub unsafe fn process_tcp_state_transition(
    hdr: &TcpHdr,
    connection_state: &mut ConnectionState,
) -> bool {
    let syn = hdr.syn() != 0;
    let ack = hdr.ack() != 0;
    let fin = hdr.fin() != 0;
    let rst = hdr.rst() != 0;
    // let psh = hdr.psh() != 0;

    if rst {
        connection_state.tcp_state = TCPState::Closed;
        return true;
    }
    // Check for SYN-ACK flood
    if syn | (syn && ack) {
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
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynSent;
                return true;
            }
        }
        TCPState::Listen => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynReceived;
                return true;
            }
        }
        TCPState::SynReceived => {
            if ack && !syn {
                connection_state.tcp_state = TCPState::Established;
                return true;
            }
        }
        TCPState::SynSent => {
            if syn && ack {
                connection_state.tcp_state = TCPState::Established;
                return true;
            }
        }
        TCPState::Established => {
            if fin {
                connection_state.tcp_state = TCPState::FinWait1;
                return true;
            } else if syn && ack {
                // THIS IS CUSTOM HANDLER INDICATED THAT THIS SOMETHIONG IS WORNG
                // AND FIREWALL SHOULD PROCESS THIS CONNECTION AGAIN WITH RESET
                connection_state.tcp_state = TCPState::Listen;
                return true;
            }
        }
        TCPState::FinWait1 => {
            if fin && ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
            if fin {
                connection_state.tcp_state = TCPState::Closing;
                return true;
            }
            if ack {
                connection_state.tcp_state = TCPState::FinWait2;
                return true;
            }
        }
        TCPState::FinWait2 => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::Closing => {
            if ack {
                connection_state.tcp_state = TCPState::TimeWait;
                return true;
            }
        }
        TCPState::TimeWait => {
            if ack {
                connection_state.tcp_state = TCPState::Closed;
                return true;
            }
        }
        _ => {}
    }
    false
}

#[inline(always)]
pub unsafe fn agressive_tcp_rst(
    hdr: &TcpHdr,
    connection_state: &mut ConnectionState,
) -> TCPState {
    let syn = hdr.syn() != 0;
    let ack = hdr.ack() != 0;
    let rst = hdr.rst() != 0;

    match connection_state.tcp_state {
        TCPState::Listen => {
            if syn && !ack {
                connection_state.tcp_state = TCPState::SynReceived;
                TCPState::SynReceived
            } else {
                TCPState::Closed
            }
        }
        TCPState::SynReceived => {
            if (ack && !syn) || rst {
                connection_state.tcp_state = TCPState::Established;
                TCPState::Established
            } else {
                TCPState::SynReceived
            }
        }
        _ => TCPState::Closed,
    }
}

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
    unsafe { CONNECTIONS.insert(session, connection_state, 0).is_ok() }
}

#[inline(always)]
pub fn tcp_sport_in(port: u16) -> bool {
    unsafe { TCP_IN_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
pub fn tcp_dport_in(port: u16) -> bool {
    unsafe { TCP_IN_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
pub fn tcp_sport_out(port: u16) -> bool {
    unsafe { TCP_OUT_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
pub fn tcp_dport_out(port: u16) -> bool {
    unsafe { TCP_OUT_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
pub fn udp_sport_in(port: u16) -> bool {
    unsafe { UDP_IN_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}
#[inline(always)]
pub fn udp_dport_in(port: u16) -> bool {
    unsafe { UDP_IN_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
pub fn udp_sport_out(port: u16) -> bool {
    unsafe { UDP_OUT_SPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
pub fn udp_dport_out(port: u16) -> bool {
    unsafe { UDP_OUT_DPORT.get(port as u32).is_some_and(|x| x.eq(&1_u8)) }
}

#[inline(always)]
pub fn ip_addr_allowed(addrs: &u32) -> bool {
    unsafe { DNS_ADDR.get(addrs).is_some() }
}
