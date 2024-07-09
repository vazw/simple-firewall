#![no_std]
use core::mem;
use core::ptr;

#[derive(Clone, Copy, Debug)]
pub struct Connection {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocal: u8,
    _padding: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionState {
    pub last_syn_ack_time: u64,
    pub syn_ack_count: u32,
    pub remote_ip: u32,
    pub protocal: u8,
    pub remote_port: u16,
    pub tcp_state: TCPState,
    _padding_: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionState {}

impl ConnectionState {
    pub fn to_backlist_key(&self) -> Session {
        Session {
            src_ip: self.remote_ip,
            src_port: self.remote_port,
            protocal: self.protocal,
            _padding: self._padding_,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpPacket {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IcmpPacket {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub src_ip: u32,
    pub src_port: u16,
    pub protocal: u8,
    _padding: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Session {}

impl Session {
    #[inline(always)]
    pub fn to_u64(&self) -> u64 {
        unsafe { mem::transmute::<Session, u64>(*self) }
    }
    #[inline(always)]
    pub fn from_u64(data: u64) -> Self {
        unsafe { mem::transmute::<u64, Session>(data) }
    }
    #[inline(always)]
    pub fn src_ip(&self) -> u32 {
        unsafe { ptr::read_unaligned(&self.src_ip) }
    }

    #[inline(always)]
    pub fn set_src_ip(&mut self, value: u32) {
        unsafe { ptr::write_unaligned(&mut self.src_ip, value) }
    }

    #[inline(always)]
    pub fn src_port(&self) -> u16 {
        unsafe { ptr::read_unaligned(&self.src_port) }
    }

    #[inline(always)]
    pub fn set_src_port(&mut self, value: u16) {
        unsafe { ptr::write_unaligned(&mut self.src_port, value) }
    }

    #[inline(always)]
    pub fn protocal(&self) -> u8 {
        unsafe { ptr::read_unaligned(&self.protocal) }
    }

    #[inline(always)]
    pub fn set_protocal(&mut self, value: u8) {
        unsafe { ptr::write_unaligned(&mut self.protocal, value) }
    }

    #[inline(always)]
    pub fn new(src_ip: u32, src_port: u16, protocal: u8) -> Self {
        Session {
            src_ip,
            src_port,
            protocal,
            _padding: 0,
        }
    }
}

impl Connection {
    //
    // dst : REMOTE
    //
    #[inline(always)]
    pub fn egress(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        protocal: u8,
    ) -> Self {
        Connection {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocal,
            _padding: [0u8; 3],
        }
    }

    //
    // src : REMOTE
    //
    #[inline(always)]
    pub fn ingress(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        protocal: u8,
    ) -> Self {
        Connection {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            protocal,
            _padding: [0u8; 3],
        }
    }

    #[inline(always)]
    pub fn into_session(&self) -> Session {
        // USE OUR HOST AS SessionKey
        Session {
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocal: self.protocal,
            _padding: self._padding[0],
        }
    }
    #[inline(always)]
    pub fn into_state(&self) -> ConnectionState {
        // USE REMOTE AS MAP VALUE
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.dst_ip,
            protocal: self.protocal,
            remote_port: self.dst_port,
            tcp_state: TCPState::default(),
            _padding_: 0xff,
        }
    }
    #[inline(always)]
    pub fn into_state_listen(&self) -> ConnectionState {
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.dst_ip,
            protocal: self.protocal,
            remote_port: self.dst_port,
            tcp_state: TCPState::Listen,
            _padding_: 0xff,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub enum TCPState {
    #[default]
    Closed,
    Established,
    FinWait1,
    FinWait2,
    Listen,
    SynReceived,
    SynSent,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TCPState {}
