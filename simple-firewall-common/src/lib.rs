#![no_std]

#[derive(Clone, Copy, Debug)]
pub struct Connection {
    pub host_addr: u32,
    pub remote_addr: u32,
    pub host_port: u16,
    pub remote_port: u16,
    pub protocal: u8,
    pub tcp_flag: u8,
    _padding: [u8; 2],
    pub seq: u32,
    pub ack_seq: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionState {
    pub last_syn_ack_time: u64,
    pub syn_ack_count: u32,
    pub remote_ip: u32,
    pub remote_port: u16,
    pub protocal: u8,
    pub last_tcp_flag: u8,
    pub tcp_state: TCPState,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionState {}

impl ConnectionState {
    pub fn to_backlist_key(&self) -> u32 {
        self.remote_ip
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpPacket {
    pub host_addr: u32,
    pub remote_addr: u32,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IcmpPacket {}

impl Connection {
    //
    // dst : REMOTE
    //
    #[inline(always)]
    pub fn egress(
        host_addr: u32,
        host_port: u16,
        remote_addr: u32,
        remote_port: u16,
        protocal: u8,
        tcp_flag: u8,
        seq: u32,
        ack_seq: u32,
    ) -> Self {
        Connection {
            host_addr,
            remote_addr,
            host_port,
            remote_port,
            protocal,
            tcp_flag,
            _padding: [0u8; 2],
            seq,
            ack_seq,
        }
    }

    //
    // src : REMOTE
    //
    #[inline(always)]
    pub fn ingress(
        host_addr: u32,
        host_port: u16,
        remote_addr: u32,
        remote_port: u16,
        protocal: u8,
        tcp_flag: u8,
        seq: u32,
        ack_seq: u32,
    ) -> Self {
        Connection {
            host_addr,
            remote_addr,
            host_port,
            remote_port,
            protocal,
            tcp_flag,
            _padding: [0u8; 2],
            seq,
            ack_seq,
        }
    }

    #[inline(always)]
    pub fn into_session(&self) -> u32 {
        // USE REMOTE HOST AS SessionKey
        self.remote_addr
    }
    #[inline(always)]
    pub fn into_state_sent(&self) -> ConnectionState {
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.remote_addr,
            remote_port: self.remote_port,
            protocal: self.protocal,
            tcp_state: TCPState::SynSent,
            last_tcp_flag: self.tcp_flag,
        }
    }
    #[inline(always)]
    pub fn into_state_listen(&self) -> ConnectionState {
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.remote_addr,
            remote_port: self.remote_port,
            protocal: self.protocal,
            tcp_state: TCPState::Listen,
            last_tcp_flag: self.tcp_flag,
        }
    }
    #[inline(always)]
    pub fn into_state_synreceived(&self) -> ConnectionState {
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.remote_addr,
            remote_port: self.remote_port,
            protocal: self.protocal,
            tcp_state: TCPState::SynReceived,
            last_tcp_flag: self.tcp_flag,
        }
    }
    #[inline(always)]
    pub fn into_state_established(&self) -> ConnectionState {
        ConnectionState {
            last_syn_ack_time: 0,
            syn_ack_count: 0,
            remote_ip: self.remote_addr,
            remote_port: self.remote_port,
            protocal: self.protocal,
            tcp_state: TCPState::Established,
            last_tcp_flag: self.tcp_flag,
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
