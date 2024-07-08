#![no_std]
use core::mem;

#[derive(Clone, Copy, Hash)]
pub struct Connection {
    pub state: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocal: u8,
    pub _padding: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub src_ip: u32,
    pub src_port: u16,
    pub protocal: u8,
    pub _padding: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Session {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub protocal: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}

#[derive(Clone, Copy, Debug)]
pub struct IcmpPacket {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub icmp_type: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IcmpPacket {}

impl SessionKey {
    pub fn session(self: &Self) -> Session {
        Session {
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocal: self.protocal,
            _padding: 0,
        }
    }
}
impl Session {
    pub fn session(self: &Self) -> SessionKey {
        SessionKey {
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocal: self.protocal,
        }
    }
    pub fn to_u64(&self) -> u64 {
        unsafe { mem::transmute::<Session, u64>(*self) }
    }
}

impl Connection {
    pub fn session(self: &Self) -> SessionKey {
        SessionKey {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            protocal: self.protocal,
        }
    }
    pub fn egress_session(self: &Self) -> Session {
        Session {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            protocal: self.protocal,
            _padding: self._padding[0],
        }
    }
    pub fn ingress_session(self: &Self) -> Session {
        Session {
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocal: self.protocal,
            _padding: self._padding[0],
        }
    }
    pub fn into_egress_connection(self: &Self) -> Connection {
        Connection {
            state: self.state,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocal: self.protocal,
            _padding: self._padding,
        }
    }
}
