#![no_std]

#[derive(Clone, Copy, Hash)]
pub struct Connection {
    pub state: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocal: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub src_ip: u32,
    pub src_port: u16,
    pub protocal: u8,
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
        }
    }
    pub fn ingress_session(self: &Self) -> Session {
        Session {
            src_ip: self.src_ip,
            src_port: self.src_port,
            protocal: self.protocal,
        }
    }
}
