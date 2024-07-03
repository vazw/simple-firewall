#![no_std]

// Connection that we requested to outside world
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Connection {
    pub state: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Session {
    pub src_ip: u32,
    pub src_port: u16,
    pub protocol: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Session {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcmpPacket {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub icmp_type: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IcmpPacket {}
