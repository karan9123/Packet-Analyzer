use std::fmt;
use crate::{IPProtocol, IPVersion, ProtocolDatagram};



pub(crate) struct IPacket {
    pub(crate) version: IPVersion,
    pub(crate) ihl: u8,
    //pub(crate) header length
    pub(crate) tos: u8,
    pub(crate) precedence: u8,
    pub(crate) delay: u8,
    pub(crate) throughput: u8,
    pub(crate) reliability: u8,
    pub(crate) total_length: [u8; 2],
    pub(crate) identification: [u8; 2],
    pub(crate) reserved_flag: u8,
    pub(crate) do_not_fragment_flag: u8,
    pub(crate) last_fragment_flag: u8,
    pub(crate) fragment_offset: u16,
    pub(crate) ttl: u8,
    pub(crate) protocol: IPProtocol,
    pub(crate) header_checksum: [u8; 2],
    pub(crate) source_add: [u8; 4],
    pub(crate) destination_add: [u8; 4],
    pub(crate) options: Option<Vec<u8>>,
    pub(crate) datagram: ProtocolDatagram,
}

impl IPacket {
    pub(crate) fn new() -> IPacket {
        IPacket {
            version: IPVersion::V4,
            ihl: 0,
            tos: 0,
            precedence: 0,
            delay: 0,
            throughput: 0,
            reliability: 0,
            total_length: [0, 0],
            identification: [0, 0],
            reserved_flag: 0,
            do_not_fragment_flag: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: IPProtocol::Default,
            header_checksum: [0, 0],
            source_add: [0, 0, 0, 0],
            destination_add: [0, 0, 0, 0],
            options: None,
            datagram: ProtocolDatagram::Default("placeholder".parse().unwrap()),
            last_fragment_flag: 0,
        }
    }
}

impl fmt::Display for IPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IP: -----IP Header-----\n")?;
        write!(f, "IP:\n")?;
        write!(f, "IP: Version         = {}\n", self.version)?;
        write!(f, "IP: Header length   = {} bytes\n", (self.ihl * 4))?;
        write!(f, "IP: Type of service = 0x{:x}\n", self.tos)?;
        write!(f, "IP:     xxx. ....   = {}(precedence)\n", self.precedence)?;
        write!(f, "IP:     ...{} ....  = {} delay \n", self.delay, if self.delay == 0 {"normal"} else { "low"})?;
        write!(f, "IP:     .... {}...  = {} throughput\n", self.throughput, if self.throughput == 0 {"normal"} else { "high"})?;
        write!(f, "IP:     .... .{}..  = {} reliability\n", self.reliability, if self.reliability == 0 {"normal"} else { "high"})?;
        write!(f, "IP: Total length    = {} bytes\n", u16::from_be_bytes(self.total_length))?;
        write!(f, "IP: Identification  = {}\n", u16::from_be_bytes(self.identification))?;
        write!(f, "IP: Flags: \n")?;
        write!(f, "IP:     {}... ....  = {}\n", self.reserved_flag, if self.reserved_flag == 0 {"reserved"} else {"not reserved"})?;
        write!(f, "IP:     .{}.. ....  = {}fragment\n", self.do_not_fragment_flag, if self.do_not_fragment_flag == 1 {"do not "} else {""})?;
        write!(f, "IP:     ..{}. ....  = last fragment\n", self.last_fragment_flag)?;
        write!(f, "IP: Fragment offset = {} bytes\n", self.fragment_offset)?;
        write!(f, "IP: Time to live    = {} seconds/hops\n", self.ttl)?;
        write!(f, "IP: Protocol        = {}\n", self.protocol)?;
        write!(f, "IP: Header checksum = 0x{:x}{:x}\n", self.header_checksum[0], self.header_checksum[1])?;
        write!(f, "IP: Source address  = {}\n", format!("{}.{}.{}.{}", self.source_add[0], self.source_add[1], self.source_add[2], self.source_add[3]))?;
        write!(f, "IP: Destination address= {}\n", format!("{}.{}.{}.{}", self.destination_add[0], self.destination_add[1], self.destination_add[2], self.destination_add[3]))?;
        match self.options.clone() {
            None => write!(f, "No options\n")?,
            Some(op) => write!(f, "Options: {}\n", op.len())?
        };
        write!(f, "{}", self.datagram)
    }
}