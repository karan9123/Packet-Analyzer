use std::fmt;
use crate::{IPacket, IPVersion};

pub(crate) struct EthernetFrame {
    pub(crate) packet_size: u32,
    pub(crate) destination_address: [u8; 6],
    pub(crate) source_address: [u8; 6],
    pub(crate) ether_type: [u8; 2],
    pub(crate) version: IPVersion,
    pub(crate) packet: IPacket,
}

impl EthernetFrame {
    pub(crate) fn new() -> EthernetFrame {
        EthernetFrame {
            packet_size: 0,
            destination_address: [0; 6],
            source_address: [0; 6],
            ether_type: [0; 2],
            version: IPVersion::V4,
            packet: IPacket::new(),
        }
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        write!(f, "ETHER: -----Ether Header-----\n")?;
        write!(f, "ETHER:\n")?;
        write!(f, "ETHER: Packet size= {} bytes\n", self.packet_size)?;
        write!(f, "ETHER: Destination= {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.destination_address[0],
               self.destination_address[1], self.destination_address[2], self.destination_address[3],
               self.destination_address[4], self.destination_address[5])?;
        write!(f, "ETHER: Source     = {:x}:{:x}:{:x}:{:x}:{:x}:{:x}\n", self.source_address[0],
               self.source_address[1], self.source_address[2], self.source_address[3],
               self.source_address[4], self.source_address[5])?;
        write!(f, "ETHER: Ethertype  = 0x{:x}{:x}\n", self.ether_type[0], self.ether_type[1])?;
        write!(f, "ETHER:")
    }
}