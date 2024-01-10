use std::fmt;

pub(crate) enum ProtocolDatagram {
    TCP(TCPPacket),
    UDP(UDPPacket),
    ICMP(ICMPPacket),
    Default(String),
}

impl ProtocolDatagram {
    pub(crate) fn new() -> ProtocolDatagram {
        ProtocolDatagram::Default("This is the default value".parse().unwrap())
    }
}

impl fmt::Display for ProtocolDatagram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolDatagram::TCP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::UDP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::ICMP(packet) => write!(f, "{}", packet),
            ProtocolDatagram::Default(_) => write!(f, "This is a placeholder")
        }
    }
}


pub(crate) struct ICMPPacket {
    pub(crate) packet_type: u8,
    pub(crate) code: u8,
    pub(crate) checksum: [u8; 2],
    pub(crate) identifier_be: [u8; 2],
    pub(crate) identifier_le: [u8; 2],
    pub(crate) sequence_be: [u8; 2],
    pub(crate) sequence_le: [u8; 2],
    pub(crate) timestamp: [u8; 8],
    pub(crate) data: Vec<u8>,
}

impl ICMPPacket {
    pub(crate) fn new() -> ICMPPacket {
        ICMPPacket {
            packet_type: 0,
            code: 0,
            checksum: [0, 0],
            identifier_be: [0, 0],
            identifier_le: [0, 0],
            sequence_be: [0, 0],
            sequence_le: [0, 0],
            timestamp: [0, 0, 0, 0, 0, 0, 0, 0],
            data: vec![],
        }
    }
}

impl fmt::Display for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP: -----ICMP Header-----\n")?;
        write!(f, "ICMP:\n")?;
        write!(f, "ICMP: type= {}\n", self.packet_type)?;
        write!(f, "ICMP: Code= {}\n", self.code)?;
        write!(f, "ICMP: checksum= 0x{:x}{:x}\n", self.checksum[0], self.checksum[1])?;
        write!(f, "ICMP:")
    }
}


pub(crate) struct UDPPacket {
    pub(crate) source_port: [u8; 2],
    pub(crate) destination_port: [u8; 2],
    pub(crate) length: [u8; 2],
    pub(crate) checksum: [u8; 2],
    pub(crate) data: Vec<u8>,
}

impl UDPPacket {
    pub(crate) fn new() -> UDPPacket {
        UDPPacket {
            source_port: [0, 0],
            destination_port: [0, 0],
            length: [0, 0],
            checksum: [0, 0],
            data: vec![],
        }
    }
}

impl fmt::Display for UDPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UDP: -----UDP Header-----\n")?;
        write!(f, "UDP:\n")?;
        write!(f, "UDP: Source port      = {}\n", u16::from_be_bytes(self.source_port))?;
        write!(f, "UDP: Destination port = {}\n", u16::from_be_bytes(self.destination_port))?;
        write!(f, "UDP: Length           = {}\n", u16::from_be_bytes(self.length))?;
        write!(f, "UDP: Checksum         = 0x{:x}{:x}\n", self.checksum[0], self.checksum[1])?;
        write!(f, "UDP:")
    }
}


pub(crate) struct TCPPacket {
    pub(crate) source_port: [u8; 2],
    pub(crate) destination_port: [u8; 2],
    pub(crate) sequence_number: [u8; 4],
    pub(crate) acknowledgement_number: [u8; 4],
    pub(crate) data_offset: u8, //Taken from same bit as flag
    pub(crate) flags: u8, //Taken from the same bit as data_offset
    pub(crate) window: [u8; 2],
    pub(crate) checksum: [u8; 2],
    pub(crate) urgent_pointer: [u8; 2],
    pub(crate) options: Option<Vec<u8>>, //Can range from 0 to 40 bytes

}

impl TCPPacket {
    pub(crate) fn new() -> TCPPacket {
        TCPPacket {
            source_port: [0, 0],
            destination_port: [0, 0],
            sequence_number: [0, 0, 0, 0],
            acknowledgement_number: [0, 0, 0, 0],
            data_offset: 0,
            flags: 0,
            window: [0, 0],
            checksum: [0, 0],
            urgent_pointer: [0, 0],
            options: None
        }
    }
}

impl fmt::Display for TCPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TCP: -----TCP Header-----\n")?;
        write!(f, "TCP:\n")?;
        write!(f, "TCP: Source Port       = {}\n", u16::from_be_bytes(self.source_port))?;
        write!(f, "TCP: Destination Port  = {}\n", u16::from_be_bytes(self.destination_port))?;
        write!(f, "TCP: Sequence number   = {}\n", u32::from_be_bytes(self.sequence_number))?;
        write!(f, "TCP: Acknowledgement number     = {}\n", u32::from_be_bytes(self.acknowledgement_number))?;
        write!(f, "TCP: Data offset(header length) = {} bytes\n", self.data_offset)?;
        write!(f, "TCP: Flags             = {}\n", self.flags)?;
        write!(f, "TCP: Window            = {}\n", u16::from_be_bytes(self.window))?;
        write!(f, "TCP: Checksum          = 0x{:x}{:x}\n", self.checksum[0], self.checksum[1])?;
        write!(f, "TCP: Urgent pointer    = {}\n", u16::from_be_bytes(self.urgent_pointer))?;
        match self.options.clone() {
            None => write!(f, "No options\n"),
            Some(op) => write!(f, "Options: {}\n", op.len())
        }
    }
}