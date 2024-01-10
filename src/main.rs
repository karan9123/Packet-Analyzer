// Allow unused imports, variables, dead code, mutable bindings, and assignments in this module.
// This is typically done during development or debugging.
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]

// Import various modules related to network packet processing.
mod ip_protocol;
mod pcap_file_header;
mod pcap_block;
mod ethernet_frame;
mod internet_packet;
// mod pcap_file;
mod internet_protocol_types;

// Standard library imports for environment handling, formatting, file I/O, networking, and string processing.
use std::{env, fmt};
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use std::str::FromStr;
use bitreader::BitReader;

// Import structs and enums from the respective modules.
use ip_protocol::IPProtocol;
use pcap_file_header::PcapFileHeader;
use ethernet_frame::EthernetFrame;
use pcap_block::PcapBlock;
use internet_protocol_types::{ProtocolDatagram, ICMPPacket, UDPPacket, TCPPacket};
use internet_packet::IPacket;
// use pcap_file::PcapFile;

/// Enum representing IP version, either IPv4 or IPv6.
#[derive(Copy, Clone, PartialOrd, PartialEq)]
enum IPVersion {
    V4,
    V6,
}

// Implement the Display trait for IPVersion for human-readable output.
impl fmt::Display for IPVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IPVersion::V4 => write!(f, "4"),
            IPVersion::V6 => write!(f, "6")
        }
    }
}

/// Enum representing various filters that can be applied to network packets.
#[derive(Debug, Clone)]
enum Filter {
    Host([u8; 4]),
    Port([u8; 2]),
    Ip,
    Tcp,
    Udp,
    Icmp,
    Net([u8; 4]),
    Count(i32),
    Default(String),
}

// Implement custom logic for converting a string vector to a Filter.
impl Filter {
    fn from_str(str: Vec<String>) -> Filter {
        // Handle different filter types based on input string.
        if str.len() ==1{
            match str[0].as_str(){
                "tcp" => {Filter::Tcp},
                "udp" =>{Filter::Udp},
                "icmp" => {Filter::Icmp},
                "ip" => {Filter::Ip}
                _ => {Filter::Default("Default".to_string())}
            }
        }
        else {
            match str[0].as_str() {
                "host" => {
                    let k: Vec<&str> = str[1].split(".").collect();
                    Filter::Host([u8::from_str(k[0]).unwrap(), u8::from_str(k[1]).unwrap(),
                        u8::from_str(k[2]).unwrap(), u8::from_str(k[3]).unwrap()])
                }
                "port" => {
                    let num = u16::from_str(&*str[1]).unwrap();
                    let b1 = (num >> 8) as u8;
                    let b2 = num as u8;
                    Filter::Port([b1, b2])
                }
                "net" => {
                    let k: Vec<&str> = str[1].split(".").collect();
                    Filter::Net([u8::from_str(k[0]).unwrap(), u8::from_str(k[1]).unwrap(),
                        u8::from_str(k[2]).unwrap(), u8::from_str(k[3]).unwrap()])
                }
                "-c" => { Filter::Count(str[1].parse::<i32>().unwrap()) }
                &_ => { Filter::Default("default".to_string()) }
            }
        }
    }
}

/// Creates and returns an `EthernetFrame` from raw data bytes.
/// 
/// # Arguments
/// * `data` - A vector of bytes representing the raw data of the Ethernet frame.
fn create_and_return_ether(data: Vec<u8>) -> EthernetFrame {
    let packet_size = data.len() as u32;
    let destination_address: [u8; 6] = data[0..6].try_into().unwrap();
    let source_address: [u8; 6] = data[6..12].try_into().unwrap();
    let ether_type: [u8; 2] = data[12..14].try_into().unwrap();


    let temp = [data[14].clone()]; //This let is important
    let mut version_head_len_byte = BitReader::new(&temp);
    let ipv = version_head_len_byte.read_u8(4).unwrap();
    let ihl = version_head_len_byte.read_u8(4).unwrap();

    let temp = [data[15].clone()];
    let mut type_of_service = BitReader::new(&temp);
    let precedence = type_of_service.read_u8(3).unwrap();
    let delay = type_of_service.read_u8(1).unwrap();
    let throughput = type_of_service.read_u8(1).unwrap();
    let reliability = type_of_service.read_u8(1).unwrap();
    let tos = type_of_service.read_u8(2).unwrap();

    let total_length: [u8; 2] = data[16..18].try_into().unwrap();
    let identification: [u8; 2] = data[18..20].try_into().unwrap();

    let temp = [data[20].clone(), data[21].clone()];
    let mut flags = BitReader::new(&temp);
    let reserved_flag = flags.read_u8(1).unwrap();
    let do_not_fragment_flag = flags.read_u8(1).unwrap();
    let last_fragment_flag = flags.read_u8(1).unwrap();
    let fragment_offset = flags.peek_u16(0).unwrap();


    //Here first 3 bits are flags and rest 13 are Fragment offset

    let ttl = data[22];
    let temp = data[23];
    let mut protocol = IPProtocol::Default;
    match temp {
        1 => { protocol = IPProtocol::ICMP }
        6 => { protocol = IPProtocol::TCP }
        17 => { protocol = IPProtocol::UDP }
        _ => {}
    }
    let header_checksum: [u8; 2] = data[24..26].try_into().unwrap();

    let source_add: [u8; 4] = data[26..30].try_into().unwrap();
    let destination_add: [u8; 4] = data[30..34].try_into().unwrap();

    let mut options = None;
    let mut current: usize = 34;
    if ihl > 5 {
        current = (34 + ((ihl * 4) - 20)) as usize;
        options = Some(data[34..(current)].to_vec());
    }


    let mut datagram: ProtocolDatagram = ProtocolDatagram::new();
    match protocol {
        IPProtocol::ICMP => {
            let mut icmp = ICMPPacket::new();
            icmp.packet_type = data[current];
            icmp.code = data[current + 1];
            icmp.checksum = data[current + 2..current + 4].try_into().unwrap();
            icmp.identifier_be = data[(current + 4)..(current + 6)].try_into().unwrap();
            icmp.identifier_le = data[(current + 4)..(current + 6)].try_into().unwrap();
            icmp.sequence_be = data[(current + 6)..(current + 8)].try_into().unwrap();
            icmp.sequence_le = data[(current + 6)..(current + 8)].try_into().unwrap();
            icmp.timestamp = data[(current + 8)..(current + 16)].try_into().unwrap();
            icmp.data = data[(current + 16)..].to_vec();
            datagram = ProtocolDatagram::ICMP(icmp);
        }
        IPProtocol::UDP => {
            let mut udp = UDPPacket::new();
            udp.source_port = data[current..(current + 2)].try_into().unwrap();
            udp.destination_port = data[(current + 2)..(current + 4)].try_into().unwrap();
            udp.length = data[(current + 4)..(current + 6)].try_into().unwrap();
            udp.checksum = data[(current + 6)..(current + 8)].try_into().unwrap();
            udp.data = data[(current + 8)..].to_vec();
            datagram = ProtocolDatagram::UDP(udp);
        }
        IPProtocol::TCP => {
            let mut tcp = TCPPacket::new();
            tcp.source_port = data[current..(current + 2)].try_into().unwrap();
            tcp.destination_port = data[(current + 2)..(current + 4)].try_into().unwrap();
            tcp.sequence_number = data[(current + 4)..(current + 8)].try_into().unwrap();
            tcp.acknowledgement_number = data[(current + 8)..(current + 12)].try_into().unwrap();

            let data_offset_and_flags = data[current + 12];
            let data_offset = (data_offset_and_flags >> 4) & 0xF;
            let flags = data_offset_and_flags & 0xF;

            tcp.data_offset = data_offset * 4;
            tcp.flags = flags;
            tcp.window = data[(current + 14)..(current + 16)].try_into().unwrap();
            tcp.checksum = data[(current + 16)..(current + 18)].try_into().unwrap();
            tcp.urgent_pointer = data[(current + 18)..(current + 20)].try_into().unwrap();
            datagram = ProtocolDatagram::TCP(tcp);
        }
        _ => {}
    }


    let version = match ipv {
        4 => { IPVersion::V4 }
        _ => { IPVersion::V6 }
    };

    let packet = IPacket {
        version,
        ihl,
        tos,
        precedence,
        delay,
        throughput,
        reliability,
        total_length,
        identification,
        reserved_flag,
        do_not_fragment_flag,
        last_fragment_flag,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source_add,
        destination_add,
        options,
        datagram,

    };

    EthernetFrame {
        packet_size,
        destination_address,
        source_address,
        ether_type,
        version,
        packet,
    }
}



/// Prints the given PCAP block if it matches the specified filter.
/// 
/// # Arguments
/// * `block` - The PCAP block to be printed.
/// * `filter` - The filter to apply to the PCAP block.
fn print_pcap(block: PcapBlock, filter: Filter) {

    match filter {
        Filter::Host(address) => {
            if block.ether_frame.packet.source_add == address ||
                block.ether_frame.packet.destination_add == address {
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Port(port) => {
            if block.ether_frame.packet.protocol == IPProtocol::UDP ||
                block.ether_frame.packet.protocol == IPProtocol::TCP {
                let mut src = [0, 0];
                let mut dst = [0, 0];
                match block.ether_frame.packet.datagram {
                    ProtocolDatagram::TCP(ref packet) => {
                        src = packet.source_port.clone();
                        dst = packet.destination_port.clone();
                    }
                    ProtocolDatagram::UDP(ref packet) => {
                        src = packet.source_port.clone();
                        dst = packet.destination_port.clone();
                    }
                    ProtocolDatagram::ICMP(_) => {}
                    ProtocolDatagram::Default(_) => {}
                }
                if [src, dst].contains(&port) {
                    println!("{}", block.ether_frame);
                    println!("{}\n\n", block.ether_frame.packet);
                }
            }
        }
        Filter::Ip => {
            if block.ether_frame.version == IPVersion::V4 {
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Tcp => {
            if block.ether_frame.packet.protocol == IPProtocol::TCP{
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Udp => {
            if block.ether_frame.packet.protocol == IPProtocol::UDP{
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Icmp => {
            if block.ether_frame.packet.protocol == IPProtocol::ICMP{
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Net(address) => {
            if block.ether_frame.packet.source_add == address ||
                block.ether_frame.packet.destination_add == address {
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Count(count) => {
            if count > 0 {
                println!("{}", block.ether_frame);
                println!("{}\n\n", block.ether_frame.packet);
            }
        }
        Filter::Default(_) => {
            println!("{}", block.ether_frame);
            println!("{}\n\n", block.ether_frame.packet);
        }
    }
}


/*fn main() {
    let args: Vec<String> = env::args().collect();
    let mut file_name = String::from("test.pcap");
    if args.len() > 1 {
        file_name = args[1].clone();
    }
    let mut filter = Filter::Default("default".to_owned());
    if args.len() > 2 {
        filter = Filter::from_str(args[2..].to_vec())
    }
    let mut pcap_header: PcapFileHeader = PcapFileHeader::new(); //Initializing a Pcap Header Structure
    let mut file: File = File::open(file_name).unwrap(); //reading the file
    let file_size: u64 = file.metadata().unwrap().len(); //File size (bytes)
    let mut byte_count: u64 = 0; //This counter is used to track the bytes reader has read from the file


    //This is PCAP Header
    file.read(&mut pcap_header.magic_number).unwrap();
    file.read(&mut pcap_header.version_major).unwrap();
    file.read(&mut pcap_header.version_minor).unwrap();
    file.read(&mut pcap_header.time_zone).unwrap();
    file.read(&mut pcap_header.timestamp_accuracy).unwrap();
    file.read(&mut pcap_header.snap_length).unwrap();
    file.read(&mut pcap_header.link_layer_type).unwrap();
    byte_count += 24;  //Because the size of PCAP Header is 24 bytes

    // let pcap_file = PcapFile::new_with_header(pcap_header); //Initializing the PCAP file with the header
    let mut packet_count = 0; //Count of network packets in PCAP File

    loop {
        let my_filter = filter.clone();
        filter = my_filter.clone();
        match filter {
            Filter::Host(_) => {}
            Filter::Port(_) => {}
            Filter::Ip => {}
            Filter::Tcp => {}
            Filter::Udp => {}
            Filter::Icmp => {}
            Filter::Net(_) => {}
            Filter::Count(count) => {
                filter = Filter::Count(count - 1)
            }
            Filter::Default(_) => {}
        }
        if byte_count + 20 > file_size {
            println!("Total number of packets in the file(Without Filter): {}", packet_count);
            break;
        }

        packet_count += 1;
        let mut pcap_block: PcapBlock = PcapBlock::new(); //Initializing a new PCAP Block
        file.read(&mut pcap_block.timestamp_seconds).unwrap();
        file.read(&mut pcap_block.timestamp_microseconds).unwrap();
        file.read(&mut pcap_block.captured_length).unwrap();
        file.read(&mut pcap_block.original_length).unwrap();

        byte_count += 16;
        byte_count += u32::from_ne_bytes(pcap_block.captured_length.clone()) as u64;

        let mut pcap_block_data = vec![0_u8; u32::from_ne_bytes(pcap_block.captured_length) as usize];
        file.read(&mut pcap_block_data).unwrap();

        pcap_block.ether_frame = create_and_return_ether(pcap_block_data);
        // pcap_file.data.push(pcap_block); //Instead of print, we can use this command to create
        // the complete PCAP file struct with Pcap Blocks
        print_pcap(pcap_block, my_filter);
    }
}*/

fn main(){
    let rcv_socket = UdpSocket::bind("0.0.0.0:4331").expect("could not bind to the receive socket");
    println!("Listening on: {}", rcv_socket.local_addr().unwrap());
    let mut buf = [0; 1024];

    let (number_of_bytes, src_addr) = rcv_socket.recv_from(&mut buf)
        .expect("Didn't receive data");
    let filled_buf =  buf[..number_of_bytes].to_vec();
    let ethernet_frame = create_and_return_ether(filled_buf);
    println!("{}", ethernet_frame);
    println!("{}", ethernet_frame.packet);

}

