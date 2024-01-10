# PCAP Analyzer

A rust implementation of a packet capture analyzer, built from scratch without relying on external libraries. This
program parses pcap files and prints information about the Ethernet header, IP header, and header data of TCP, UDP, or
ICMP packets.

## Getting Started

To run the PCAP analyzer program, you need to have [Rust](https://www.rust-lang.org/) installed on your system.

### Move into the folder:

```shell
$ cd packet_analyzer
```

### Build using cargo

```shell
/packet_analyzer $ cargo build
```

## Usage

### To analyze a pcap file, run the following command:

```shell
$ cargo run -r [filename]
```

### To filter the packets while analyzing, use the following command:

```shell
$ cargo run -r [filename] [filter]
```

## Filters

### The following filters are supported for packet analysis:

- host
- port
- ip
- icmp
- tcp
- udp
- net

## Example

To analyze the `test.pcap` file and filter the packets based on the TCP protocol, run the following command:

```shell
$ cargo run -r test.pcap tcp
```

This command will parse the `test.pcap` file, print information about the Ethernet header, IP header, and header data of
TCP packets, and display only the filtered results based on the TCP protocol.
