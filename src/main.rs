extern crate pnet;
extern crate pnet_macros_support;

pub mod tools;

use pnet::packet::Packet;

use pnet::datalink::{self, NetworkInterface};

//use pnet::packet::arp::ArpPacket;
//use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
//use pnet::packet::icmpv6::Icmpv6Packet;
//use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
//use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum, Ipv4Flags};
use pnet::packet::ipv4::{MutableIpv4Packet, checksum, Ipv4Flags};
//use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
//use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, ipv4_checksum, TcpFlags, TcpOption};
use pnet::packet::tcp::{MutableTcpPacket, ipv4_checksum, TcpFlags};
//use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::util::MacAddr;
use pnet::packet::MutablePacket;
//use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ip::IpNextHeaderProtocols::Tcp;

use std::env;
use std::io::{self, Write};
use std::net::Ipv4Addr;
//use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process;
use tools::fast_random;

fn set_ipv4_header(ethernet_payload: &mut [u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, header_length: u8, total_length: u16) {
    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_payload).unwrap();
    //let mut ipv4_packet = MutableIpv4Packet::new(ethernet_frame.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    // minimum header length = 4 byte x 5
    ipv4_packet.set_header_length(header_length);
    ipv4_packet.set_total_length(total_length);
    ipv4_packet.set_identification(0);
    //ipv4_packet.set_identification(fast_random::<u16>().unwrap());
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(Tcp);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));
    println!("ipv4_packet: {:?}", ipv4_packet);
    println!("ipv4_packet: {:?}", ipv4_packet.packet());
    println!("ipv4_packet.payload().len(): {}", ipv4_packet.payload().len());
}

fn set_tcp_header(ip_payload: &mut [u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, header_length: u8) {
    let mut tcp_packet = MutableTcpPacket::new(ip_payload).unwrap();
    //let mut tcp_packet = MutableTcpPacket::new(&mut ethernet_frame.payload_mut()[(4*5)..]).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(fast_random::<u32>().unwrap());
    // ヘッダ長，オプションなしの場合 4 bytes x 5 = 20 bytes
    tcp_packet.set_data_offset(header_length);
    //tcp_packet.set_data_offset(11);
    tcp_packet.set_flags(TcpFlags::SYN);
    //tcp_packet.set_flags(TcpFlags::SYN|TcpFlags::ECE|TcpFlags::CWR);
    tcp_packet.set_window(65535);
    tcp_packet.set_urgent_ptr(0);
    //let ts = TcpOption::timestamp(0, 0);
    //let ts = TcpOption::timestamp(743951781, 44056978);
    //tcp_packet.set_options(&vec![TcpOption::mss(1460), TcpOption::nop(), TcpOption::wscale(6), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()]);
    //tcp_packet.set_options(&vec![TcpOption::mss(1460), TcpOption::nop(), TcpOption::wscale(6), TcpOption::nop(), TcpOption::nop(), ts, TcpOption::sack_perm()]);
    tcp_packet.set_checksum(ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip));
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    // IPv4でのTCP SYNパケットの生成例
    // Ethernetのパケットを生成（54バイトの場合）
    let mut ethernet_frame = MutableEthernetPacket::owned(vec![0u8; 54]).unwrap();
    //let mut ethernet_frame = MutableEthernetPacket::owned(vec![0u8; 1500]).unwrap();
    // loopbackの場合，Ethernet Header 14バイトは0のまま
    if !interface.is_loopback() {
        // loopbackでない場合はMacAddrを指定
        ethernet_frame.set_destination(MacAddr(0x08,0x00,0x27,0x27,0x36,0x6d));
        ethernet_frame.set_source(MacAddr(0x0a,0x00,0x27,0x00,0x00,0x00));
        ethernet_frame.set_ethertype(EtherTypes::Ipv4);
        //ethernet_frame.set_ethertype(EtherTypes::Ipv6);
    };
    println!("ethernet_frame: {:?}", ethernet_frame.packet());
    println!("ethernet_frame.payload().len(): {}", ethernet_frame.payload().len());

    //let src_ip = Ipv4Addr::new(172, 16, 0, 2);
    let src_ip = Ipv4Addr::new(127, 0, 0, 1);
    //let dst_ip = Ipv4Addr::new(172, 16, 0, 5);
    let dst_ip = Ipv4Addr::new(127, 0, 0, 1);
    // header_length: オプションなしの場合 5 (4 bytes x 5 = 20 bytes)
    // total_length: ペイロードも含めたIPヘッダ以降のパケット長を指定 (54 - 14 = 40)
    set_ipv4_header(ethernet_frame.payload_mut(), src_ip.clone(), dst_ip.clone(), 5, 40);

    // IPペイロードは 4 bytes x 5 = 20 + 1 バイト目から
    // header_length: オプションなしの場合 5 (4 bytes x 5 = 20 bytes)
    set_tcp_header(&mut ethernet_frame.payload_mut()[(4*5)..], src_ip.clone(), dst_ip.clone(), 54321, 12345, 5);

    // TCPペイロードは 4 x 5 + 4 x 5 = 40 + 1 バイト目から
    // set_xxx_header(&mut ethernet_frame.payload_mut()[(4*5+4*5)..], ...)

    println!("ethernet_frame: {:?}", ethernet_frame.packet());
    match tx.send_to(ethernet_frame.packet(), None) {
        Some(Ok(_)) => (),
        Some(Err(e)) => println!("{:?}", e),
        None => println!("None"),
    }
}
