use super::packet::RDMA_DEFAULT_PORT;
use super::types::RdmaOpCode;
use crate::device::layout::{Aeth, Bth, NReth};
use crate::device::ToHostWorkRbDescTransType;
use crate::responser::ACKPACKET_SIZE;
use super::types::{Psn, Qpn};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};

use pnet::util::MacAddr;
use std::net::Ipv4Addr;

const PKT_ETH_SIZE: usize = EthernetPacket::minimum_packet_size();
const PKT_IPV4_SIZE: usize = Ipv4Packet::minimum_packet_size();
const PKT_UDP_SIZE: usize = UdpPacket::minimum_packet_size();

const IP_VERSION_4: u8 = 4;
const IPV4_HEADER_LEN_DEAFULT: u8 = 5;
const IPV4_DEFAULT_TTL: u8 = 64;

const MAC_HEADER_SIZE: usize = 14;
const IPV4_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const BTH_HEADER_SIZE: usize = 12;
const IPV4_UDP_BTH_HEADER_SIZE: usize = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + BTH_HEADER_SIZE;
const AETH_HEADER_SIZE: usize = 4;
const NRETH_HEADER_SIZE: usize = 4;
const ICRC_SIZE: usize = 4;
const ACKPACKET_SIZE_WITHOUT_MAC_AND_IPV4: usize =
    UDP_HEADER_SIZE + BTH_HEADER_SIZE + AETH_HEADER_SIZE + NRETH_HEADER_SIZE + ICRC_SIZE;

const ACKPACKET_SIZE_WITHOUT_MAC: usize = IPV4_HEADER_SIZE + ACKPACKET_SIZE_WITHOUT_MAC_AND_IPV4;

const AUTO_ACK_CODE: u32 = 0;
const AUTO_ACK_VALUE: u32 = 0b0001_1111;

pub(super) fn write_auto_ack(
    buf: &mut [u8],
    src: (MacAddr, Ipv4Addr),
    dst: (MacAddr, Ipv4Addr),
    pkey: u16,
    expected_psn: Psn,
    peer_qp: Qpn,
) {
    let buf = &mut buf[..ACKPACKET_SIZE];
    let (src_mac, src_ip) = src;
    let (dst_mac, dst_ip) = dst;

    {
        let mut eth_header =
            MutableEthernetPacket::new(buf).expect("buffer to small to hold EthernetPacket");
        eth_header.set_ethertype(EtherTypes::Ipv4);
        eth_header.set_source(src_mac);
        eth_header.set_destination(dst_mac);
    }

    {
        let mut ip_header = MutableIpv4Packet::new(&mut buf[PKT_ETH_SIZE..])
            .expect("buffer to small to hold Ipv4Packet");
        ip_header.set_version(IP_VERSION_4);
        ip_header.set_header_length(IPV4_HEADER_LEN_DEAFULT);
        ip_header.set_dscp(0);
        ip_header.set_ecn(0);
        ip_header.set_total_length(ACKPACKET_SIZE_WITHOUT_MAC as u16);
        ip_header.set_identification(0x27);
        ip_header.set_fragment_offset(0);
        ip_header.set_ttl(IPV4_DEFAULT_TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(src_ip);
        ip_header.set_destination(dst_ip);
        ip_header.set_checksum(0);
        let ip_checksum = ip_header.get_checksum();
        ip_header.set_checksum(ip_checksum);
    }
    {
        let mut udp_header = MutableUdpPacket::new(&mut buf[PKT_ETH_SIZE + PKT_IPV4_SIZE..])
            .expect("buffer to small to hold UdpPacket");
        udp_header.set_source(RDMA_DEFAULT_PORT);
        udp_header.set_destination(RDMA_DEFAULT_PORT);
    }
    let mut bth = Bth(&mut buf[PKT_ETH_SIZE + PKT_IPV4_SIZE + PKT_UDP_SIZE..]);
    bth.set_opcode(RdmaOpCode::Acknowledge as u32);
    bth.set_pad_count(0);
    bth.set_pkey(0);
    bth.set_becn(false);
    bth.set_fecn(false);
    bth.set_resv6(0);
    bth.set_dqpn(peer_qp.get());
    bth.set_psn(expected_psn.get());

    let mut aeth = Aeth(&mut buf[PKT_ETH_SIZE + PKT_IPV4_SIZE + PKT_UDP_SIZE + BTH_HEADER_SIZE..]);
    aeth.set_aeth_code(AUTO_ACK_CODE);
    aeth.set_aeth_value(AUTO_ACK_VALUE);
    aeth.set_msn(pkey.into());

    let mut nreth = NReth(
        &mut buf
            [PKT_ETH_SIZE + PKT_IPV4_SIZE + PKT_UDP_SIZE + BTH_HEADER_SIZE + AETH_HEADER_SIZE..],
    );
    nreth.set_last_retry_psn(expected_psn.get());
}
