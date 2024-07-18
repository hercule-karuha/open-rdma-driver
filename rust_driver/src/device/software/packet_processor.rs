use super::{
    packet::{
        PacketError, RdmaAcknowledgeHeader, RdmaPacketHeader, RdmaReadRequestHeader,
        RdmaReadResponseFirstHeader, RdmaReadResponseLastHeader, RdmaReadResponseMiddleHeader,
        RdmaReadResponseOnlyHeader, RdmaWriteFirstHeader, RdmaWriteLastHeader,
        RdmaWriteLastWithImmediateHeader, RdmaWriteMiddleHeader, RdmaWriteOnlyHeader,
        RdmaWriteOnlyWithImmediateHeader, BTH,
    },
    types::{RdmaMessage, RdmaOpCode},
};
use eui48::MacAddress;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use std::net::Ipv4Addr;
use thiserror::Error;

use super::packet::{
    ICRC_SIZE, IPV4_DEFAULT_DSCP_AND_ECN, IPV4_DEFAULT_TTL, IPV4_DEFAULT_VERSION_AND_HEADER_LENGTH,
    IPV4_PROTOCOL_UDP, IPV4_UDP_BTH_HEADER_SIZE, MAC_SERVICE_LAYER_IPV4, RDMA_DEFAULT_PORT,
};
use crate::device::layout::{Ipv4, Mac, Udp};
use crate::device::layout::{IPV4_HEADER_SIZE, MAC_HEADER_SIZE, UDP_HEADER_SIZE};

const IP_VERSION_4: u8 = 4;
const IPV4_HEADER_LEN_DEAFULT: u8 = 5;

pub(crate) struct PacketProcessor;

impl PacketProcessor {
    pub(crate) fn to_rdma_message(buf: &[u8]) -> Result<RdmaMessage, PacketError> {
        let opcode = RdmaOpCode::try_from(BTH::from_bytes(buf).get_opcode());
        match opcode {
            Ok(RdmaOpCode::RdmaWriteFirst) => {
                let header = RdmaWriteFirstHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaWriteMiddle) => {
                let header = RdmaWriteMiddleHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaWriteLast) => {
                let header = RdmaWriteLastHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaWriteLastWithImmediate) => {
                let header = RdmaWriteLastWithImmediateHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaWriteOnly) => {
                let header = RdmaWriteOnlyHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaWriteOnlyWithImmediate) => {
                let header = RdmaWriteOnlyWithImmediateHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaReadRequest) => {
                let header = RdmaReadRequestHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaReadResponseFirst) => {
                let header = RdmaReadResponseFirstHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaReadResponseMiddle) => {
                let header = RdmaReadResponseMiddleHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaReadResponseLast) => {
                let header = RdmaReadResponseLastHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::RdmaReadResponseOnly) => {
                let header = RdmaReadResponseOnlyHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            Ok(RdmaOpCode::Acknowledge) => {
                let header = RdmaAcknowledgeHeader::from_bytes(buf);
                Ok(header.to_rdma_message(buf.len())?)
            }
            _ => Err(PacketError::InvalidOpcode),
        }
    }

    pub(crate) fn set_from_rdma_message(
        buf: &mut [u8],
        message: &RdmaMessage,
    ) -> Result<usize, PacketError> {
        match message.meta_data.get_opcode() {
            RdmaOpCode::RdmaWriteFirst => {
                let header = RdmaWriteFirstHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaWriteMiddle => {
                let header = RdmaWriteMiddleHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaWriteLast => {
                let header = RdmaWriteLastHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaWriteLastWithImmediate => {
                let header = RdmaWriteLastWithImmediateHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaWriteOnly => {
                let header = RdmaWriteOnlyHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaWriteOnlyWithImmediate => {
                let header = RdmaWriteOnlyWithImmediateHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaReadRequest => {
                let header = RdmaReadRequestHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaReadResponseFirst => {
                let header = RdmaReadResponseFirstHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaReadResponseMiddle => {
                let header = RdmaReadResponseMiddleHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaReadResponseLast => {
                let header = RdmaReadResponseLastHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::RdmaReadResponseOnly => {
                let header = RdmaReadResponseOnlyHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            RdmaOpCode::Acknowledge => {
                let header = RdmaAcknowledgeHeader::from_bytes(buf);
                Ok(header.set_from_rdma_message(message)?)
            }
            _ => Err(PacketError::InvalidOpcode),
        }
    }
}

#[allow(variant_size_differences)]
#[derive(Error, Debug)]
pub(crate) enum PacketProcessorError {
    #[error("missing src_mac")]
    MissingSrcMac,
    #[error("missing src_addr")]
    MissingSrcAddr,
    #[error("missing src_port")]
    MissingSrcPort,
    #[error("missing dest_mac")]
    MissingDestMac,
    #[error("missing dest_addr")]
    MissingDestAddr,
    #[error("missing dest_port")]
    MissingDestPort,
    #[error("missing message")]
    MissingMessage,
    #[error("missing ip identification")]
    MissingIpId,
    #[error("Needs a buffer of at least {0} bytes")]
    BufferNotLargeEnough(usize),
    #[error("packet error")]
    PacketError(#[from] PacketError),
    #[error("Length too long :{0}")]
    LengthTooLong(usize),
}

/// A builder for writing a packet
pub(crate) struct PacketWriter<'buf, 'message> {
    buf: &'buf mut [u8],
    src_mac: Option<MacAddr>,
    src_addr: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dest_mac: Option<MacAddr>,
    dest_addr: Option<Ipv4Addr>,
    dest_port: Option<u16>,
    message: Option<&'message RdmaMessage>,
    ip_id: Option<u16>,
}

impl<'buf, 'message> PacketWriter<'buf, 'message> {
    pub(crate) fn new(buf: &'buf mut [u8]) -> Self {
        Self {
            buf,
            src_mac: None,
            src_addr: None,
            src_port: None,
            dest_mac: None,
            dest_addr: None,
            dest_port: None,
            message: None,
            ip_id: None,
        }
    }

    pub(crate) fn src_mac(&mut self, mac: MacAddress) -> &mut Self {
        let new = self;
        new.src_mac = Some(MacAddr::from(mac.to_array()));
        new
    }

    pub(crate) fn src_addr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let new = self;
        new.src_addr = Some(addr);
        new
    }

    pub(crate) fn src_port(&mut self, port: u16) -> &mut Self {
        let new = self;
        new.src_port = Some(port);
        new
    }

    pub(crate) fn dest_mac(&mut self, mac: MacAddress) -> &mut Self {
        let new = self;
        new.dest_mac = Some(MacAddr::from(mac.to_array()));
        new
    }

    pub(crate) fn dest_addr(&mut self, addr: Ipv4Addr) -> &mut Self {
        let new = self;
        new.dest_addr = Some(addr);
        new
    }

    pub(crate) fn dest_port(&mut self, port: u16) -> &mut Self {
        let new = self;
        new.dest_port = Some(port);
        new
    }

    pub(crate) fn ip_id(&mut self, id: u16) -> &mut Self {
        let new = self;
        new.ip_id = Some(id);
        new
    }

    pub(crate) fn message(&mut self, message: &'message RdmaMessage) -> &mut Self {
        let new = self;
        new.message = Some(message);
        new
    }

    pub(crate) fn write(&mut self) -> Result<usize, PacketProcessorError> {
        // advance `size_of::<IpUdpHeaders>()` to write the rdma header
        let net_header_size = IPV4_HEADER_SIZE + UDP_HEADER_SIZE;
        let message = self.message.ok_or(PacketProcessorError::MissingMessage)?;
        // write the rdma header
        let rdma_header_buf = self
            .buf
            .get_mut(net_header_size..)
            .ok_or(PacketProcessorError::BufferNotLargeEnough(net_header_size))?;
        let rdma_header_length = PacketProcessor::set_from_rdma_message(rdma_header_buf, message)?;

        // get the total length(include the ip,udp header and the icrc)
        let total_length = net_header_size
            + rdma_header_length
            + rdma_header_length
            + message.payload.with_pad_length()
            + ICRC_SIZE;
        let total_length_in_u16 = u16::try_from(total_length)
            .map_err(|_| PacketProcessorError::LengthTooLong(total_length))?;

        // write the payload
        let header_offset = net_header_size + rdma_header_length;
        let header_buf = self
            .buf
            .get_mut(header_offset..)
            .ok_or(PacketProcessorError::BufferNotLargeEnough(net_header_size))?;
        message.payload.copy_to(header_buf.as_mut_ptr());

        // write the ip,udp header
        let ip_id = self.ip_id.ok_or(PacketProcessorError::MissingIpId)?;
        let src_mac = self.src_mac.ok_or(PacketProcessorError::MissingSrcMac)?;
        let src_addr = self.src_addr.ok_or(PacketProcessorError::MissingSrcAddr)?;
        let src_port = self.src_port.ok_or(PacketProcessorError::MissingSrcPort)?;
        let dest_mac = self.src_mac.ok_or(PacketProcessorError::MissingDestMac)?;
        let dest_addr = self
            .dest_addr
            .ok_or(PacketProcessorError::MissingDestAddr)?;
        let dest_port = self
            .dest_port
            .ok_or(PacketProcessorError::MissingDestPort)?;
        write_network_header(
            self.buf,
            src_mac,
            src_addr,
            src_port,
            dest_mac,
            dest_addr,
            dest_port,
            total_length_in_u16,
            ip_id,
        );
        // compute icrc
        let icrc_buf = self
            .buf
            .get(MAC_HEADER_SIZE..total_length)
            .ok_or(PacketProcessorError::BufferNotLargeEnough(total_length))?;
        if total_length < ICRC_SIZE {
            return Err(PacketProcessorError::BufferNotLargeEnough(ICRC_SIZE));
        }
        let icrc = compute_icrc(icrc_buf).to_le_bytes();
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        // we have checked it is large enough
        self.buf[total_length - ICRC_SIZE..total_length].copy_from_slice(&icrc);
        Ok(total_length)
    }
}

/// Assume the buffer is a packet, compute the icrc
/// Return a u32 of the icrc
///
/// # Panic
/// The function made an assumption that the buffer is a valid RDMA packet, in other words,
/// it should at least contain the common header, ip header, udp header, bth header and the icrc.
#[allow(clippy::indexing_slicing)]
pub(crate) fn compute_icrc(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    let prefix = [0xffu8; 8];
    let mut buf = [0; IPV4_UDP_BTH_HEADER_SIZE];
    hasher.update(&prefix);

    buf.copy_from_slice(data[..IPV4_UDP_BTH_HEADER_SIZE].as_ref());
    let mut ip_header = Ipv4(&mut buf);
    ip_header.set_dscp_ecn(0xff);
    ip_header.set_ttl(0xff);
    ip_header.set_checksum(0xffff);

    let mut udp_header = Udp(&mut buf[IPV4_HEADER_SIZE..]);
    udp_header.set_checksum(0xffff);

    let bth_header = BTH::from_bytes(&mut buf[IPV4_HEADER_SIZE + UDP_HEADER_SIZE..]);
    bth_header.fill_ecn_and_resv6();

    hasher.update(&buf);
    // the rest of header and payload
    #[allow(clippy::arithmetic_side_effects)]
    hasher.update(&data[IPV4_UDP_BTH_HEADER_SIZE..data.len() - ICRC_SIZE]);
    hasher.finalize()
}

/// Write the mac, ip and udp header to the buffer
///
/// # Panic
/// the buffer should be large enough to hold the mac, ip and udp header
pub(crate) fn write_network_header(
    buf: &mut [u8],
    src_mac: MacAddr,
    src_addr: Ipv4Addr,
    src_port: u16,
    dest_mac: MacAddr,
    dest_addr: Ipv4Addr,
    dest_port: u16,
    total_length: u16,
    ip_identification: u16,
) {
    {
        let mut eth_header =
            MutableEthernetPacket::new(buf).expect("buffer to small to hold EthernetPacket");
        eth_header.set_ethertype(EtherTypes::Ipv4);
        eth_header.set_source(src_mac);
        eth_header.set_destination(dest_mac);
    }

    {
        let mut ip_header = MutableIpv4Packet::new(&mut buf[MAC_HEADER_SIZE..])
            .expect("buffer to small to hold Ipv4Packet");
        ip_header.set_version(IP_VERSION_4);
        ip_header.set_header_length(IPV4_HEADER_LEN_DEAFULT);
        ip_header.set_dscp(0);
        ip_header.set_ecn(0);
        ip_header.set_total_length(total_length);
        ip_header.set_identification(ip_identification);
        ip_header.set_fragment_offset(0);
        ip_header.set_ttl(IPV4_DEFAULT_TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(src_addr);
        ip_header.set_destination(dest_addr);
        ip_header.set_checksum(0);
        let ip_checksum = ip_header.get_checksum();
        ip_header.set_checksum(ip_checksum);
    }
    {
        let mut udp_header = MutableUdpPacket::new(&mut buf[MAC_HEADER_SIZE + IPV4_HEADER_SIZE..])
            .expect("buffer to small to hold UdpPacket");
        udp_header.set_source(src_port);
        udp_header.set_destination(dest_port);
        udp_header.set_checksum(0);
    }
}

/// Assume the buffer is a packet, check if the icrc is valid
/// Return a bool if the icrc is valid
///
/// # Panic
/// The function made an assumption that the buffer is a valid RDMA packet, in other words,
/// it should at least contain the common header, ip header, udp header, bth header and the icrc.
#[allow(clippy::indexing_slicing)]
pub(crate) fn is_icrc_valid(data: &mut [u8]) -> Result<bool, PacketProcessorError> {
    let length = data.len();
    // chcek the icrc
    let icrc_array: [u8; 4] = match data[length.wrapping_sub(ICRC_SIZE)..length].try_into()
    {
        Ok(arr) => arr,
        #[allow(clippy::cast_possible_truncation)]
        Err(_) => return Err(PacketProcessorError::BufferNotLargeEnough(ICRC_SIZE)),
    };
    let origin_icrc = u32::from_le_bytes(icrc_array);
    data[length.wrapping_sub(ICRC_SIZE)..length].copy_from_slice(&[0u8; 4]);
    let our_icrc = compute_icrc(data);
    Ok(our_icrc == origin_icrc)
}

/// Check if the packet is a vaild rdma packet
/// Return a bool if the the packet is a vaild rdma packet
pub(crate) fn check_rdma_pkt(data: &[u8]) -> bool {
    let Some(mac_header) = EthernetPacket::new(data) else {
        return false;
    };
    if mac_header.get_ethertype() != EtherTypes::Ipv4 {
        return false;
    }

    let Some(ipv4_header) = Ipv4Packet::new(&data[MAC_HEADER_SIZE..]) else {
        return false;
    };
    if ipv4_header.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return false;
    }

    let Some(udp_header) = UdpPacket::new(&data[MAC_HEADER_SIZE + IPV4_HEADER_SIZE..])
    else {
        return false;
    };
    if udp_header.get_destination() != RDMA_DEFAULT_PORT {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use crate::device::layout::{Ipv4, Mac, Udp};
    use crate::device::software::packet::{
        IPV4_HEADER_SIZE, IPV4_PROTOCOL_UDP, MAC_HEADER_SIZE, MAC_SERVICE_LAYER_IPV4,
        RDMA_DEFAULT_PORT, UDP_HEADER_SIZE,
    };
    use crate::device::software::packet_processor::{check_rdma_pkt, compute_icrc};

    #[test]
    fn test_computing_icrc() {
        // The buffer is a packet in hex format:
        // IP(id=54321, frag=0,protocol= \
        //     ttl=128, dst="127.0.0.1", src="127.0.0.1", len=108)/ \
        //     UDP(sport=49152, dport=4791, len=88)/ \
        //     BTH(opcode='RC_RDMA_WRITE_MIDDLE',pkey=0x1, dqpn=3, psn=0)/ \
        //     Raw(bytes([0]*64))
        let buf = [
            0x45, 0x00, 0x00, 0xbc, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf8, 0xda, 0xc0, 0xa8,
            0x00, 0x02, 0xc0, 0xa8, 0x00, 0x03, 0x12, 0xb7, 0x12, 0xb7, 0x00, 0xa8, 0x00, 0x00,
            0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x7f, 0x7e, 0x91, 0x00, 0x00, 0x00, 0x01, 0x70, 0x9a, 0x33, 0x00, 0x00, 0x00, 0x80,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xc6, 0x87, 0x22, 0x98,
        ];
        let icrc = compute_icrc(&buf);
        assert!(
            icrc == u32::from_le_bytes([0xc6, 0x87, 0x22, 0x98]),
            "icrc: {:x}",
            icrc
        );

        let buf = [
            69, 0, 0, 0, 0, 0, 0, 0, 64, 17, 124, 232, 127, 0, 0, 3, 127, 0, 0, 2, 18, 183, 18,
            183, 0, 32, 0, 0, 17, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        let icrc = compute_icrc(&buf);
        assert_eq!(icrc, u32::from_le_bytes([64, 33, 163, 207]));
    }

    #[test]
    fn test_check_rdma_pkt() {
        // Test case 1: Valid RDMA packet
        let mut packet1: [u8; 100] = [0; 100];

        let mut mac_header = Mac(&mut packet1);
        mac_header.set_network_layer_type(MAC_SERVICE_LAYER_IPV4.into());

        let mut ipv4_header = Ipv4(&mut packet1[MAC_HEADER_SIZE..]);
        ipv4_header.set_protocol(IPV4_PROTOCOL_UDP.into());

        let mut udp_header = Udp(&mut packet1[MAC_HEADER_SIZE + IPV4_HEADER_SIZE..]);
        udp_header.set_dst_port(RDMA_DEFAULT_PORT);

        assert_eq!(check_rdma_pkt(&packet1), true);

        // Test case 2: small size
        let mut packet2: [u8; MAC_HEADER_SIZE] = [0; MAC_HEADER_SIZE];
        let mut mac_header = Mac(&mut packet2);
        mac_header.set_network_layer_type(MAC_SERVICE_LAYER_IPV4.into());
        assert_eq!(check_rdma_pkt(&packet2), false);

        // Test case 3: small size
        let mut packet3: [u8; MAC_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE] =
            [0; MAC_HEADER_SIZE + IPV4_HEADER_SIZE + UDP_HEADER_SIZE];
        let mut mac_header = Mac(&mut packet3);
        mac_header.set_network_layer_type(0xff);
        assert_eq!(check_rdma_pkt(&packet2), false);
    }
}
