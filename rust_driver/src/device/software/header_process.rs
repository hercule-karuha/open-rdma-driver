use std::net::Ipv4Addr;

use eui48::MacAddress;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;

use super::packet::BTH_HEADER_SIZE;
use super::types::{Key, PDHandle, RdmaOpCode};
use crate::device::layout::{Aeth, Bth, MAC_HEADER_SIZE};
use crate::types::QpType;

/// do bth zero field check and pad count check
pub(super) fn header_pre_check(data: &[u8]) -> bool {
    let bth = Bth(data);
    let zero_fields_check = (bth.get_tver() == 0)
        && (!bth.get_becn())
        && (!bth.get_fecn())
        && (bth.get_resv6() == 0)
        && (bth.get_resv7() == 0);
    if !zero_fields_check {
        return false;
    }

    let opcode = match RdmaOpCode::try_from(bth.get_opcode() as u8) {
        Ok(opcode) => opcode,
        Err(_) => {
            return false;
        }
    };
    match opcode {
        RdmaOpCode::SendMiddle
        | RdmaOpCode::RdmaWriteMiddle
        | RdmaOpCode::RdmaReadRequest
        | RdmaOpCode::CompareSwap
        | RdmaOpCode::FetchAdd => bth.get_pad_count() == 0,

        RdmaOpCode::SendFirst
        | RdmaOpCode::SendLast
        | RdmaOpCode::SendOnly
        | RdmaOpCode::SendOnlyWithImmediate
        | RdmaOpCode::SendLastWithImmediate
        | RdmaOpCode::SendLastWithInvalidate
        | RdmaOpCode::SendOnlyWithInvalidate
        | RdmaOpCode::RdmaWriteFirst
        | RdmaOpCode::RdmaWriteLast
        | RdmaOpCode::RdmaWriteOnly
        | RdmaOpCode::RdmaWriteLastWithImmediate
        | RdmaOpCode::RdmaWriteOnlyWithImmediate => true,

        RdmaOpCode::RdmaReadResponseMiddle => bth.get_pad_count() == 0,

        _ => false,
    }
}

pub(super) fn check_opcode_supported(qp_type: &QpType, opcode: &RdmaOpCode) -> bool {
    match qp_type {
        QpType::Rc => match opcode {
            RdmaOpCode::SendFirst
            | RdmaOpCode::SendMiddle
            | RdmaOpCode::SendLast
            | RdmaOpCode::SendLastWithImmediate
            | RdmaOpCode::SendOnly
            | RdmaOpCode::SendOnlyWithImmediate
            | RdmaOpCode::SendLastWithInvalidate
            | RdmaOpCode::SendOnlyWithInvalidate
            | RdmaOpCode::RdmaWriteFirst
            | RdmaOpCode::RdmaWriteMiddle
            | RdmaOpCode::RdmaWriteLast
            | RdmaOpCode::RdmaWriteLastWithImmediate
            | RdmaOpCode::RdmaWriteOnly
            | RdmaOpCode::RdmaWriteOnlyWithImmediate
            | RdmaOpCode::RdmaReadRequest
            | RdmaOpCode::RdmaReadResponseFirst
            | RdmaOpCode::RdmaReadResponseMiddle
            | RdmaOpCode::RdmaReadResponseLast
            | RdmaOpCode::RdmaReadResponseOnly
            | RdmaOpCode::Acknowledge
            | RdmaOpCode::AtomicAcknowledge
            | RdmaOpCode::CompareSwap
            | RdmaOpCode::FetchAdd => true,
            _ => false,
        },
        _ => false,
    }
}

pub(super) fn extract_mac_and_ip(data: &[u8]) -> (MacAddr, Ipv4Addr) {
    let Some(mac_header) = EthernetPacket::new(data) else {
        return (MacAddr::zero(), Ipv4Addr::new(0, 0, 0, 0));
    };
    let mac = mac_header.get_source();
    let Some(ip_header) = Ipv4Packet::new(&data[MAC_HEADER_SIZE..]) else {
        return (MacAddr::zero(), Ipv4Addr::new(0, 0, 0, 0));
    };
    let ip = ip_header.get_source();
    (mac, ip)
}
