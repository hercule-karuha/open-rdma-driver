use super::packet::BTH;
use super::types::{Key, PDHandle, RdmaOpCode};
use crate::types::{MemAccessTypeFlag, Pmtu, Psn, QpType};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    usize,
};

const RAW_PKT_BLOCK_SIZE: usize = 4096;
const PSN_MAX_WINDOW_SIZE: u32 = 1 << 23_i32;

/// The hardware queue pair context
#[derive(Debug)]
pub(super) struct QueuePair {
    pub(super) inner: QueuePairInner,
}

#[derive(Debug, Clone)]
pub(super) struct QueuePairInner {
    pub(super) pmtu: Pmtu,
    pub(super) qp_type: QpType,
    pub(super) qp_access_flags: MemAccessTypeFlag,
    pub(super) pdkey: PDHandle,
}

/// The hardware memory region context
#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct MemoryRegion {
    pub(super) key: Key,
    pub(super) acc_flags: MemAccessTypeFlag,
    pub(super) pdkey: PDHandle,
    pub(super) addr: u64,
    pub(super) len: usize,
    pub(super) pgt_offset: u32,
}

/// Store the config information for raw packets
#[derive(Debug)]
pub(super) struct RawPktConfig {
    raw_pkt_base_addr: AtomicUsize,
    raw_pkt_buf_idx: AtomicUsize,
}

impl RawPktConfig {
    pub(super) fn new() -> Self {
        RawPktConfig {
            raw_pkt_base_addr: AtomicUsize::new(0),
            raw_pkt_buf_idx: AtomicUsize::new(0),
        }
    }

    pub(super) fn get_write_addr(&self) -> usize {
        let base = self.raw_pkt_base_addr.load(Ordering::Acquire);
        let idx = self.raw_pkt_buf_idx.load(Ordering::Acquire);
        self.raw_pkt_buf_idx.store(idx + 1, Ordering::Release);
        base + (idx * RAW_PKT_BLOCK_SIZE)
    }

    pub(super) fn set_base_addr(&self, base: usize) {
        self.raw_pkt_base_addr.store(base, Ordering::Release);
    }
}

/// a software simulation of ExpectedPsnManager in blue-rdma
/// used to check the psn continous
#[derive(Debug)]
pub(super) struct ExpectedPsnManager {
    psn_storage: Vec<ExpectedPsnContextEntry>,
}

impl ExpectedPsnManager {
    pub(super) fn new(max_qp: usize) -> Self {
        Self {
            psn_storage: vec![ExpectedPsnContextEntry::new(); max_qp],
        }
    }

    pub(super) fn reset_psn(&mut self, qpn_idx: usize) {
        assert!(qpn_idx < self.psn_storage.len());
        let entry_to_reset = self
            .psn_storage
            .get_mut(qpn_idx)
            .expect("index error for ExpectedPsnManager");
        entry_to_reset.expected_psn = Psn::new(0);
        entry_to_reset.latest_error_psn = Psn::new(0);
        entry_to_reset.is_qp_psn_continous = true;
    }

    pub(super) fn recovery_qp(&mut self, qpn_idx: usize, recovery_point: Psn) {
        assert!(qpn_idx < self.psn_storage.len());
        let entry_to_reset = self
            .psn_storage
            .get_mut(qpn_idx)
            .expect("index error for ExpectedPsnManager");
        if recovery_point == entry_to_reset.latest_error_psn {
            entry_to_reset.is_qp_psn_continous = true;
        }
    }

    pub(super) fn check_continous(
        &mut self,
        qpn_idx: usize,
        incoming_psn: Psn,
        packet_abnormal: bool,
    ) -> ExpectedPsnCheckResp {
        assert!(qpn_idx < self.psn_storage.len());
        let entry_to_reset = self
            .psn_storage
            .get_mut(qpn_idx)
            .expect("index error for ExpectedPsnManager");
        // if previous failed should return false directly without modify anything
        if packet_abnormal {
            entry_to_reset.latest_error_psn = incoming_psn;
            entry_to_reset.is_qp_psn_continous = false;
            return ExpectedPsnCheckResp {
                expected_psn: entry_to_reset.expected_psn,
                is_qp_psn_continous: false,
                is_adjacent_psn_continous: false,
            };
        }

        // if the psn is lower than expected psn, shouldn't modify theexpected psn
        let diff = incoming_psn
            .wrapping_sub(entry_to_reset.expected_psn.get())
            .get();
        if diff > PSN_MAX_WINDOW_SIZE {
            return ExpectedPsnCheckResp {
                expected_psn: entry_to_reset.expected_psn,
                is_qp_psn_continous: entry_to_reset.is_qp_psn_continous,
                is_adjacent_psn_continous: false,
            };
        }

        let old_expected_psn = entry_to_reset.expected_psn;
        entry_to_reset.expected_psn = incoming_psn.wrapping_add(1);

        let adjacent_continous = incoming_psn == old_expected_psn;
        if !adjacent_continous {
            entry_to_reset.latest_error_psn = incoming_psn;
            entry_to_reset.is_qp_psn_continous = false;
        }

        return ExpectedPsnCheckResp {
            expected_psn: entry_to_reset.expected_psn,
            is_qp_psn_continous: entry_to_reset.is_qp_psn_continous,
            is_adjacent_psn_continous: adjacent_continous,
        };
    }
}

pub(super) struct ExpectedPsnCheckResp {
    pub(super) expected_psn: Psn,
    pub(super) is_qp_psn_continous: bool,
    pub(super) is_adjacent_psn_continous: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ExpectedPsnContextEntry {
    pub(super) expected_psn: Psn,
    pub(super) latest_error_psn: Psn,
    pub(super) is_qp_psn_continous: bool,
}

impl ExpectedPsnContextEntry {
    fn new() -> Self {
        Self {
            expected_psn: Psn::new(0),
            latest_error_psn: Psn::new(0),
            is_qp_psn_continous: true,
        }
    }
}

// /// do bth zero field check and pad count check
pub (super) fn header_pre_check(data: &[u8]) -> bool {
    let bth = BTH::from_bytes(data);
    let zero_fields_check = (bth.get_tver() == 0)
        && (bth.get_becn() == 0)
        && (bth.get_fecn() == 0)
        && (bth.get_resv6() == 0)
        && (bth.get_resv7() == 0);
    if !zero_fields_check {
        return false;
    }

    let opcode = match RdmaOpCode::try_from(bth.get_opcode()) {
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
        | RdmaOpCode::FetchAdd => bth.get_pad_cnt() == 0,

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

        _ => false,
    }
}

pub (super) fn check_opcode_supported(qp_type: &QpType, opcode: &RdmaOpCode) -> bool {
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

#[cfg(test)]
mod tests {
    use crate::types::Psn;

    use super::ExpectedPsnManager;

    #[test]
    fn test_expected_psn_panager() {
        let mut expected_psn_panager = ExpectedPsnManager::new(256);
        let test_qp = 114;
        let mut incoming_psn = Psn::new(0);

        // first packet arrive, should be ok
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, Psn::new(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // sequentially arrive some pkckets
        for _ in 0..50 {
            incoming_psn = incoming_psn.wrapping_add(1);
            let _ = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        }
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // an out of order packet
        incoming_psn = incoming_psn.wrapping_add(10);
        let error_point1 = incoming_psn;
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // after out of order, arrive a adjacent continous packet
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, false);

        // a abnormal packet should not change anything
        let resp =
            expected_psn_panager.check_continous(test_qp, incoming_psn.wrapping_add(500), true);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // another out of order packet
        incoming_psn = incoming_psn.wrapping_add(66);
        let error_point2 = incoming_psn;
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // recovery, but not the lastest error point
        expected_psn_panager.recovery_qp(test_qp, error_point1);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, false);

        // recovery, lastest error point, shoule return to normal
        expected_psn_panager.recovery_qp(test_qp, error_point2);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // test reset
        expected_psn_panager.reset_psn(test_qp);
        let resp = expected_psn_panager.check_continous(test_qp, Psn::new(0), false);
        assert_eq!(resp.expected_psn, Psn::new(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);
    }
}
