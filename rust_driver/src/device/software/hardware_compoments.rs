use super::types::{Key, PDHandle};
use crate::types::{MemAccessTypeFlag, Msn, Pmtu, Psn, QpType};
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

#[derive(Debug)]
pub(super) struct ExpectedPsnManager {
    psnStorage: Vec<ExpectedPsnContextEntry>,
}

impl ExpectedPsnManager {
    pub(super) fn new(max_qp: usize) -> Self {
        Self {
            psnStorage: vec![ExpectedPsnContextEntry::new(); max_qp],
        }
    }

    pub(super) fn reset_psn(&mut self, qpn_idx: usize) {
        assert!(qpn_idx < self.psnStorage.len());
        let entry_to_reset = self
            .psnStorage
            .get_mut(qpn_idx)
            .expect("error index to reset expected psn");
        entry_to_reset.expectedPSN = Psn::new(0);
        entry_to_reset.latestErrorPSN = Psn::new(0);
        entry_to_reset.isQpPsnContinous = true;
    }

    pub(super) fn return_to_normal(&mut self, qpn_idx: usize, recovery_point: Psn) {
        assert!(qpn_idx < self.psnStorage.len());
        let entry_to_reset = self
            .psnStorage
            .get_mut(qpn_idx)
            .expect("error index to reset expected psn");
        if recovery_point == entry_to_reset.latestErrorPSN {
            entry_to_reset.isQpPsnContinous = true;
        }
    }

    pub(super) fn check_continous(
        &mut self,
        qpn_idx: usize,
        incoming_psn: Psn,
        packet_abnormal: bool,
    ) -> ExpectedPsnCheckResp {
        let entry_to_reset = self
            .psnStorage
            .get_mut(qpn_idx)
            .expect("error index to reset expected psn");
        if packet_abnormal {
            entry_to_reset.latestErrorPSN = incoming_psn;
            entry_to_reset.isQpPsnContinous = false;
            return ExpectedPsnCheckResp {
                expectedPSN: entry_to_reset.expectedPSN,
                isQpPsnContinous: false,
                isAdjacentPsnContinous: false,
            };
        }
        let diff = incoming_psn
            .wrapping_sub(entry_to_reset.expectedPSN.get())
            .get();
        if diff > PSN_MAX_WINDOW_SIZE {
            return ExpectedPsnCheckResp {
                expectedPSN: entry_to_reset.expectedPSN,
                isQpPsnContinous: entry_to_reset.isQpPsnContinous,
                isAdjacentPsnContinous: false,
            };
        }

        let old_expected_psn = entry_to_reset.expectedPSN;
        entry_to_reset.expectedPSN = incoming_psn.wrapping_add(1);

        let adjacent_continous = incoming_psn == old_expected_psn;
        if !adjacent_continous {
            entry_to_reset.latestErrorPSN = incoming_psn;
            entry_to_reset.isQpPsnContinous = false;
        }

        return ExpectedPsnCheckResp {
            expectedPSN: entry_to_reset.expectedPSN,
            isQpPsnContinous: entry_to_reset.isQpPsnContinous,
            isAdjacentPsnContinous: adjacent_continous,
        };
    }
}

pub(super) struct ExpectedPsnCheckResp {
    pub(super) expectedPSN: Psn,
    pub(super) isQpPsnContinous: bool,
    pub(super) isAdjacentPsnContinous: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ExpectedPsnContextEntry {
    pub(super) expectedPSN: Psn,
    pub(super) latestErrorPSN: Psn,
    pub(super) isQpPsnContinous: bool,
}

impl ExpectedPsnContextEntry {
    fn new() -> Self {
        Self {
            expectedPSN: Psn::new(0),
            latestErrorPSN: Psn::new(0),
            isQpPsnContinous: true,
        }
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
        assert_eq!(resp.expectedPSN, Psn::new(1));
        assert_eq!(resp.isAdjacentPsnContinous, true);
        assert_eq!(resp.isQpPsnContinous, true);

        // sequentially arrive some pkckets
        for _ in 0..50 {
            incoming_psn = incoming_psn.wrapping_add(1);
            let _ = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        }
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, true);
        assert_eq!(resp.isQpPsnContinous, true);

        // an out of order packet
        incoming_psn = incoming_psn.wrapping_add(10);
        let error_point1 = incoming_psn;
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, false);
        assert_eq!(resp.isQpPsnContinous, false);

        // after out of order, arrive a adjacent continous packet
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, true);
        assert_eq!(resp.isQpPsnContinous, false);

        // a abnormal packet should not change anything
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn.wrapping_add(500), true);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, false);
        assert_eq!(resp.isQpPsnContinous, false);

        // another out of order packet
        incoming_psn = incoming_psn.wrapping_add(66);
        let error_point2 = incoming_psn;
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, false);
        assert_eq!(resp.isQpPsnContinous, false);

        // recovery, but not the lastest error point
        expected_psn_panager.return_to_normal(test_qp, error_point1);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, true);
        assert_eq!(resp.isQpPsnContinous, false);

        // recovery, lastest error point, shoule return to normal
        expected_psn_panager.return_to_normal(test_qp, error_point2);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = expected_psn_panager.check_continous(test_qp, incoming_psn, false);
        assert_eq!(resp.expectedPSN, incoming_psn.wrapping_add(1));
        assert_eq!(resp.isAdjacentPsnContinous, true);
        assert_eq!(resp.isQpPsnContinous, true);
    }
}
