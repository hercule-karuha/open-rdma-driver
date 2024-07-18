use super::packet::BTH;
use super::types::{Key, PDHandle, Psn, Qpn, RdmaOpCode};
use crate::types::{MemAccessTypeFlag, Pmtu, QpType};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    usize,
};

#[derive(Debug, Clone)]
pub(super) struct QpTableEntry {
    pub(super) qp_context: QpContext,
    pub(super) expected_psn_context: ExpectedPsnContext,
}
impl QpTableEntry {
    fn new() -> Self {
        Self {
            qp_context: QpContext::new(),
            expected_psn_context: ExpectedPsnContext::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct QpContext {
    pub(super) pmtu: Pmtu,
    pub(super) qp_type: QpType,
    pub(super) qp_access_flags: MemAccessTypeFlag,
    pub(super) peer_qp: Qpn,
    pub(super) pdkey: PDHandle,
}

impl QpContext {
    fn new() -> Self {
        Self {
            pmtu: Pmtu::Mtu256,
            qp_type: QpType::Rc,
            qp_access_flags: MemAccessTypeFlag::empty(),
            peer_qp: Qpn::new(0),
            pdkey: PDHandle::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExpectedPsnContext {
    expected_psn: Psn,
    latest_error_psn: Psn,
    is_qp_psn_continous: bool,
}

impl ExpectedPsnContext {
    fn new() -> Self {
        Self {
            expected_psn: Psn::new(0),
            latest_error_psn: Psn::new(0),
            is_qp_psn_continous: true,
        }
    }
}

pub(super) struct ExpectedPsnCheckResp {
    pub(super) expected_psn: Psn,
    pub(super) is_qp_psn_continous: bool,
    pub(super) is_adjacent_psn_continous: bool,
}

#[derive(Debug)]
pub(super) struct QpTable {
    qpe_storage: Vec<QpTableEntry>,
}

impl QpTable {
    pub(super) fn new(max_qp: usize) -> Self {
        Self {
            qpe_storage: vec![QpTableEntry::new(); max_qp],
        }
    }

    pub(super) fn set_qp(&mut self, qp_idx: Qpn, qp_context: QpContext) -> bool {
        let existing_entry = match self.qpe_storage.get_mut(qp_idx.to_idx()) {
            Some(entry) => entry,
            None => {
                return false;
            }
        };
        *existing_entry = QpTableEntry {
            qp_context: qp_context,
            expected_psn_context: ExpectedPsnContext::new(),
        };
        true
    }

    pub(super) fn reset_qp(&mut self, qp_idx: Qpn) -> bool {
        let existing_entry = match self.qpe_storage.get_mut(qp_idx.to_idx()) {
            Some(entry) => entry,
            None => {
                return false;
            }
        };
        *existing_entry = QpTableEntry {
            qp_context: QpContext::new(),
            expected_psn_context: ExpectedPsnContext::new(),
        };
        true
    }

    pub(super) fn get_qp_context(&self, qp_idx: Qpn) -> Option<QpContext> {
        self.qpe_storage
            .get(qp_idx.to_idx())
            .map(|entry| entry.qp_context.clone())
    }

    pub(super) fn recovery_qp(&mut self, qp_idx: Qpn, recovery_point: Psn) -> bool {
        let qp_entry = match self.qpe_storage.get_mut(qp_idx.to_idx()) {
            Some(entry) => entry,
            None => {
                return false;
            }
        };
        if recovery_point == qp_entry.expected_psn_context.latest_error_psn {
            qp_entry.expected_psn_context.is_qp_psn_continous = true;
        }
        true
    }

    pub(super) fn check_continous(
        &mut self,
        qp_idx: Qpn,
        incoming_psn: Psn,
        packet_abnormal: bool,
    ) -> Option<ExpectedPsnCheckResp> {
        let expected_psn_context = match self.qpe_storage.get_mut(qp_idx.to_idx()) {
            Some(entry) => &mut entry.expected_psn_context,
            None => {
                return None;
            }
        };
        // if previous failed should return false directly without modify anything
        if packet_abnormal {
            expected_psn_context.latest_error_psn = incoming_psn;
            expected_psn_context.is_qp_psn_continous = false;
            return Some(ExpectedPsnCheckResp {
                expected_psn: expected_psn_context.expected_psn,
                is_qp_psn_continous: false,
                is_adjacent_psn_continous: false,
            });
        }

        // if the psn is lower than expected psn, shouldn't modify theexpected psn
        if incoming_psn.larger_in_psn(expected_psn_context.expected_psn) {
            return Some(ExpectedPsnCheckResp {
                expected_psn: expected_psn_context.expected_psn,
                is_qp_psn_continous: expected_psn_context.is_qp_psn_continous,
                is_adjacent_psn_continous: false,
            });
        }

        let old_expected_psn = expected_psn_context.expected_psn;
        expected_psn_context.expected_psn = incoming_psn.wrapping_add(1);

        let adjacent_continous = incoming_psn == old_expected_psn;
        if !adjacent_continous {
            expected_psn_context.latest_error_psn = incoming_psn;
            expected_psn_context.is_qp_psn_continous = false;
        }

        return Some(ExpectedPsnCheckResp {
            expected_psn: expected_psn_context.expected_psn,
            is_qp_psn_continous: expected_psn_context.is_qp_psn_continous,
            is_adjacent_psn_continous: adjacent_continous,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::QpTable;
    use crate::device::software::qp_table::QpContext;
    use crate::device::software::types::{Psn, Qpn};

    #[test]
    fn test_expected_psn_panager() {
        let mut qp_table = QpTable::new(256);
        let test_qp = Qpn::new(114);
        let mut incoming_psn = Psn::new(0);

        // first packet arrive, should be ok
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, Psn::new(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // sequentially arrive some pkckets
        for _ in 0..50 {
            incoming_psn = incoming_psn.wrapping_add(1);
            let _ = qp_table.check_continous(test_qp, incoming_psn, false);
        }
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // an out of order packet
        incoming_psn = incoming_psn.wrapping_add(10);
        let error_point1 = incoming_psn;
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // after out of order, arrive a adjacent continous packet
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, false);

        // a abnormal packet should not change anything
        let resp = qp_table
            .check_continous(test_qp, incoming_psn.wrapping_add(500), true)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // another out of order packet
        incoming_psn = incoming_psn.wrapping_add(66);
        let error_point2 = incoming_psn;
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, false);
        assert_eq!(resp.is_qp_psn_continous, false);

        // recovery, but not the lastest error point
        qp_table.recovery_qp(test_qp, error_point1);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, false);

        // recovery, lastest error point, shoule return to normal
        qp_table.recovery_qp(test_qp, error_point2);
        incoming_psn = incoming_psn.wrapping_add(1);
        let resp = qp_table
            .check_continous(test_qp, incoming_psn, false)
            .unwrap();
        assert_eq!(resp.expected_psn, incoming_psn.wrapping_add(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);

        // test reset
        let qp_context_empty = QpContext::new();
        qp_table.set_qp(test_qp, qp_context_empty);
        let resp = qp_table
            .check_continous(test_qp, Psn::new(0), false)
            .unwrap();
        assert_eq!(resp.expected_psn, Psn::new(1));
        assert_eq!(resp.is_adjacent_psn_continous, true);
        assert_eq!(resp.is_qp_psn_continous, true);
    }
}
