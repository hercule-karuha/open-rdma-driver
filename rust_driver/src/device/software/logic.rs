use super::{
    header_check::*,
    net_agent::{NetAgentError, NetReceiveLogic, NetSendAgent, NET_SERVER_BUF_SIZE},
    packet::RDMA_DEFAULT_PORT,
    packet_processor::{PacketProcessor, PacketWriter},
    qp_table::*,
    types::{
        Key, Metadata, PDHandle, PKey, PayloadInfo, Psn, Qpn, RdmaGeneralMeta, RdmaMessage,
        RdmaMessageMetaCommon, RdmaOpCode, RdmaReqStatus, RethHeader, ToCardDescriptor,
        ToCardReadDescriptor, ToCardWriteDescriptor,
    },
};
use crate::unsafe_tools::{get_raw_pkt_buf, RAW_PKT_BLOCK_SIZE, RAW_PKT_SLOT_NUM};
use crate::{
    device::{
        CtrlRbDescOpcode, ToCardCtrlRbDesc, ToCardWorkRbDesc, ToHostCtrlRbDesc,
        ToHostCtrlRbDescCommon, ToHostWorkRbDesc, ToHostWorkRbDescAck, ToHostWorkRbDescAethCode,
        ToHostWorkRbDescCommon, ToHostWorkRbDescRead, ToHostWorkRbDescStatus,
        ToHostWorkRbDescTransType, ToHostWorkRbDescWriteOrReadResp, ToHostWorkRbDescWriteType,
        ToHostWorkRbDescWriteWithImm,
    },
    types::{MemAccessTypeFlag, Msn, Pmtu, QpType},
    utils::get_first_packet_max_length,
};
use eui48::MacAddress;
use flume::Sender;
use pnet::datalink::MacAddr;
use thiserror::Error;

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, PoisonError, RwLock},
    usize,
};

const MAX_QP: usize = 8;

/// The hardware memory region context
#[derive(Debug)]
pub(super) struct MemoryRegion {
    pub(super) key: Key,
    pub(super) acc_flags: MemAccessTypeFlag,
    pub(super) pdkey: PDHandle,
    pub(super) addr: u64,
    pub(super) len: usize,
    pub(super) pgt_offset: u32,
}
// a buf divied into 4096 bytes slot to store raw packet
#[derive(Debug)]
pub(super) struct RawPktBuf {
    buf_vec: Vec<[u8; RAW_PKT_BLOCK_SIZE]>,
    buf_idx: usize,
}

impl RawPktBuf {
    fn new() -> Self {
        Self {
            buf_vec: Vec::new(),
            buf_idx: 0,
        }
    }

    fn set_base_addr(&mut self, base_addr: u64) {
        self.buf_vec = get_raw_pkt_buf(base_addr);
    }

    fn put_raw_pkt(&mut self, raw_packet: &[u8]) {
        self.buf_vec[self.buf_idx].copy_from_slice(raw_packet);
        self.buf_idx += 1;
        if self.buf_idx == RAW_PKT_SLOT_NUM {
            self.buf_idx = 0;
        }
    }
}

#[derive(Debug)]
pub(crate) struct NetworkParam {
    pub(crate) gateway: Ipv4Addr,
    pub(crate) netmask: Ipv4Addr,
    pub(crate) ipaddr: Ipv4Addr,
    pub(crate) macaddr: MacAddress,
}

impl NetworkParam {
    fn new() -> Self {
        Self {
            gateway: Ipv4Addr::new(0, 0, 0, 0),
            netmask: Ipv4Addr::new(0, 0, 0, 0),
            ipaddr: Ipv4Addr::new(0, 0, 0, 0),
            macaddr: MacAddress::new([0u8; 6]),
        }
    }
}

/// The simulating hardware logic of `BlueRDMA`
///
/// Typically, the logic needs a `NetSendAgent` and a `NetReceiveAgent` to send and receive packets.
/// User use the `send` method to send a `ToCardWorkRbDesc` to the network, and use the `update` method to update the hardware context.
/// And when the `recv_agent` is binded, the received packets will be parsed and be pushed to the `to_host_data_descriptor_queue`.
#[derive(Debug)]
pub(crate) struct BlueRDMALogic {
    mr_rkey_table: RwLock<HashMap<Key, Arc<RwLock<MemoryRegion>>>>,
    qp_table: Arc<RwLock<QpTable>>,
    raw_pkt_buf: RwLock<RawPktBuf>,
    net_send_agent: Arc<dyn NetSendAgent>,
    net_param: RwLock<NetworkParam>,
    to_host_data_descriptor_queue: Sender<ToHostWorkRbDesc>,
    to_host_ctrl_descriptor_queue: Sender<ToHostCtrlRbDesc>,
}

#[derive(Error, Debug)]
pub(crate) enum BlueRdmaLogicError {
    #[error("packet process error")]
    NetAgentError(#[from] NetAgentError),
    #[error("Raw packet length is too long. Pmtu is `{0}`, length is `{1}`")]
    RawPacketLengthTooLong(u32, u32),
    #[error("Poison error")]
    Poison,
    #[error("Unreachable")]
    Unreachable,
}

impl<T> From<PoisonError<T>> for BlueRdmaLogicError {
    fn from(_err: PoisonError<T>) -> Self {
        Self::Poison
    }
}

impl BlueRDMALogic {
    pub(crate) fn new(
        net_sender: Arc<dyn NetSendAgent>,
        ctrl_sender: Sender<ToHostCtrlRbDesc>,
        work_sender: Sender<ToHostWorkRbDesc>,
    ) -> Self {
        BlueRDMALogic {
            mr_rkey_table: RwLock::new(HashMap::new()),
            qp_table: Arc::new(RwLock::new(QpTable::new(MAX_QP))),
            raw_pkt_buf: RwLock::new(RawPktBuf::new()),
            net_param: RwLock::new(NetworkParam::new()),
            net_send_agent: net_sender,
            to_host_data_descriptor_queue: work_sender,
            to_host_ctrl_descriptor_queue: ctrl_sender,
        }
    }

    fn send_raw_packet(&self, mut desc: ToCardDescriptor) -> Result<(), BlueRdmaLogicError> {
        let common = desc.common();
        let total_length = common.total_len;
        let pmtu = u32::from(&common.pmtu);
        if total_length > pmtu {
            return Err(BlueRdmaLogicError::RawPacketLengthTooLong(
                pmtu,
                total_length,
            ));
        }
        let dqp_ip = common.dqp_ip;
        let payload = desc.first_sge_mut().cut(total_length)?;
        let buf = payload
            .direct_data_ptr(true)
            .ok_or(NetAgentError::InvalidRdmaMessage(
                "PayloadInfo should have at least one item".to_owned(),
            ))?;
        self.net_send_agent.send(buf, buf.len());
        Ok(())
    }

    fn send_write_only_packet(
        &self,
        mut req: ToCardWriteDescriptor,
        mut meta_data: RdmaGeneralMeta,
    ) -> Result<(), BlueRdmaLogicError> {
        // RdmaWriteOnly or RdmaWriteOnlyWithImmediate
        let payload = req.sg_list.cut_all_levels();

        // if it's a RdmaWriteOnlyWithImmediate, add the immediate data
        let (opcode, imm) = req.write_only_opcode_with_imm();
        meta_data.common_meta.opcode = opcode;
        meta_data.imm = imm;
        meta_data.reth.len = if meta_data.common_meta.opcode.is_first() {
            req.common.total_len
        } else {
            req.sg_list.get_total_length()
        };

        let msg = RdmaMessage {
            meta_data: Metadata::General(meta_data),
            payload,
        };

        self.send_rdma_message(
            req.common.mac_addr,
            req.common.dqp_ip,
            RDMA_DEFAULT_PORT,
            &msg,
        )?;
        Ok(())
    }

    fn send_read_packet(
        &self,
        req: &ToCardReadDescriptor,
        mut common_meta: RdmaMessageMetaCommon,
    ) -> Result<(), BlueRdmaLogicError> {
        let local_sa = &req.sge.data[0];
        common_meta.opcode = RdmaOpCode::RdmaReadRequest;

        let msg = RdmaMessage {
            meta_data: Metadata::General(RdmaGeneralMeta {
                common_meta,
                reth: RethHeader {
                    va: req.common.raddr,
                    rkey: Key::new(req.common.rkey.get()),
                    len: req.common.total_len,
                },
                imm: None,
                secondary_reth: Some(RethHeader {
                    va: local_sa.addr,
                    rkey: local_sa.key,
                    len: local_sa.len,
                }),
            }),
            payload: PayloadInfo::new(),
        };

        self.send_rdma_message(
            req.common.mac_addr,
            req.common.dqp_ip,
            RDMA_DEFAULT_PORT,
            &msg,
        )?;
        Ok(())
    }

    /// Convert a `ToCardWorkRbDesc` to a `RdmaMessage` and call the `net_send_agent` to send through the network.
    pub(crate) fn send(&self, desc: Box<ToCardWorkRbDesc>) -> Result<(), BlueRdmaLogicError> {
        let desc = ToCardDescriptor::from(desc);
        // if it's a raw packet, send it directly
        if desc.is_raw_packet() {
            return self.send_raw_packet(desc);
        }

        let common_meta = {
            let common = desc.common();
            RdmaMessageMetaCommon {
                tran_type: desc.common().qp_type.into(),
                opcode: RdmaOpCode::RdmaWriteOnly,
                solicited: false,
                // We use the pkey to store msn
                pkey: PKey::new(common.msn.get()),
                dqpn: Qpn::new(common.dqpn.get()),
                ack_req: false,
                psn: Psn::new(common.psn.get()),
            }
        };

        #[allow(clippy::arithmetic_side_effects)]
        match desc {
            ToCardDescriptor::Write(mut req) => {
                log::info!("{:?}", req);
                let pmtu = u32::from(&req.common.pmtu);
                let first_packet_max_length = get_first_packet_max_length(req.common.raddr, pmtu);

                // a default metadata. It will be updated later
                let mut meta_data = RdmaGeneralMeta {
                    common_meta,
                    reth: RethHeader {
                        va: req.common.raddr,
                        rkey: Key::new(req.common.rkey.get()),
                        len: req.common.total_len,
                    },
                    imm: None,
                    secondary_reth: None,
                };
                let sge_total_length = req.sg_list.get_total_length();
                if sge_total_length <= first_packet_max_length {
                    return self.send_write_only_packet(req, meta_data);
                }
                // othetrwise send the data in multiple packets
                // we specifically handle the first and last packet
                // The first va might not align to pmtu
                let mut cur_va = req.common.raddr;
                let mut cur_len = sge_total_length;
                let mut psn = req.common.psn;

                // since the packet size is larger than first_packet_max_length, first_packet_length should equals
                // to first_packet_max_length
                let first_packet_length = first_packet_max_length;

                let payload = req.sg_list.cut(first_packet_length)?;
                meta_data.common_meta.opcode = req.write_first_opcode();
                meta_data.reth.len = if meta_data.common_meta.opcode.is_first() {
                    req.common.total_len
                } else {
                    first_packet_length
                };
                meta_data.reth.va = cur_va;
                let msg = RdmaMessage {
                    meta_data: Metadata::General(meta_data.clone()),
                    payload,
                };
                cur_len -= first_packet_length;
                psn = psn.wrapping_add(1);
                cur_va = cur_va.wrapping_add(u64::from(first_packet_length));
                self.send_rdma_message(
                    req.common.mac_addr,
                    req.common.dqp_ip,
                    RDMA_DEFAULT_PORT,
                    &msg,
                )?;

                // send the middle packets
                meta_data.reth.len = pmtu;
                while cur_len > pmtu {
                    let middle_payload = req.sg_list.cut(pmtu)?;
                    meta_data.common_meta.opcode = req.write_middle_opcode();
                    meta_data.reth.va = cur_va;
                    meta_data.common_meta.psn = Psn::new(psn.get());
                    let middle_msg = RdmaMessage {
                        meta_data: Metadata::General(meta_data.clone()),
                        payload: middle_payload,
                    };
                    cur_len -= pmtu;
                    psn = psn.wrapping_add(1);
                    cur_va = cur_va.wrapping_add(u64::from(pmtu));
                    self.send_rdma_message(
                        req.common.mac_addr,
                        req.common.dqp_ip,
                        RDMA_DEFAULT_PORT,
                        &msg,
                    )?;
                }

                // cur_len <= pmtu, send last packet
                let last_payload = req.sg_list.cut(cur_len)?;

                // The last packet may be with immediate data
                let (opcode, imm) = req.write_last_opcode_with_imm();
                meta_data.common_meta.opcode = opcode;
                meta_data.common_meta.psn = Psn::new(psn.get());
                meta_data.imm = imm;
                meta_data.reth.va = cur_va;
                meta_data.reth.len = cur_len;
                let last_msg = RdmaMessage {
                    meta_data: Metadata::General(meta_data),
                    payload: last_payload,
                };
                self.send_rdma_message(
                    req.common.mac_addr,
                    req.common.dqp_ip,
                    RDMA_DEFAULT_PORT,
                    &msg,
                )?;
            }
            ToCardDescriptor::Read(req) => {
                self.send_read_packet(&req, common_meta)?;
            }
        }
        Ok(())
    }

    fn send_rdma_message(
        &self,
        dst_mac: MacAddress,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        message: &RdmaMessage,
    ) -> Result<(), BlueRdmaLogicError> {
        let mut buf = [0u8; NET_SERVER_BUF_SIZE];
        let locked_net_param = self.net_param.read()?;
        let src_mac = locked_net_param.macaddr;
        let src_ip = locked_net_param.ipaddr;
        let src_port = RDMA_DEFAULT_PORT;
        let ip_id = 0;
        let total_length = PacketWriter::new(&mut buf)
            .src_mac(src_mac)
            .src_addr(src_ip)
            .src_port(src_port)
            .dest_mac(dst_mac)
            .dest_addr(dst_ip)
            .dest_port(dst_port)
            .ip_id(ip_id)
            .message(message)
            .write()
            .map_err(|e| NetAgentError::PacketProcess(e))?;

        self.net_send_agent
            .send(&buf[..total_length], total_length)?;
        Ok(())
    }

    #[allow(clippy::unwrap_in_result)]
    pub(crate) fn update(&self, desc: ToCardCtrlRbDesc) -> Result<(), BlueRdmaLogicError> {
        let opcode = to_host_ctrl_opcode(&desc);
        let (op_id, is_succ) = match desc {
            ToCardCtrlRbDesc::QpManagement(desc) => {
                let mut qp_table = self.qp_table.write()?;
                let qpn = Qpn::new(desc.qpn.get());
                let qp_context = QpContext {
                    pmtu: desc.pmtu,
                    qp_type: desc.qp_type,
                    qp_access_flags: desc.rq_acc_flags,
                    // TODO: change to same Qpn
                    peer_qp: Qpn::new(desc.peer_qpn.get()),
                    pdkey: PDHandle::new(desc.pd_hdl),
                };
                let is_success = if desc.is_valid {
                    // create
                    qp_table.set_qp(qpn, qp_context)
                } else {
                    // delete
                    qp_table.reset_qp(qpn)
                };
                (desc.common.op_id, is_success)
            }
            ToCardCtrlRbDesc::UpdateMrTable(desc) => {
                let mut mr_table = self.mr_rkey_table.write()?;
                let key = Key::new(desc.key.get());
                let mr = MemoryRegion {
                    key,
                    acc_flags: desc.acc_flags,
                    pdkey: PDHandle::new(desc.pd_hdl),
                    addr: desc.addr,
                    len: desc.len as usize,
                    pgt_offset: desc.pgt_offset,
                };
                if let Some(mr_context) = mr_table.get(&mr.key) {
                    let mut guard = mr_context.write()?;
                    *guard = mr;
                } else {
                    let mr = Arc::new(RwLock::new(mr));
                    // we have ensured that the qpn is not exists.
                    let _: Option<Arc<RwLock<MemoryRegion>>> = mr_table.insert(key, mr);
                }
                (desc.common.op_id, true)
            }
            ToCardCtrlRbDesc::SetNetworkParam(desc) => (desc.common.op_id, true),
            ToCardCtrlRbDesc::SetRawPacketReceiveMeta(desc) => {
                let mut locked_buf = self.raw_pkt_buf.write()?;
                locked_buf.set_base_addr(desc.base_write_addr);
                (desc.common.op_id, true)
            }
            ToCardCtrlRbDesc::UpdateErrorPsnRecoverPoint(desc) => {
                let mut locked_table = self.qp_table.write()?;
                let qpn = Qpn::new(desc.qpn.get());
                let recovery_success = locked_table
                    .recovery_qp(Qpn::new(desc.qpn.get()), Psn::new(desc.recover_psn.get()));
                (desc.common.op_id, recovery_success)
            }
            // Userspace types use virtual address directly
            ToCardCtrlRbDesc::UpdatePageTable(desc) => (desc.common.op_id, true),
        };
        let resp_desc = ToHostCtrlRbDesc {
            common: ToHostCtrlRbDescCommon {
                op_id,
                is_success: is_succ,
                opcode,
            },
        };
        #[allow(clippy::unwrap_used)] // if the pipe in software is broken, we should panic.
        {
            self.to_host_ctrl_descriptor_queue.send(resp_desc).unwrap();
        }
        Ok(())
    }

    /// Validate the permission, va and length of corresponding memory region.
    ///
    /// The function will check the following things:
    /// * if the rkey is valid. If not, return `InvMrKey`
    /// * if the permission is valid. If not, return `InvAccFlag`
    /// * if the va and length are valid. If not, return `InvMrRegion`
    /// Otherwise, return `RDMA_REQ_ST_NORMAL`
    fn do_validation(&self, message: &RdmaMessage) -> Result<RdmaReqStatus, BlueRdmaLogicError> {
        match &message.meta_data {
            Metadata::General(common_meta) => {
                let opcode = &common_meta.common_meta.opcode;
                let needed_permissions = common_meta.needed_permissions();
                let qp_table = self.qp_table.read()?;
                let Some(qp_entry) = qp_table.get_qp_context(common_meta.common_meta.dqpn.clone())
                else {
                    return Ok(RdmaReqStatus::RdmaReqStInvHeader);
                };

                if !check_opcode_supported(&qp_entry.qp_type, opcode) {
                    return Ok(RdmaReqStatus::RdmaReqStInvOpcode);
                }
                if !qp_entry.qp_access_flags.contains(needed_permissions) {
                    return Ok(RdmaReqStatus::RdmaReqStInvAccFlag);
                }

                let pmtu = u64::from(&qp_entry.pmtu);
                let is_first_mid = opcode.is_first() || opcode.is_middle();
                let is_mid = opcode.is_middle();
                let is_last_only = opcode.is_last() || opcode.is_only();

                let payload_length = u64::from(common_meta.reth.len);
                let eq_pmtu = payload_length == pmtu;
                let gt_pmtu = payload_length > pmtu;

                if !((is_first_mid && !gt_pmtu)
                    || (is_mid && eq_pmtu)
                    || (is_last_only && !gt_pmtu))
                {
                    return Ok(RdmaReqStatus::RdmaReqStInvHeader);
                }

                let r_key = common_meta.reth.rkey;
                let mr_rkey_table = self.mr_rkey_table.read()?;
                let Some(mr) = mr_rkey_table.get(&r_key) else {
                    return Ok(RdmaReqStatus::RdmaReqStInvMrKey);
                };

                let read_guard = mr.read()?;
                // check the permission.
                if !read_guard.acc_flags.contains(needed_permissions) {
                    return Ok(RdmaReqStatus::RdmaReqStInvAccFlag);
                }

                let va = common_meta.reth.va;

                // check if the va and length are valid.
                if read_guard.addr > va
                    || read_guard.addr.wrapping_add(read_guard.len as u64)
                        < va.wrapping_add(u64::from(payload_length))
                {
                    return Ok(RdmaReqStatus::RdmaReqStInvMrRegion);
                }

                Ok(RdmaReqStatus::RdmaReqStNormal)
            }
            Metadata::Acknowledge(_) => Ok(RdmaReqStatus::RdmaReqStNormal),
        }
    }
}

unsafe impl Send for BlueRDMALogic {}
unsafe impl Sync for BlueRDMALogic {}

fn recv_default_meta(message: &RdmaMessage) -> ToHostWorkRbDescCommon {
    #[allow(clippy::cast_possible_truncation)]
    ToHostWorkRbDescCommon {
        status: ToHostWorkRbDescStatus::Unknown,
        trans: ToHostWorkRbDescTransType::Rc,
        dqpn: crate::types::Qpn::new(message.meta_data.common_meta().dqpn.get()),
        msn: Msn::new(message.meta_data.common_meta().pkey.get()),
        expected_psn: crate::types::Psn::new(0),
    }
}

impl NetReceiveLogic<'_> for BlueRDMALogic {
    fn recv(&self, data: &[u8]) {
        let message = PacketProcessor::to_rdma_message(data)
            .expect("Fail to convert to rdma message, may be check error?");
        let req_status = if !header_pre_check(data) {
            RdmaReqStatus::RdmaReqStInvHeader
        } else {
            match self.do_validation(&message) {
                Ok(status) => status,
                Err(_) => {
                    log::error!("Failed to validate the rkey");
                    return;
                }
            }
        };
        
        let meta = &message.meta_data;
        let mut common = recv_default_meta(&message);
        let descriptor =  match meta {
            Metadata::General(general_meta) => {
                let Ok(mut expected_psn_manager) = self.qp_table.write() else {
                    log::error!("Failed to lock the qp table");
                    return;
                };

                let qpn_idx = Qpn::new(general_meta.common_meta.dqpn.get());
                let continous_resp = match expected_psn_manager.check_continous(
                    qpn_idx,
                    general_meta.common_meta.psn,
                    !req_status.is_nromal(),
                ) {
                    Some(resp) => resp,
                    None => {
                        return;
                    }
                };
                let va = general_meta.reth.va;
                if req_status.is_nromal() && general_meta.has_payload() {
                    message.payload.copy_to(va as *mut u8);
                }

                let need_report = !(continous_resp.is_adjacent_psn_continous
                    && general_meta.common_meta.opcode.is_middle());
                let need_gen_ack =
                    continous_resp.is_qp_psn_continous && general_meta.common_meta.ack_req;

                match general_meta.common_meta.opcode {
                    RdmaOpCode::RdmaWriteFirst
                    | RdmaOpCode::RdmaWriteMiddle
                    | RdmaOpCode::RdmaWriteLast
                    | RdmaOpCode::RdmaWriteOnly
                    | RdmaOpCode::RdmaReadResponseFirst
                    | RdmaOpCode::RdmaReadResponseMiddle
                    | RdmaOpCode::RdmaReadResponseLast
                    | RdmaOpCode::RdmaReadResponseOnly => {
                        ToHostWorkRbDesc::WriteOrReadResp(ToHostWorkRbDescWriteOrReadResp {
                            common,
                            is_read_resp,
                            write_type,
                            psn: general_meta.common_meta.psn,
                            addr: general_meta.reth.va,
                            len: general_meta.reth.len,
                            can_auto_ack: false,
                        })
                    }
                    _ => unimplemented!(),
                }
            }
            Metadata::Acknowledge(header) => {
                common.status = ToHostWorkRbDescStatus::Normal;
                match header.aeth_code {
                    ToHostWorkRbDescAethCode::Ack => ToHostWorkRbDesc::Ack(ToHostWorkRbDescAck {
                        common,
                        #[allow(clippy::cast_possible_truncation)]
                        msn: crate::types::Msn::new(header.msn as u16), // msn is u16 currently. So we can just truncate it.
                        value: header.aeth_value,
                        psn: crate::types::Psn::new(header.common_meta.psn.get()),
                        code: ToHostWorkRbDescAethCode::Ack,
                        retry_psn: Psn::default(),
                    }),
                    ToHostWorkRbDescAethCode::Rnr
                    | ToHostWorkRbDescAethCode::Rsvd
                    | ToHostWorkRbDescAethCode::Nak => {
                        // just ignore
                        unimplemented!()
                    }
                }
            }
        }
        // if the pipe in software is broken, we should panic.
        self.to_host_data_descriptor_queue
            .send(descriptor)
            .expect("software pipe broken");
    }

    fn recv_raw(&self, data: &[u8]) {
        let mut locked_buf = self
            .raw_pkt_buf
            .write()
            .expect("fail to lock raw packet buf");
        locked_buf.put_raw_pkt(data);
    }
}

fn to_host_ctrl_opcode(desc: &ToCardCtrlRbDesc) -> CtrlRbDescOpcode {
    match desc {
        ToCardCtrlRbDesc::UpdateMrTable(_) => CtrlRbDescOpcode::UpdateMrTable,
        ToCardCtrlRbDesc::UpdatePageTable(_) => CtrlRbDescOpcode::UpdatePageTable,
        ToCardCtrlRbDesc::QpManagement(_) => CtrlRbDescOpcode::QpManagement,
        ToCardCtrlRbDesc::SetNetworkParam(_) => CtrlRbDescOpcode::SetNetworkParam,
        ToCardCtrlRbDesc::SetRawPacketReceiveMeta(_) => CtrlRbDescOpcode::SetRawPacketReceiveMeta,
        ToCardCtrlRbDesc::UpdateErrorPsnRecoverPoint(_) => {
            CtrlRbDescOpcode::UpdateErrorPsnRecoverPoint
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use flume::unbounded;

    use crate::{
        device::{
            software::{
                net_agent::{NetAgentError, NetSendAgent},
                types::{Key, PayloadInfo, Qpn, RdmaMessage},
            },
            ToCardCtrlRbDesc, ToCardCtrlRbDescCommon, ToCardCtrlRbDescQpManagement,
            ToCardCtrlRbDescUpdateMrTable,
        },
        types::{MemAccessTypeFlag, Pmtu, QpType},
    };

    use super::BlueRDMALogic;

    // test update mr table, qp table
    #[test]
    fn test_logic_update() {
        #[derive(Debug)]
        struct DummpyProxy;

        impl NetSendAgent for DummpyProxy {
            fn send(&self, data: &[u8], length: usize) -> Result<(), NetAgentError> {
                Ok(())
            }
        }
        let agent = Arc::new(DummpyProxy);
        let (ctrl_sender, _ctrl_receiver) = unbounded();
        let (work_sender, _work_receiver) = unbounded();
        let logic = BlueRDMALogic::new(Arc::<DummpyProxy>::clone(&agent), ctrl_sender, work_sender);
        // test updating qp
        {
            let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
                common: ToCardCtrlRbDescCommon { op_id: 0 },
                is_valid: true,
                qpn: crate::Qpn::new(1234),
                pd_hdl: 1,
                qp_type: QpType::Rc,
                rq_acc_flags: MemAccessTypeFlag::IbvAccessRemoteWrite,
                pmtu: Pmtu::Mtu1024,
                peer_qpn: crate::Qpn::new(1234),
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.qp_table.read().unwrap();
                let qp_context = guard.get_qp_context(Qpn::new(1234)).unwrap();
                assert!(matches!(qp_context.pmtu, Pmtu::Mtu1024));
                assert!(matches!(qp_context.qp_type, QpType::Rc));
                assert!(qp_context
                    .qp_access_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
            }

            // write again
            let desc = ToCardCtrlRbDesc::QpManagement(ToCardCtrlRbDescQpManagement {
                common: ToCardCtrlRbDescCommon { op_id: 0 },
                is_valid: true,
                qpn: crate::Qpn::new(1234),
                pd_hdl: 1,
                qp_type: QpType::Rc,
                rq_acc_flags: MemAccessTypeFlag::IbvAccessRemoteWrite,
                pmtu: Pmtu::Mtu2048,
                peer_qpn: crate::Qpn::new(1234),
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.qp_table.read().unwrap();
                let qp_context = guard.get_qp_context(Qpn::new(1234)).unwrap();
                assert!(matches!(qp_context.pmtu, Pmtu::Mtu2048));
                assert!(matches!(qp_context.qp_type, QpType::Rc));
                assert!(qp_context
                    .qp_access_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
            }
        }

        // test updating mr
        {
            let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
                common: ToCardCtrlRbDescCommon { op_id: 0 },
                addr: 0x1234567812345678,
                len: 1024 * 16,
                key: crate::types::Key::new(1234),
                pd_hdl: 0,
                acc_flags: MemAccessTypeFlag::IbvAccessRemoteWrite,
                pgt_offset: 0,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.mr_rkey_table.read().unwrap();
                let mr_context = guard.get(&Key::new(1234_u32)).unwrap();
                let read_guard = mr_context.read().unwrap();
                assert_eq!(read_guard.addr, 0x1234567812345678);
                assert_eq!(read_guard.len, 1024 * 16);
                assert_eq!(read_guard.pdkey.get(), 0);
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
                assert_eq!(read_guard.pgt_offset, 0);
            }

            // update again
            let desc = ToCardCtrlRbDesc::UpdateMrTable(ToCardCtrlRbDescUpdateMrTable {
                common: ToCardCtrlRbDescCommon { op_id: 0 },
                addr: 0x1234567812345678,
                len: 1024 * 24,
                key: crate::types::Key::new(1234),
                pd_hdl: 0,
                acc_flags: (MemAccessTypeFlag::IbvAccessRemoteWrite
                    | MemAccessTypeFlag::IbvAccessRemoteRead),
                pgt_offset: 0,
            });
            logic.update(desc).unwrap();
            {
                let guard = logic.mr_rkey_table.read().unwrap();
                let mr_context = guard.get(&Key::new(1234_u32)).unwrap();
                let read_guard = mr_context.read().unwrap();
                assert_eq!(read_guard.addr, 0x1234567812345678);
                assert_eq!(read_guard.len, 1024 * 24);
                assert_eq!(read_guard.pdkey.get(), 0);
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteWrite));
                assert!(read_guard
                    .acc_flags
                    .contains(MemAccessTypeFlag::IbvAccessRemoteRead));
                assert_eq!(read_guard.pgt_offset, 0);
            }
        }
    }
}
