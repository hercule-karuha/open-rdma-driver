use super::net_basic::{NetAgentError, NetReceiveLogic, NetSendAgent};
use crate::device::layout::MAC_HEADER_SIZE;
use crate::device::software::packet_processor::{check_rdma_pkt, is_icrc_valid};
use crate::unsafe_tools::get_layer2_protocol;
use log::error;
use socket2::{Domain, Socket, Type};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

pub(crate) const NET_SERVER_BUF_SIZE: usize = 8192;

#[derive(Debug)]
pub(crate) struct RawSockSendAgent {
    sender: Socket,
}

impl RawSockSendAgent {
    pub(crate) fn new() -> Result<Self, NetAgentError> {
        let sender = Socket::new(Domain::PACKET, Type::RAW, Some(get_layer2_protocol()))?;
        Ok(Self { sender: sender })
    }
}

impl NetSendAgent for RawSockSendAgent {
    fn send(&self, data: &[u8], length: usize) -> Result<(), NetAgentError> {
        let sended_size = self.sender.send(&data[..length])?;
        if length != sended_size {
            return Err(NetAgentError::WrongBytesSending(length, sended_size));
        }
        Ok(())
    }
}

/// A single thread server, use raw socket to reveive layer 2 packets
#[derive(Debug)]
pub(crate) struct RawSockRecvAgent {
    listen_thread: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
}

impl RawSockRecvAgent {
    pub(crate) fn new(
        receiver: Arc<dyn for<'a> NetReceiveLogic<'a>>,
    ) -> Result<Self, NetAgentError> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop_flag = Arc::clone(&stop_flag);
        let layer2_protocol = get_layer2_protocol();
        let mut socket = Socket::new(Domain::PACKET, Type::RAW, Some(layer2_protocol))?;
        let listen_thread = Some(thread::spawn(move || {
            let mut buf = [0u8; NET_SERVER_BUF_SIZE];
            while !thread_stop_flag.load(Ordering::Relaxed) {
                if let Ok(length) = socket.read(&mut buf) {
                    if length < MAC_HEADER_SIZE {
                        error!("Packet too short");
                        continue;
                    }
                    if !check_rdma_pkt(&buf) {
                        receiver.recv_raw(&buf);
                        continue;
                    }

                    match is_icrc_valid(&mut buf) {
                        Ok(is_valid) => {
                            if !is_valid {
                                error!("ICRC check failed {:?}", &buf);
                                continue;
                            }
                        }
                        Err(e) => {
                            error!("ICRC check failed {:?}", e);
                            continue;
                        }
                    }
                    receiver.recv(&buf[..length]);
                }
            }
        }));
        Ok(Self {
            listen_thread,
            stop_flag,
        })
    }
}
