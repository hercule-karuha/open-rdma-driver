use super::super::packet::PacketError;
use super::super::packet_processor::PacketProcessorError;

use std::fmt::Debug;
use std::io;
use thiserror::Error;

pub(crate) trait NetReceiveLogic<'a>: Send + Sync + Debug {
    fn recv(&self, data: &[u8]);
    fn recv_raw(&self, data: &[u8]);
}

pub(crate) trait NetSendAgent: Debug {
    fn send(&self, data: &[u8]) -> Result<(), NetAgentError>;
}

#[derive(Error, Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum NetAgentError {
    #[error("packet process error")]
    Packet(#[from] PacketError),
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("packet process error")]
    PacketProcess(#[from] PacketProcessorError),
    #[error("setsockopt failed, errno: {0}")]
    SetSockOptFailed(i32),
    #[error("Expected {0} bytes, but sended {1} bytes")]
    WrongBytesSending(usize, usize),
    #[error("Invalid RDMA message :{0}")]
    InvalidRdmaMessage(String),
}
