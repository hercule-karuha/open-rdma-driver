use libc::ETH_P_ALL;
use socket2::Protocol;

pub(crate) const RAW_PKT_SLOT_NUM: usize = 512;
pub(crate) const RAW_PKT_BLOCK_SIZE: usize = 4096;

/// Return a ETH_P_ALL to set the raw socket
pub(crate) fn get_layer2_protocol() -> Protocol {
    Protocol::from(ETH_P_ALL.to_be())
}

/// Return a Vec to set the buffer of raw packets in software device
/// SAFETY: the software ensure is safe to copy raw packet to base address
pub(crate) fn get_raw_pkt_buf(base_addr: u64) -> Vec<[u8; RAW_PKT_BLOCK_SIZE]> {
    let buf =
        unsafe { std::slice::from_raw_parts(base_addr as *const [u8; 4096], RAW_PKT_SLOT_NUM) };
    buf.to_vec()
}
