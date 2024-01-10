use crate::EthernetFrame;

pub(crate) struct PcapBlock {
    pub(crate) timestamp_seconds: [u8; 4],
    pub(crate) timestamp_microseconds: [u8; 4],
    pub(crate) captured_length: [u8; 4],
    pub(crate) original_length: [u8; 4],
    pub(crate) ether_frame: EthernetFrame,
}

impl PcapBlock {
    pub(crate) fn new() -> PcapBlock {
        PcapBlock {
            timestamp_seconds: [0, 0, 0, 0],
            timestamp_microseconds: [0, 0, 0, 0],
            captured_length: [0, 0, 0, 0],
            original_length: [0, 0, 0, 0],
            ether_frame: EthernetFrame::new(),
        }
    }
}