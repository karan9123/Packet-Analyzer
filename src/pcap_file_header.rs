pub(crate) struct PcapFileHeader {
    pub(crate) magic_number: [u8; 4],
    pub(crate) version_major: [u8; 2],
    pub(crate) version_minor: [u8; 2],
    pub(crate) time_zone: [u8; 4],
    pub(crate) timestamp_accuracy: [u8; 4],
    pub(crate) snap_length: [u8; 4],
    pub(crate) link_layer_type: [u8; 4],
}

impl PcapFileHeader {
    pub(crate) fn new() -> PcapFileHeader {
        PcapFileHeader {
            magic_number: [0; 4],
            version_major: [0; 2],
            version_minor: [0; 2],
            time_zone: [0; 4],
            timestamp_accuracy: [0; 4],
            snap_length: [0; 4],
            link_layer_type: [0; 4],
        }
    }
}