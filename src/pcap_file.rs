use crate::{PcapBlock, PcapFileHeader};

pub(crate) struct PcapFile {
    header: PcapFileHeader,
    data: Vec<PcapBlock>,
}

impl PcapFile {
    fn new() -> PcapFile {
        PcapFile {
            header: PcapFileHeader::new(),
            data: Vec::new(),
        }
    }
    fn new_with_header(header: PcapFileHeader) -> PcapFile {
        PcapFile {
            header,
            data: Vec::new(),
        }
    }
}