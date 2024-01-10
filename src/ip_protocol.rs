use std::fmt;

#[derive(PartialOrd, PartialEq)]
pub(crate) enum IPProtocol {
    ICMP,
    TCP,
    UDP,
    Default,
}

impl fmt::Display for IPProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPProtocol::ICMP => { write!(f, "1 (ICMP)") }
            IPProtocol::TCP => { write!(f, "6 (TCP)") }
            IPProtocol::UDP => { write!(f, "17 (UDP)") }
            IPProtocol::Default => { write!(f, "00 (Default)") }
        }
    }
}