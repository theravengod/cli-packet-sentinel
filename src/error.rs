use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

#[allow(dead_code)]
#[derive(Debug)]
pub enum SentinelError {
    Io(std::io::Error),
    InvalidPcap(String),
    UnsupportedProtocol(String),
    ParseError { layer: String, reason: String },
}

impl Display for SentinelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            SentinelError::Io(ioe) => {
                format!("I/O Error: {ioe}")
            }
            SentinelError::InvalidPcap(ipe) => {
                format!("Invalid PCAP: {ipe}")
            }
            SentinelError::UnsupportedProtocol(upe) => {
                format!("Unsupported Protocol: {upe}")
            }
            SentinelError::ParseError { layer, reason } => {
                format!("Parse error @ layer {layer} : {reason}")
            }
        };

        write!(f, "{text}")
    }
}

impl Error for SentinelError {}
