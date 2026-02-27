use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

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
                format!("I/O Error: {}", ioe.to_string())
            }
            SentinelError::InvalidPcap(ipe) => {
                format!("Invalid PCAP: {}", ipe.to_string())
            }
            SentinelError::UnsupportedProtocol(upe) => {
                format!("Unsupported Protocol: {}", upe.to_string())
            }
            SentinelError::ParseError { layer, reason } => {
                format!("Parse error @ layer {} : {}", layer, reason)
            }
        };

        write!(f, "{}", text)
    }
}

impl Error for SentinelError {}