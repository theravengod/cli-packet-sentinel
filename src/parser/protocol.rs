use crate::error::SentinelError;
use crate::parser::protocol::EtherType::{ARP, IPv4, IPv6};
use std::fmt::{Display, Formatter};

pub struct EthFrame {
    pub dst: MACAddr,
    pub src: MACAddr,
    pub eth_type: EtherType,
}

impl EthFrame {
    fn from_bytes(b: [u8; 14]) -> Result<EthFrame, SentinelError> {
        let eth_type = EtherType::from_bytes(u16::from_le_bytes(b[12..14].try_into().unwrap()))
            .ok_or_else(|| SentinelError::ParseError {
                layer: "Ethernet".to_string(),
                reason: "Unknown EtherType".to_string(),
            })?;

        Ok(EthFrame {
            dst: MACAddr::try_from(&b[0..6]).map_err(|e| SentinelError::ParseError {
                layer: "Ethernet".to_string(),
                reason: e.to_string(),
            })?,
            src: MACAddr::try_from(&b[6..12]).map_err(|e| SentinelError::ParseError {
                layer: "Ethernet".to_string(),
                reason: e.to_string(),
            })?,
            eth_type,
        })
    }
}

pub struct MACAddr([u8; 6]);

impl Display for MACAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

impl TryFrom<&[u8]> for MACAddr {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(MACAddr(bytes.try_into()?))
    }
}

pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
}

impl EtherType {
    fn from_bytes(b: u16) -> Option<EtherType> {
        match b {
            0x0800 => Some(IPv4),
            0x86DD => Some(IPv6),
            0x0806 => Some(ARP),
            _ => None,
        }
    }
}
