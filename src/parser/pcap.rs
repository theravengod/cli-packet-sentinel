use crate::error::SentinelError;
use std::io::Read;

pub struct PcapHeader {
    pub byte_order: ByteOrder,
    pub version_major: u16,
    pub version_minor: u16,
    pub snap_len: u32,
    pub network: u32,
}

impl PcapHeader {
    fn from_raw(buffer: &mut [u8]) -> Result<PcapHeader, SentinelError> {
        let magic = match u32::from_le_bytes(buffer[0..4].try_into().unwrap()) {
            0xA1B2C3D4 => Some(ByteOrder::Native),
            0xD4C3B2A1 => Some(ByteOrder::Swapped),
            _ => None,
        };

        if magic.is_some() {
            Ok(PcapHeader {
                byte_order: magic.unwrap(),
                version_major: u16::from_le_bytes(buffer[4..6].try_into().unwrap()),
                version_minor: u16::from_le_bytes(buffer[6..8].try_into().unwrap()),
                snap_len: u32::from_le_bytes(buffer[16..20].try_into().unwrap()),
                network: u32::from_le_bytes(buffer[20..24].try_into().unwrap()),
            })
        } else {
            Err(SentinelError::InvalidPcap(
                "Missing or corrupt magic number".to_string(),
            ))
        }
    }
}

pub struct RawPacket {
    pub timestamp: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum ByteOrder {
    Native,
    Swapped,
}

pub struct PcapReader<R: Read> {
    reader: R,
    pub header: PcapHeader,
}

impl<R: Read> Read for PcapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> Result<Self, SentinelError> {
        let mut buffer = [0; 24];
        let read_result = reader.read(&mut buffer);

        match read_result {
            Ok(_) => Ok(PcapReader {
                reader,
                header: PcapHeader::from_raw(&mut buffer)?,
            }),
            Err(_) => Err(SentinelError::InvalidPcap(
                "Could not read header".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal 24-byte pcap global header.
    ///
    /// Pcap global header layout (all fields little-endian):
    ///   0..4   magic number
    ///   4..6   version major
    ///   6..8   version minor
    ///   8..12  reserved1
    ///   12..16 reserved2
    ///   16..20 snap_len
    ///   20..24 link-layer type (network)
    fn make_header(magic: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&magic.to_le_bytes()); // magic
        buf.extend_from_slice(&2u16.to_le_bytes()); // version_major
        buf.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snap_len
        buf.extend_from_slice(&1u32.to_le_bytes()); // network (LINKTYPE_ETHERNET)
        buf
    }

    #[test]
    fn reads_native_magic_number() {
        let data = make_header(0xA1B2C3D4);
        let reader = PcapReader::new(data.as_slice()).expect("should parse valid pcap header");
        assert_eq!(reader.header.byte_order, ByteOrder::Native);
    }

    #[test]
    fn reads_swapped_magic_number() {
        let data = make_header(0xD4C3B2A1);
        let reader = PcapReader::new(data.as_slice()).expect("should parse valid pcap header");
        assert_eq!(reader.header.byte_order, ByteOrder::Swapped);
    }

    #[test]
    fn rejects_invalid_magic_number() {
        let data = make_header(0xDEADBEEF);
        match PcapReader::new(data.as_slice()) {
            Err(SentinelError::InvalidPcap(_)) => {}
            _ => panic!("expected InvalidPcap error for bad magic number"),
        }
    }
}
