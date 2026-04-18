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
                network: u32::from_le_bytes(buffer[22..24].try_into().unwrap()),
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
    fn new(mut reader: R) -> Result<Self, SentinelError> {
        let mut h_buffer = [0; 24];
        let h_read_result = reader.read(&mut h_buffer);

        match h_read_result {
            Ok(_) => Ok(PcapReader {
                reader,
                header: PcapHeader::from_raw(&mut h_buffer)?,
            }),
            Err(_) => Err(SentinelError::InvalidPcap(
                "Could not read header".to_string(),
            )),
        }
    }
}
