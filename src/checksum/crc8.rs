use super::algorithms::Checksum;

pub struct Crc8;

impl Checksum for Crc8 {
    fn name(&self) -> &'static str {
        "CRC8"
    }

    fn width(&self) -> usize {
        1
    }

    fn calculate(&self, data: &[u8]) -> u32 {
        let mut crc: u8 = 0x00;

        for &byte in data {
            crc ^= byte;

            for _ in 0..8 {
                if crc & 0x80 != 0 {
                    crc = (crc << 1) ^ 0x07;
                } else {
                    crc <<= 1;
                }
            }
        }

        crc as u32
    }
}