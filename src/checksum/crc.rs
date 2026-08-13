use super::algorithms::Checksum;

pub struct Crc16Modbus;

impl Checksum for Crc16Modbus {
    fn name(&self) -> &'static str {
        "CRC16/MODBUS"
    }

    fn width(&self) -> usize {
        2
    }

    fn calculate(&self, data: &[u8]) -> u32 {
        let mut crc: u16 = 0xFFFF;

        for &byte in data {
            crc ^= byte as u16;

            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }

        crc as u32
    }
}