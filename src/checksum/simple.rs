use super::algorithms::Checksum;

pub struct Sum8;

impl Checksum for Sum8 {
    fn name(&self) -> &'static str {
        "SUM8"
    }

    fn width(&self) -> usize {
        1
    }

    fn calculate(&self, data: &[u8]) -> u32 {
        data.iter()
            .fold(0u8, |acc, &byte| acc.wrapping_add(byte))
            as u32
    }
}
pub struct Sum16;

impl Checksum for Sum16 {
    fn name(&self) -> &'static str {
        "SUM16"
    }

    fn width(&self) -> usize {
        2
    }

    fn calculate(&self, data: &[u8]) -> u32 {
        data.iter()
            .fold(0u16, |acc, &byte| {
                acc.wrapping_add(byte as u16)
            }) as u32
    }
}