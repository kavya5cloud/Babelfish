pub trait Checksum {
    /// Human-readable name of the algorithm.
    fn name(&self) -> &'static str;

    /// Number of bytes produced by the checksum.
    fn width(&self) -> usize;

    /// Calculate the checksum for a byte slice.
    fn calculate(&self, data: &[u8]) -> u32;
}

pub struct ChecksumCandidate {
    pub algorithm: Box<dyn Checksum>,

    /// First byte containing the checksum.
    pub checksum_offset: usize,

    /// First byte included in checksum calculation.
    pub coverage_start: usize,

    /// Number of frames that validated.
    pub validation_count: usize,

    /// Total number of frames tested.
    pub total_frames: usize,
}

impl ChecksumCandidate {
    pub fn validation_rate(&self) -> f64 {
        if self.total_frames == 0 {
            return 0.0;
        }

        self.validation_count as f64 / self.total_frames as f64
    }

    pub fn is_proven(&self) -> bool {
        self.validation_count == self.total_frames
    }
}
pub struct XorChecksum;

impl Checksum for XorChecksum {
    fn name(&self) -> &'static str {
        "XOR"
    }

    fn width(&self) -> usize {
        1
    }

    fn calculate(&self, data: &[u8]) -> u32 {
        data.iter()
            .fold(0u8, |acc, &byte| acc ^ byte) as u32
    }
}