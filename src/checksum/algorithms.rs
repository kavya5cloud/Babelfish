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

    /// First byte included in checksum calculation.
    pub coverage_start: usize,

    /// First byte excluded from checksum calculation.
    pub coverage_end: usize,

    /// First byte containing the checksum.
    pub checksum_start: usize,

    /// One past the final checksum byte.
    pub checksum_end: usize,

    /// Number of frames that validated.
    pub validation_count: usize,

    /// Total number of frames tested.
    pub total_frames: usize,

    /// Indexes of frames that failed validation.
    pub failed_frames: Vec<usize>,
}

impl ChecksumCandidate {
    pub fn validation_rate(&self) -> f64 {
        if self.total_frames == 0 {
            return 0.0;
        }

        self.validation_count as f64 / self.total_frames as f64
    }

    pub fn confidence(&self) -> f64 {
        if self.total_frames == 0 {
            return 0.0;
        }

        let validation_rate = self.validation_rate();

        let evidence_factor =
            1.0 - (-((self.total_frames as f64) / 20.0)).exp();

        validation_rate * evidence_factor
    }

    pub fn is_proven(&self) -> bool {
        self.validation_count == self.total_frames
    }

    pub fn verdict(&self) -> &'static str {
        let confidence = self.confidence();

        if self.is_proven() && self.total_frames >= 100 {
            "PROVEN"
        } else if confidence >= 0.70 {
            "LIKELY"
        } else if confidence >= 0.20 {
            "WEAK"
        } else {
            "REJECTED"
        }
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