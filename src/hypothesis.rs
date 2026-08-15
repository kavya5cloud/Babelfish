use crate::checksum::algorithms::ChecksumCandidate;
use crate::framing::FramingCandidate;

pub struct ProtocolHypothesis {
    pub framing: FramingCandidate,
    pub checksum: ChecksumCandidate,
}

impl ProtocolHypothesis {
    pub fn validation_rate(&self) -> f64 {
        self.checksum.validation_rate()
    }

    pub fn confidence(&self) -> f64 {
        self.checksum.confidence()
    }

    pub fn verdict(&self) -> &'static str {
        self.checksum.verdict()
    }
}

pub fn build_hypothesis(
    framing: FramingCandidate,
    frames: &[Vec<u8>],
) -> Option<ProtocolHypothesis> {
    let checksum =
        crate::checksum::search::best_candidate(frames)?;

    Some(ProtocolHypothesis {
        framing,
        checksum,
    })
}