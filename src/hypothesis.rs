use crate::checksum::algorithms::ChecksumCandidate;
use crate::fields::FieldHypothesis;
use crate::framing::FramingCandidate;

pub struct ProtocolHypothesis {
    pub framing: FramingCandidate,
    pub checksum: ChecksumCandidate,
    pub fields: Vec<FieldHypothesis>,
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

    let field_start = checksum.coverage_start;
    let field_end = checksum.checksum_start;

    let fields = crate::fields::infer_fields(
        frames,
        field_start,
        field_end,
    );

    Some(ProtocolHypothesis {
        framing,
        checksum,
        fields,
    })
}