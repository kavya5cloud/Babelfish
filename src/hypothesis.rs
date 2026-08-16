use crate::checksum::algorithms::ChecksumCandidate;
use crate::fields::{FieldHypothesis, MultiByteFieldHypothesis};
use crate::framing::FramingCandidate;

pub struct ProtocolHypothesis {
    pub framing: FramingCandidate,
    pub checksum: ChecksumCandidate,
    pub fields: Vec<FieldHypothesis>,
    pub multi_byte_fields: Vec<MultiByteFieldHypothesis>,
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

    pub fn field_evidence(&self) -> f64 {
        if self.fields.is_empty() {
            return 0.0;
        }

        let frame_count = self.framing.frame_count;

        let total: f64 = self
            .fields
            .iter()
            .map(|field| field.evidence_score(frame_count))
            .sum();

        total / self.fields.len() as f64
    }

    pub fn multi_byte_evidence(&self) -> f64 {
        if self.multi_byte_fields.is_empty() {
            return 0.0;
        }

        let total: f64 = self
            .multi_byte_fields
            .iter()
            .map(|field| field.score())
            .sum();

        (total / self.multi_byte_fields.len() as f64).min(1.0)
    }

    pub fn ambiguous_multi_byte_fields(&self) -> Vec<&MultiByteFieldHypothesis> {
        if self.multi_byte_fields.len() < 2 {
            return Vec::new();
        }

        let best_score = self
            .multi_byte_fields
            .iter()
            .map(|field| field.score())
            .fold(0.0_f64, f64::max);

        self.multi_byte_fields
            .iter()
            .filter(|field| (field.score() - best_score).abs() < f64::EPSILON)
            .collect()
    }
}

pub fn build_hypothesis(
    framing: FramingCandidate,
    frames: &[Vec<u8>],
) -> Option<ProtocolHypothesis> {
    let checksum = crate::checksum::search::best_candidate(frames)?;

    let field_start = checksum.coverage_start;
    let field_end = checksum.checksum_start;

    let fields = crate::fields::infer_fields(frames, field_start, field_end);

    let mut multi_byte_fields = Vec::new();

    if field_start + 1 < field_end {
        let u16_fields = crate::fields::infer_u16_fields(frames, field_start, field_end);

        multi_byte_fields.extend(u16_fields);
    }

    if field_start + 3 < field_end {
        let u32_fields = crate::fields::infer_u32_fields(frames, field_start, field_end);

        multi_byte_fields.extend(u32_fields);
    }

    multi_byte_fields.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| a.width.cmp(&b.width))
    });

    Some(ProtocolHypothesis {
        framing,
        checksum,
        fields,
        multi_byte_fields,
    })
}
