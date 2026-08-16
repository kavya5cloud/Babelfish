use crate::evidence::EvidenceReport;
use crate::fields::{FieldInterpretation, MultiByteInterpretation};
use crate::hypothesis::ProtocolHypothesis;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FramingModel {
    pub kind: String,
    pub frame_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChecksumModel {
    pub algorithm: String,
    pub coverage_start: usize,
    pub coverage_end: usize,
    pub checksum_start: usize,
    pub checksum_end: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolModel {
    pub framing: FramingModel,
    pub checksum: ChecksumModel,
    pub fields: Vec<FieldInterpretation>,
    pub multi_byte_fields: Vec<MultiByteInterpretation>,
    pub evidence: EvidenceReport,
}

impl ProtocolModel {
    pub fn from_hypothesis(hypothesis: &ProtocolHypothesis) -> Self {
        let framing_kind = match &hypothesis.framing.kind {
            crate::framing::FramingKind::Prefix(prefix) => {
                format!("prefix {:02X?}", prefix)
            }

            crate::framing::FramingKind::Length {
                length_offset,
                payload_offset,
                checksum_width,
            } => {
                format!(
                    "length byte {}, payload {}, checksum {} byte(s)",
                    length_offset, payload_offset, checksum_width
                )
            }
        };

        let framing = FramingModel {
            kind: framing_kind,
            frame_count: hypothesis.framing.frame_count,
        };

        let checksum = ChecksumModel {
            algorithm: hypothesis.checksum.algorithm.name().to_string(),
            coverage_start: hypothesis.checksum.coverage_start,
            coverage_end: hypothesis.checksum.coverage_end,
            checksum_start: hypothesis.checksum.checksum_start,
            checksum_end: hypothesis.checksum.checksum_end,
        };

        let fields = hypothesis
            .fields
            .iter()
            .map(|field| field.interpretation())
            .collect();

        let multi_byte_fields = hypothesis
            .multi_byte_fields
            .iter()
            .map(|field| field.interpretation())
            .collect();

        let evidence = EvidenceReport::from_hypothesis(hypothesis);

        Self {
            framing,
            checksum,
            fields,
            multi_byte_fields,
            evidence,
        }
    }
}
