use crate::evidence::EvidenceReport;
use crate::fields::{FieldInterpretation, MultiByteInterpretation};
use crate::hypothesis::ProtocolHypothesis;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FramingModel {
    pub kind: String,
    pub frame_count: usize,

    pub length_offset: Option<usize>,
    pub payload_offset: Option<usize>,
    pub checksum_width: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChecksumModel {
    pub algorithm: String,
    pub coverage_start: usize,
    pub coverage_end: usize,
    pub checksum_start: usize,
    pub checksum_end: usize,
}

/// A normalized field description suitable for:
/// - JSON output
/// - code generation
/// - protocol documentation
/// - future language generators
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolField {
    /// Byte offset relative to the complete frame.
    pub offset: usize,

    /// Width of the field in bytes.
    pub width: usize,

    /// Human-readable generated name.
    pub name: String,

    /// Machine-readable Rust-style data type.
    pub data_type: String,

    /// Semantic interpretation inferred from the capture.
    pub interpretation: String,

    /// Evidence supporting this interpretation.
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolModel {
    pub framing: FramingModel,
    pub checksum: ChecksumModel,

    /// Normalized protocol field schema.
    pub protocol_fields: Vec<ProtocolField>,

    /// Original byte-level interpretations.
    ///
    /// Kept for backwards compatibility and detailed inspection.
    pub fields: Vec<FieldInterpretation>,

    /// Multi-byte interpretations discovered by Babelfish.
    pub multi_byte_fields: Vec<MultiByteInterpretation>,

    pub evidence: EvidenceReport,
}

fn field_name(index: usize, field: &FieldInterpretation) -> String {
    match field {
        FieldInterpretation::Constant { .. } => {
            if index == 0 {
                "header".to_string()
            } else {
                format!("reserved_{}", index - 1)
            }
        }

        FieldInterpretation::CounterLike { .. } => {
            if index == 0 {
                "counter".to_string()
            } else {
                format!("counter_{}", index)
            }
        }

        _ => format!("field_{}", index),
    }
}

fn field_interpretation(field: &FieldInterpretation) -> String {
    match field {
        FieldInterpretation::Constant { value } => {
            format!("constant(0x{:02X})", value)
        }

        FieldInterpretation::CounterLike { step } => {
            format!("counter(step={})", step)
        }

        FieldInterpretation::LengthLike => "length".to_string(),

        FieldInterpretation::Linear { step } => {
            format!("linear(step={})", step)
        }

        FieldInterpretation::Cyclic => "cyclic".to_string(),

        FieldInterpretation::Variable => "variable".to_string(),
    }
}

fn field_confidence(field: &FieldInterpretation, evidence: &EvidenceReport, offset: usize) -> f64 {
    evidence
        .items
        .iter()
        .find(|item| {
            item.category == "Field" && item.statement.starts_with(&format!("byte {} ", offset))
        })
        .map(|item| item.score)
        .unwrap_or_else(|| match field {
            FieldInterpretation::Constant { .. } => 1.0,
            FieldInterpretation::CounterLike { .. } => 1.0,
            FieldInterpretation::LengthLike => 1.0,
            FieldInterpretation::Linear { .. } => 1.0,
            FieldInterpretation::Cyclic => 1.0,
            FieldInterpretation::Variable => 0.0,
        })
}

impl ProtocolModel {
    pub fn from_hypothesis(hypothesis: &ProtocolHypothesis) -> Self {
        let framing = match &hypothesis.framing.kind {
            crate::framing::FramingKind::Prefix(prefix) => FramingModel {
                kind: format!("prefix {:02X?}", prefix),
                frame_count: hypothesis.framing.frame_count,
                length_offset: None,
                payload_offset: None,
                checksum_width: hypothesis.checksum.algorithm.width(),
            },

            crate::framing::FramingKind::Length {
                length_offset,
                payload_offset,
                checksum_width,
            } => FramingModel {
                kind: format!(
                    "length byte {}, payload {}, checksum {} byte(s)",
                    length_offset, payload_offset, checksum_width
                ),
                frame_count: hypothesis.framing.frame_count,
                length_offset: Some(*length_offset),
                payload_offset: Some(*payload_offset),
                checksum_width: *checksum_width,
            },
        };

        let checksum = ChecksumModel {
            algorithm: hypothesis.checksum.algorithm.name().to_string(),
            coverage_start: hypothesis.checksum.coverage_start,
            coverage_end: hypothesis.checksum.coverage_end,
            checksum_start: hypothesis.checksum.checksum_start,
            checksum_end: hypothesis.checksum.checksum_end,
        };

        let fields: Vec<FieldInterpretation> = hypothesis
            .fields
            .iter()
            .map(|field| field.interpretation())
            .collect();

        let multi_byte_fields: Vec<MultiByteInterpretation> = hypothesis
            .multi_byte_fields
            .iter()
            .map(|field| field.interpretation())
            .collect();

        let evidence = EvidenceReport::from_hypothesis(hypothesis);

        /*
         * FieldInterpretation positions are relative to the checksum
         * coverage range. Build the normalized schema with absolute
         * frame offsets.
         */
        let mut protocol_fields = Vec::new();

        let unique_multi_byte = {
            let best_score = multi_byte_fields.iter().map(|field| field.score).max();

            match best_score {
                Some(best_score) => {
                    let candidates: Vec<&MultiByteInterpretation> = multi_byte_fields
                        .iter()
                        .filter(|field| field.score == best_score)
                        .collect();

                    if candidates.len() == 1 {
                        Some(candidates[0])
                    } else {
                        None
                    }
                }

                None => None,
            }
        };

        for (index, field) in fields.iter().enumerate() {
            let offset = checksum.coverage_start + index;

            if offset >= checksum.checksum_start {
                break;
            }

            if let Some(multi) = unique_multi_byte {
                if offset == checksum.coverage_start + multi.start {
                    let data_type = match multi.kind.as_str() {
                        "U16LittleEndian" | "U16BigEndian" => "u16",
                        "U32LittleEndian" | "U32BigEndian" => "u32",
                        _ => "bytes",
                    };

                    protocol_fields.push(ProtocolField {
                        offset,
                        width: multi.width,
                        name: format!("value_{}", offset),
                        data_type: data_type.to_string(),
                        interpretation: multi.kind.clone(),
                        confidence: multi.score as f64 / 100.0,
                    });

                    continue;
                }

                if offset > checksum.coverage_start + multi.start
                    && offset < checksum.coverage_start + multi.start + multi.width
                {
                    continue;
                }
            }

            protocol_fields.push(ProtocolField {
                offset,
                width: 1,
                name: field_name(index, field),
                data_type: "u8".to_string(),
                interpretation: field_interpretation(field),
                confidence: field_confidence(field, &evidence, offset),
            });
        }

        Self {
            framing,
            checksum,
            protocol_fields,
            fields,
            multi_byte_fields,
            evidence,
        }
    }
}
