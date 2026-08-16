use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    pub category: &'static str,
    pub statement: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceReport {
    pub items: Vec<EvidenceItem>,

    /// Strength of the observations found in the data.
    pub evidence_strength: f64,

    /// Confidence that the current protocol interpretation
    /// is the unique/best explanation.
    pub interpretation_confidence: f64,

    /// Whether competing interpretations remain.
    pub ambiguous: bool,
}

impl EvidenceReport {
    pub fn from_hypothesis(hypothesis: &crate::hypothesis::ProtocolHypothesis) -> Self {
        let mut items = Vec::new();

        let framing_score = hypothesis.framing.checksum_validation_rate();

        items.push(EvidenceItem {
            category: "Framing",
            statement: format!(
                "{} frames recovered with consistent framing",
                hypothesis.framing.frame_count
            ),
            score: framing_score,
        });

        let checksum_score = hypothesis.checksum.confidence();

        items.push(EvidenceItem {
            category: "Checksum",
            statement: format!(
                "{} validates {}/{} frames",
                hypothesis.checksum.algorithm.name(),
                hypothesis.checksum.validation_count,
                hypothesis.checksum.total_frames
            ),
            score: checksum_score,
        });

        for field in &hypothesis.fields {
            items.push(EvidenceItem {
                category: "Field",
                statement: format!("byte {} → {:?}", field.position, field.kind),
                score: field.evidence_score(hypothesis.framing.frame_count),
            });
        }

        for field in &hypothesis.multi_byte_fields {
            items.push(EvidenceItem {
                category: "MultiByte",
                statement: format!(
                    "bytes[{}..{}] → {:?}",
                    field.start,
                    field.start + field.width,
                    field.kind
                ),
                score: field.score(),
            });
        }

        let evidence_strength = if items.is_empty() {
            0.0
        } else {
            items.iter().map(|item| item.score).sum::<f64>() / items.len() as f64
        };

        let ambiguous = hypothesis.ambiguous_multi_byte_fields().len() > 1;

        let interpretation_confidence = if ambiguous {
            // Strong evidence exists, but there is no
            // unique multi-byte interpretation.
            evidence_strength * 0.75
        } else {
            evidence_strength
        };

        Self {
            items,
            evidence_strength,
            interpretation_confidence,
            ambiguous,
        }
    }
}
