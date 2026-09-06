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
    pub overall: f64,

    // Backwards-compatible evidence metrics.
    pub evidence_strength: f64,
    pub interpretation_confidence: f64,
    pub ambiguous: bool,
}

impl EvidenceReport {
    pub fn from_hypothesis(hypothesis: &crate::hypothesis::ProtocolHypothesis) -> Self {
        let mut items = Vec::new();

        let framing_score = if hypothesis.framing.checksum_total_frames > 0
            && hypothesis.framing.checksum_validation_count == 0
        {
            1.0
        } else {
            hypothesis.framing.checksum_validation_rate()
        };

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

        items.push(EvidenceItem {
            category: "Checksum",
            statement: format!(
                "checksum occupies bytes[{}..{}] and covers bytes[{}..{}]",
                hypothesis.checksum.checksum_start,
                hypothesis.checksum.checksum_end,
                hypothesis.checksum.coverage_start,
                hypothesis.checksum.coverage_end
            ),
            score: checksum_score,
        });

        for field in &hypothesis.fields {
            items.push(EvidenceItem {
                category: "Field",
                statement: format!(
                    "byte {} → {:?} ({} unique values, range {}..={})",
                    field.position,
                    field.kind,
                    field.unique_values,
                    field.min_value,
                    field.max_value
                ),
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

        let overall = if items.is_empty() {
            0.0
        } else {
            items.iter().map(|item| item.score).sum::<f64>() / items.len() as f64
        };

        // Preserve the original interpretation semantics expected by
        // main.rs and the existing test suite.
        let evidence_strength = overall;

        let interpretation_confidence = if hypothesis.multi_byte_fields.is_empty() {
            overall
        } else {
            let best = hypothesis
                .multi_byte_fields
                .iter()
                .map(|field| field.score())
                .fold(0.0_f64, f64::max);

            let second = hypothesis
                .multi_byte_fields
                .iter()
                .map(|field| field.score())
                .filter(|score| *score < best)
                .fold(0.0_f64, f64::max);

            if best > 0.0 && second > 0.0 {
                second / best
            } else {
                overall
            }
        };

        let ambiguous = hypothesis.multi_byte_fields.len() > 1 && {
            let mut scores: Vec<f64> = hypothesis
                .multi_byte_fields
                .iter()
                .map(|field| field.score())
                .collect();

            scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

            scores.len() >= 2 && (scores[0] - scores[1]).abs() < 0.000_001
        };

        Self {
            items,
            overall,
            evidence_strength,
            interpretation_confidence,
            ambiguous,
        }
    }
}
