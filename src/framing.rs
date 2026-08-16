use crate::checksum::search::best_candidate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingKind {
    Prefix(Vec<u8>),

    Length {
        length_offset: usize,
        payload_offset: usize,
        checksum_width: usize,
    },
}

impl FramingKind {
    pub fn complexity(&self) -> usize {
        match self {
            FramingKind::Prefix(prefix) => prefix.len(),

            FramingKind::Length {
                length_offset,
                payload_offset,
                checksum_width,
            } => {
                1 + *length_offset
                    + *payload_offset
                    + *checksum_width
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramingCandidate {
    pub kind: FramingKind,
    pub frame_count: usize,
    pub checksum_algorithm: Option<String>,
    pub checksum_validation_count: usize,
    pub checksum_total_frames: usize,
}

impl FramingCandidate {
    pub fn checksum_validation_rate(&self) -> f64 {
        if self.checksum_total_frames == 0 {
            return 0.0;
        }

        self.checksum_validation_count as f64
            / self.checksum_total_frames as f64
    }

    pub fn score(&self) -> f64 {
        let validation_rate =
            self.checksum_validation_rate();

        if self.checksum_total_frames == 0 {
            return 0.0;
        }

        let evidence_factor =
            1.0
                - (-((self.checksum_total_frames as f64) / 20.0))
                    .exp();

        let validation_score =
            validation_rate * evidence_factor;

        let complexity_penalty =
            self.kind.complexity() as f64 * 0.01;

        validation_score - complexity_penalty
    }

    pub fn confidence(&self) -> f64 {
        if self.checksum_total_frames == 0 {
            return 0.0;
        }

        let validation_rate =
            self.checksum_validation_rate();

        let evidence_factor =
            1.0
                - (-((self.checksum_total_frames as f64) / 20.0))
                    .exp();

        validation_rate * evidence_factor
    }

    pub fn verdict(&self) -> &'static str {
        let confidence = self.confidence();

        if self.checksum_validation_count
            == self.checksum_total_frames
            && self.checksum_total_frames >= 100
        {
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

pub fn rank_framing_candidates(
    mut candidates: Vec<FramingCandidate>,
) -> Vec<FramingCandidate> {
    candidates.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.kind
                    .complexity()
                    .cmp(&b.kind.complexity())
            })
            .then_with(|| {
                b.frame_count.cmp(&a.frame_count)
            })
    });

    candidates
}

pub fn find_recurring_prefixes(
    stream: &[u8],
    min_length: usize,
    max_length: usize,
) -> Vec<Vec<u8>> {
    if stream.is_empty()
        || min_length == 0
        || min_length > max_length
    {
        return Vec::new();
    }

    let mut results = Vec::new();

    for length in min_length..=max_length {
        if length > stream.len() {
            break;
        }

        let mut candidates = Vec::new();

        for start in 0..=stream.len() - length {
            let sequence =
                &stream[start..start + length];

            let mut occurrences = 0;

            for position in 0..=stream.len() - length {
                if &stream[position..position + length]
                    == sequence
                {
                    occurrences += 1;
                }
            }

            if occurrences >= 2 {
                candidates.push((
                    sequence.to_vec(),
                    occurrences,
                ));
            }
        }

        candidates.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.cmp(&b.0))
        });

        for (sequence, _) in candidates {
            if !results.contains(&sequence) {
                results.push(sequence);
            }
        }
    }

    results
}

pub fn split_on_prefix(
    stream: &[u8],
    prefix: &[u8],
) -> Vec<Vec<u8>> {
    if stream.is_empty() || prefix.is_empty() {
        return Vec::new();
    }

    let mut starts = Vec::new();

    for position in 0..=stream
        .len()
        .saturating_sub(prefix.len())
    {
        if &stream[
            position..position + prefix.len()
        ] == prefix
        {
            starts.push(position);
        }
    }

    if starts.is_empty() {
        return Vec::new();
    }

    let mut frames = Vec::new();

    for window in starts.windows(2) {
        let start = window[0];
        let end = window[1];

        frames.push(stream[start..end].to_vec());
    }

    if let Some(&last_start) = starts.last() {
        frames.push(stream[last_start..].to_vec());
    }

    frames
}

pub fn split_on_length_field(
    stream: &[u8],
    length_offset: usize,
    payload_offset: usize,
    checksum_width: usize,
) -> Vec<Vec<u8>> {
    if stream.is_empty()
        || length_offset >= stream.len()
        || payload_offset > stream.len()
    {
        return Vec::new();
    }

    let mut frames = Vec::new();
    let mut position = 0;

    while position < stream.len() {
        if position + length_offset >= stream.len() {
            break;
        }

        let length =
            stream[position + length_offset] as usize;

        let frame_len =
            (payload_offset - length_offset)
                + length
                + checksum_width;

        if frame_len == 0
            || position + frame_len > stream.len()
        {
            break;
        }

        frames.push(
            stream[
                position..position + frame_len
            ]
            .to_vec(),
        );

        position += frame_len;
    }

    frames
}

pub fn build_framing_candidates(
    stream: &[u8],
    min_prefix_length: usize,
    max_prefix_length: usize,
) -> Vec<FramingCandidate> {
    let prefixes = find_recurring_prefixes(
        stream,
        min_prefix_length,
        max_prefix_length,
    );

    let candidates = prefixes
        .into_iter()
        .filter_map(|prefix| {
            let frames =
                split_on_prefix(stream, &prefix);

            if frames.len() < 2 {
                return None;
            }

            match best_candidate(&frames) {
                Some(checksum) => {
                    Some(FramingCandidate {
                        kind: FramingKind::Prefix(
                            prefix,
                        ),
                        frame_count: frames.len(),
                        checksum_algorithm: Some(
                            checksum
                                .algorithm
                                .name()
                                .to_string(),
                        ),
                        checksum_validation_count:
                            checksum.validation_count,
                        checksum_total_frames:
                            checksum.total_frames,
                    })
                }

                None => None,
            }
        })
        .collect();

    rank_framing_candidates(candidates)
}

pub fn best_framing_candidate(
    stream: &[u8],
    min_prefix_length: usize,
    max_prefix_length: usize,
) -> Option<FramingCandidate> {
    build_framing_candidates(
        stream,
        min_prefix_length,
        max_prefix_length,
    )
    .into_iter()
    .next()
}

pub fn infer_length_framing_candidates(
    stream: &[u8],
    min_length_offset: usize,
    max_length_offset: usize,
    payload_offset: usize,
    checksum_width: usize,
) -> Vec<FramingCandidate> {
    if stream.is_empty()
        || min_length_offset > max_length_offset
    {
        return Vec::new();
    }

    let mut candidates = Vec::new();

    for length_offset in
        min_length_offset..=max_length_offset
    {
        let frames = split_on_length_field(
            stream,
            length_offset,
            payload_offset,
            checksum_width,
        );

        if frames.len() < 2 {
            continue;
        }

        let Some(checksum) =
            best_candidate(&frames)
        else {
            continue;
        };

        candidates.push(
            FramingCandidate {
                kind: FramingKind::Length {
                    length_offset,
                    payload_offset,
                    checksum_width,
                },
                frame_count: frames.len(),
                checksum_algorithm: Some(
                    checksum
                        .algorithm
                        .name()
                        .to_string(),
                ),
                checksum_validation_count:
                    checksum.validation_count,
                checksum_total_frames:
                    checksum.total_frames,
            },
        );
    }

    rank_framing_candidates(candidates)
}