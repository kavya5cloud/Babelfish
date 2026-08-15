use crate::checksum::search::best_candidate;

pub struct FramingCandidate {
    pub prefix: Vec<u8>,
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
        self.checksum_validation_rate()
    }
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
            let sequence = &stream[start..start + length];

            let mut occurrences = 0;

            for position in 0..=stream.len() - length {
                if &stream[position..position + length] == sequence {
                    occurrences += 1;
                }
            }

            if occurrences >= 2 {
                candidates.push((sequence.to_vec(), occurrences));
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
        if &stream[position..position + prefix.len()]
            == prefix
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
            let frames = split_on_prefix(
                stream,
                &prefix,
            );

            if frames.len() < 2 {
                return None;
            }

            let checksum = best_candidate(&frames);

            match checksum {
                Some(candidate) => Some(
                    FramingCandidate {
                        prefix,
                        frame_count: frames.len(),
                        checksum_algorithm: Some(
                            candidate
                                .algorithm
                                .name()
                                .to_string(),
                        ),
                        checksum_validation_count:
                            candidate
                                .validation_count,
                        checksum_total_frames:
                            candidate.total_frames,
                    },
                ),

                None => Some(
                    FramingCandidate {
                        prefix,
                        frame_count: frames.len(),
                        checksum_algorithm: None,
                        checksum_validation_count: 0,
                        checksum_total_frames:
                            frames.len(),
                    },
                ),
            }
        })
        .collect();

    rank_framing_candidates(candidates)
}

pub fn rank_framing_candidates(
    mut candidates: Vec<FramingCandidate>,
) -> Vec<FramingCandidate> {
    candidates.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(
                std::cmp::Ordering::Equal,
            )
            .then_with(|| {
                b.frame_count.cmp(&a.frame_count)
            })
    });

    candidates
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
            let frames = split_on_prefix(
                stream,
                &prefix,
            );

            if frames.len() < 2 {
                return None;
            }

            match best_candidate(&frames) {
                Some(candidate) => Some(FramingCandidate {
                    prefix,
                    frame_count: frames.len(),
                    checksum_algorithm: Some(
                        candidate.algorithm.name().to_string(),
                    ),
                    checksum_validation_count:
                        candidate.validation_count,
                    checksum_total_frames:
                        candidate.total_frames,
                }),

                None => Some(FramingCandidate {
                    prefix,
                    frame_count: frames.len(),
                    checksum_algorithm: None,
                    checksum_validation_count: 0,
                    checksum_total_frames: frames.len(),
                }),
            }
        })
        .collect();

    rank_framing_candidates(candidates)
}