use super::algorithms::{Checksum, ChecksumCandidate};

pub fn validate_frame(
    algorithm: &dyn Checksum,
    frame: &[u8],
    coverage_start: usize,
    checksum_offset: usize,
) -> bool {
    let checksum_width = algorithm.width();

    if coverage_start > checksum_offset {
        return false;
    }

    if checksum_offset + checksum_width > frame.len() {
        return false;
    }

    let data = &frame[coverage_start..checksum_offset];
    let expected_bytes = &frame[checksum_offset..checksum_offset + checksum_width];

    let calculated = algorithm.calculate(data);
    let expected = bytes_to_u32(expected_bytes);

    calculated == expected
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .enumerate()
        .fold(0u32, |value, (index, &byte)| {
            value | ((byte as u32) << (index * 8))
        })
}

pub fn validate_frame_at_end(
    algorithm: &dyn Checksum,
    frame: &[u8],
    coverage_start: usize,
) -> bool {
    let checksum_width = algorithm.width();

    if frame.len() < checksum_width {
        return false;
    }

    let checksum_offset = frame.len() - checksum_width;

    validate_frame(algorithm, frame, coverage_start, checksum_offset)
}

pub fn count_valid_frames(
    algorithm: &dyn Checksum,
    frames: &[Vec<u8>],
    coverage_start: usize,
) -> usize {
    frames
        .iter()
        .filter(|frame| validate_frame_at_end(algorithm, frame, coverage_start))
        .count()
}

pub fn failed_frame_indexes(
    algorithm: &dyn Checksum,
    frames: &[Vec<u8>],
    coverage_start: usize,
) -> Vec<usize> {
    frames
        .iter()
        .enumerate()
        .filter_map(|(index, frame)| {
            if validate_frame_at_end(algorithm, frame, coverage_start) {
                None
            } else {
                Some(index)
            }
        })
        .collect()
}

pub fn find_checksum_position(algorithm: &dyn Checksum, frames: &[Vec<u8>]) -> Vec<usize> {
    if frames.is_empty() {
        return Vec::new();
    }

    let checksum_width = algorithm.width();

    let mut positions = Vec::new();

    let Some(min_len) = frames.iter().map(|frame| frame.len()).min() else {
        return positions;
    };

    if min_len < checksum_width {
        return positions;
    }

    let max_offset = min_len - checksum_width;

    for offset in 0..=max_offset {
        if frames
            .iter()
            .all(|frame| validate_frame(algorithm, frame, 0, offset))
        {
            positions.push(offset);
        }
    }

    positions
}

pub fn default_algorithms() -> Vec<Box<dyn Checksum>> {
    vec![
        Box::new(super::Crc16Modbus),
        Box::new(super::Crc8),
        Box::new(super::XorChecksum),
        Box::new(super::Sum8),
        Box::new(super::Sum16),
    ]
}

pub fn search_algorithms(frames: &[Vec<u8>]) -> Vec<ChecksumCandidate> {
    if frames.is_empty() {
        return Vec::new();
    }

    default_algorithms()
        .into_iter()
        .filter_map(|algorithm| {
            let (coverage_start, validation_count) =
                best_coverage_candidate(algorithm.as_ref(), frames)?;

            let checksum_width = algorithm.width();

            let min_frame_len = frames.iter().map(|frame| frame.len()).min()?;

            if min_frame_len < checksum_width {
                return None;
            }

            /*
             * For variable-length frames the checksum lives at the
             * end of every frame.
             *
             * Therefore checksum_start/checksum_end describe the
             * shortest frame's checksum position for the model,
             * while validation itself uses each frame's own end.
             */
            let checksum_start = min_frame_len - checksum_width;
            let checksum_end = min_frame_len;

            let failed_frames = failed_frame_indexes(algorithm.as_ref(), frames, coverage_start);

            Some(ChecksumCandidate {
                algorithm,
                coverage_start,
                coverage_end: checksum_start,
                checksum_start,
                checksum_end,
                validation_count,
                total_frames: frames.len(),
                failed_frames,
            })
        })
        .collect()
}

pub fn rank_candidates(mut candidates: Vec<ChecksumCandidate>) -> Vec<ChecksumCandidate> {
    candidates.sort_by(|a, b| {
        b.validation_rate()
            .partial_cmp(&a.validation_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.validation_count.cmp(&a.validation_count))
    });

    candidates
}

pub fn best_candidate(frames: &[Vec<u8>]) -> Option<ChecksumCandidate> {
    let candidates = search_algorithms(frames);
    let ranked = rank_candidates(candidates);

    ranked.into_iter().next()
}

pub fn coverage_candidates(algorithm: &dyn Checksum, frames: &[Vec<u8>]) -> Vec<usize> {
    if frames.is_empty() {
        return Vec::new();
    }

    let checksum_width = algorithm.width();

    if frames.iter().any(|frame| frame.len() < checksum_width) {
        return Vec::new();
    }

    let max_coverage_start = frames
        .iter()
        .map(|frame| frame.len() - checksum_width)
        .min()
        .unwrap_or(0);

    (0..=max_coverage_start)
        .filter(|&coverage_start| {
            frames
                .iter()
                .all(|frame| validate_frame_at_end(algorithm, frame, coverage_start))
        })
        .collect()
}

pub fn best_coverage_candidate(
    algorithm: &dyn Checksum,
    frames: &[Vec<u8>],
) -> Option<(usize, usize)> {
    if frames.is_empty() {
        return None;
    }

    let checksum_width = algorithm.width();

    let max_coverage_start = frames
        .iter()
        .filter_map(|frame| {
            if frame.len() < checksum_width {
                None
            } else {
                Some(frame.len() - checksum_width)
            }
        })
        .min()?;

    (0..=max_coverage_start)
        .map(|coverage_start| {
            let validation_count = count_valid_frames(algorithm, frames, coverage_start);

            (coverage_start, validation_count)
        })
        .max_by(|a, b| a.1.cmp(&b.1))
}
