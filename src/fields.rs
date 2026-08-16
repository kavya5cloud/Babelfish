use serde::Serialize;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Constant,
    Incrementing,
    Linear,
    Length,
    Cyclic,
    Variable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteFieldObservation {
    pub position: usize,
    pub unique_values: usize,
    pub min_value: u8,
    pub max_value: u8,
    pub is_constant: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldHypothesis {
    pub position: usize,
    pub kind: FieldKind,
    pub unique_values: usize,
    pub min_value: u8,
    pub max_value: u8,
    pub linear_step: Option<i16>,
}

impl FieldHypothesis {
    pub fn evidence_score(&self, frame_count: usize) -> f64 {
        if frame_count == 0 {
            return 0.0;
        }

        match self.kind {
            FieldKind::Constant => {
                if self.unique_values == 1 {
                    1.0
                } else {
                    0.0
                }
            }

            FieldKind::Incrementing | FieldKind::Linear | FieldKind::Length | FieldKind::Cyclic => {
                1.0
            }

            FieldKind::Variable => 0.25,
        }
    }
}

pub fn analyze_byte_positions(
    frames: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Vec<ByteFieldObservation> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames.iter().map(|frame| frame.len()).min().unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    let mut observations = Vec::new();

    for position in start..end {
        let mut values: Vec<u8> = frames.iter().map(|frame| frame[position]).collect();

        values.sort_unstable();
        values.dedup();

        let min_value = frames
            .iter()
            .map(|frame| frame[position])
            .min()
            .unwrap_or(0);

        let max_value = frames
            .iter()
            .map(|frame| frame[position])
            .max()
            .unwrap_or(0);

        observations.push(ByteFieldObservation {
            position,
            unique_values: values.len(),
            min_value,
            max_value,
            is_constant: values.len() == 1,
        });
    }

    observations
}

pub fn is_incrementing_byte(frames: &[Vec<u8>], position: usize) -> bool {
    if frames.len() < 2 {
        return false;
    }

    for window in frames.windows(2) {
        if window[0].len() <= position || window[1].len() <= position {
            return false;
        }

        let expected = window[0][position].wrapping_add(1);

        if window[1][position] != expected {
            return false;
        }
    }

    true
}

pub fn is_cyclic_byte(frames: &[Vec<u8>], position: usize, cycle_length: usize) -> bool {
    if frames.len() < cycle_length * 2 || cycle_length == 0 {
        return false;
    }

    let values: Vec<u8> = frames
        .iter()
        .filter_map(|frame| frame.get(position).copied())
        .collect();

    if values.len() != frames.len() {
        return false;
    }

    values
        .iter()
        .enumerate()
        .all(|(index, &value)| value == values[index % cycle_length])
}

pub fn detect_linear_byte_pattern(frames: &[Vec<u8>], position: usize) -> Option<i16> {
    if frames.len() < 3 {
        return None;
    }

    let first = *frames.get(0)?.get(position)? as i16;

    let second = *frames.get(1)?.get(position)? as i16;

    let step = second - first;

    for window in frames.windows(2) {
        let a = *window[0].get(position)? as i16;

        let b = *window[1].get(position)? as i16;

        let actual = b - a;

        if actual != step {
            return None;
        }
    }

    Some(step)
}

pub fn is_length_field(frames: &[Vec<u8>], position: usize, checksum_start: usize) -> bool {
    if frames.is_empty() || position >= checksum_start {
        return false;
    }

    let expected_length = checksum_start - position - 1;

    if expected_length > u8::MAX as usize {
        return false;
    }

    frames.iter().all(|frame| {
        if checksum_start > frame.len() {
            return false;
        }

        frame.get(position).copied() == Some(expected_length as u8)
    })
}

pub fn infer_field_hypothesis(
    frames: &[Vec<u8>],
    position: usize,
    checksum_start: usize,
) -> Option<FieldHypothesis> {
    let observations = analyze_byte_positions(frames, position, position + 1);

    let observation = observations.first()?;

    let linear_step = detect_linear_byte_pattern(frames, position);

    let kind = if is_length_field(frames, position, checksum_start) {
        FieldKind::Length
    } else if observation.is_constant {
        FieldKind::Constant
    } else if is_incrementing_byte(frames, position) {
        FieldKind::Incrementing
    } else if let Some(step) = linear_step {
        if step != 0 {
            FieldKind::Linear
        } else {
            FieldKind::Variable
        }
    } else if is_cyclic_byte(frames, position, 3) {
        FieldKind::Cyclic
    } else {
        FieldKind::Variable
    };

    Some(FieldHypothesis {
        position,
        kind,
        unique_values: observation.unique_values,
        min_value: observation.min_value,
        max_value: observation.max_value,
        linear_step,
    })
}

pub fn infer_fields(frames: &[Vec<u8>], start: usize, end: usize) -> Vec<FieldHypothesis> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames.iter().map(|frame| frame.len()).min().unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    (start..end)
        .filter_map(|position| infer_field_hypothesis(frames, position, end))
        .collect()
}

pub fn decode_u16_le(frames: &[Vec<u8>], position: usize) -> Option<Vec<u16>> {
    if frames.is_empty() {
        return None;
    }

    let mut values = Vec::with_capacity(frames.len());

    for frame in frames {
        if position + 2 > frame.len() {
            return None;
        }

        let value = u16::from_le_bytes([frame[position], frame[position + 1]]);

        values.push(value);
    }

    Some(values)
}

pub fn decode_u16_be(frames: &[Vec<u8>], position: usize) -> Option<Vec<u16>> {
    if frames.is_empty() {
        return None;
    }

    let mut values = Vec::with_capacity(frames.len());

    for frame in frames {
        if position + 2 > frame.len() {
            return None;
        }

        let value = u16::from_be_bytes([frame[position], frame[position + 1]]);

        values.push(value);
    }

    Some(values)
}

pub fn is_incrementing_u16(frames: &[Vec<u8>], position: usize, little_endian: bool) -> bool {
    let values = if little_endian {
        match decode_u16_le(frames, position) {
            Some(values) => values,
            None => return false,
        }
    } else {
        match decode_u16_be(frames, position) {
            Some(values) => values,
            None => return false,
        }
    };

    if values.len() < 2 {
        return false;
    }

    values
        .windows(2)
        .all(|window| window[1] == window[0].wrapping_add(1))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiByteKind {
    U16LittleEndian,
    U16BigEndian,
    U32LittleEndian,
    U32BigEndian,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiByteFieldHypothesis {
    pub start: usize,
    pub width: usize,
    pub kind: MultiByteKind,
    pub unique_values: usize,
    pub min_value: u64,
    pub max_value: u64,
    pub is_incrementing: bool,
}
impl MultiByteFieldHypothesis {
    pub fn score(&self) -> f64 {
        let mut score = 0.0;

        if self.unique_values > 1 {
            score += 0.4;
        }

        if self.is_incrementing {
            score += 0.4;
        }

        if self.min_value != self.max_value {
            score += 0.2;
        }

        score
    }
}

pub fn infer_u16_field(frames: &[Vec<u8>], position: usize) -> Option<MultiByteFieldHypothesis> {
    let le_values = decode_u16_le(frames, position)?;

    let be_values = decode_u16_be(frames, position)?;

    let le_incrementing = is_incrementing_u16(frames, position, true);

    let be_incrementing = is_incrementing_u16(frames, position, false);

    let (kind, values, is_incrementing) = if le_incrementing {
        (MultiByteKind::U16LittleEndian, le_values, true)
    } else if be_incrementing {
        (MultiByteKind::U16BigEndian, be_values, true)
    } else {
        return None;
    };

    let min_value = *values.iter().min()?;

    let max_value = *values.iter().max()?;

    let unique_values = values
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len();

    Some(MultiByteFieldHypothesis {
        start: position,
        width: 2,
        kind,
        unique_values,
        min_value: min_value as u64,
        max_value: max_value as u64,
        is_incrementing,
    })
}
pub fn infer_u16_fields(
    frames: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Vec<MultiByteFieldHypothesis> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames.iter().map(|frame| frame.len()).min().unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    let mut hypotheses = Vec::new();

    for position in start..end.saturating_sub(1) {
        if let Some(hypothesis) = infer_u16_field(frames, position) {
            hypotheses.push(hypothesis);
        }
    }

    hypotheses.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.start.cmp(&b.start))
    });

    hypotheses
}
pub fn decode_u32_le(frames: &[Vec<u8>], position: usize) -> Option<Vec<u32>> {
    if frames.is_empty() {
        return None;
    }

    let mut values = Vec::with_capacity(frames.len());

    for frame in frames {
        if position + 4 > frame.len() {
            return None;
        }

        let value = u32::from_le_bytes([
            frame[position],
            frame[position + 1],
            frame[position + 2],
            frame[position + 3],
        ]);

        values.push(value);
    }

    Some(values)
}

pub fn decode_u32_be(frames: &[Vec<u8>], position: usize) -> Option<Vec<u32>> {
    if frames.is_empty() {
        return None;
    }

    let mut values = Vec::with_capacity(frames.len());

    for frame in frames {
        if position + 4 > frame.len() {
            return None;
        }

        let value = u32::from_be_bytes([
            frame[position],
            frame[position + 1],
            frame[position + 2],
            frame[position + 3],
        ]);

        values.push(value);
    }

    Some(values)
}

pub fn is_incrementing_u32(frames: &[Vec<u8>], position: usize, little_endian: bool) -> bool {
    let values = if little_endian {
        match decode_u32_le(frames, position) {
            Some(values) => values,
            None => return false,
        }
    } else {
        match decode_u32_be(frames, position) {
            Some(values) => values,
            None => return false,
        }
    };

    if values.len() < 2 {
        return false;
    }

    values
        .windows(2)
        .all(|window| window[1] == window[0].wrapping_add(1))
}
pub fn infer_u32_field(frames: &[Vec<u8>], position: usize) -> Option<MultiByteFieldHypothesis> {
    let le_values = decode_u32_le(frames, position)?;
    let be_values = decode_u32_be(frames, position)?;

    let le_incrementing = is_incrementing_u32(frames, position, true);

    let be_incrementing = is_incrementing_u32(frames, position, false);

    let (kind, values, is_incrementing) = if le_incrementing {
        (MultiByteKind::U32LittleEndian, le_values, true)
    } else if be_incrementing {
        (MultiByteKind::U32BigEndian, be_values, true)
    } else {
        return None;
    };

    let min_value = *values.iter().min()? as u64;
    let max_value = *values.iter().max()? as u64;

    let unique_values = values
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len();

    Some(MultiByteFieldHypothesis {
        start: position,
        width: 4,
        kind,
        unique_values,
        min_value,
        max_value,
        is_incrementing,
    })
}
pub fn infer_u32_fields(
    frames: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Vec<MultiByteFieldHypothesis> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames.iter().map(|frame| frame.len()).min().unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    let mut hypotheses = Vec::new();

    if end.saturating_sub(start) < 4 {
        return hypotheses;
    }

    for position in start..=end - 4 {
        if let Some(hypothesis) = infer_u32_field(frames, position) {
            hypotheses.push(hypothesis);
        }
    }

    hypotheses.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.start.cmp(&b.start))
    });

    hypotheses
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FieldInterpretation {
    Constant { value: u8 },

    CounterLike { step: i16 },

    LengthLike,

    Linear { step: i16 },

    Cyclic,

    Variable,
}
impl FieldHypothesis {
    pub fn interpretation(&self) -> FieldInterpretation {
        match self.kind {
            FieldKind::Constant => FieldInterpretation::Constant {
                value: self.min_value,
            },

            FieldKind::Incrementing => FieldInterpretation::CounterLike { step: 1 },

            FieldKind::Length => FieldInterpretation::LengthLike,

            FieldKind::Linear => FieldInterpretation::Linear {
                step: self.linear_step.unwrap_or(0),
            },

            FieldKind::Cyclic => FieldInterpretation::Cyclic,

            FieldKind::Variable => FieldInterpretation::Variable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiByteInterpretation {
    pub start: usize,
    pub width: usize,
    pub kind: String,
    pub min_value: u64,
    pub max_value: u64,
    pub is_incrementing: bool,
    pub score: u64,
}
impl MultiByteFieldHypothesis {
    pub fn interpretation(&self) -> MultiByteInterpretation {
        MultiByteInterpretation {
            start: self.start,
            width: self.width,
            kind: format!("{:?}", self.kind),
            min_value: self.min_value,
            max_value: self.max_value,
            is_incrementing: self.is_incrementing,
            score: (self.score() * 100.0) as u64,
        }
    }
}
