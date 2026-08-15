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

pub fn analyze_byte_positions(
    frames: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Vec<ByteFieldObservation> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames
        .iter()
        .map(|frame| frame.len())
        .min()
        .unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    let mut observations = Vec::new();

    for position in start..end {
        let mut values: Vec<u8> = frames
            .iter()
            .map(|frame| frame[position])
            .collect();

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

pub fn is_incrementing_byte(
    frames: &[Vec<u8>],
    position: usize,
) -> bool {
    if frames.len() < 2 {
        return false;
    }

    for window in frames.windows(2) {
        if window[0].len() <= position
            || window[1].len() <= position
        {
            return false;
        }

        let expected =
            window[0][position].wrapping_add(1);

        if window[1][position] != expected {
            return false;
        }
    }

    true
}

pub fn is_cyclic_byte(
    frames: &[Vec<u8>],
    position: usize,
    cycle_length: usize,
) -> bool {
    if frames.len() < cycle_length * 2
        || cycle_length == 0
    {
        return false;
    }

    let values: Vec<u8> = frames
        .iter()
        .filter_map(|frame| frame.get(position).copied())
        .collect();

    if values.len() != frames.len() {
        return false;
    }

    values.iter().enumerate().all(
        |(index, &value)| {
            value == values[index % cycle_length]
        },
    )
}

pub fn detect_linear_byte_pattern(
    frames: &[Vec<u8>],
    position: usize,
) -> Option<i16> {
    if frames.len() < 3 {
        return None;
    }

    let first =
        *frames.get(0)?.get(position)? as i16;

    let second =
        *frames.get(1)?.get(position)? as i16;

    let step = second - first;

    for window in frames.windows(2) {
        let a =
            *window[0].get(position)? as i16;

        let b =
            *window[1].get(position)? as i16;

        let actual = b - a;

        if actual != step {
            return None;
        }
    }

    Some(step)
}

pub fn is_length_field(
    frames: &[Vec<u8>],
    position: usize,
    checksum_start: usize,
) -> bool {
    if frames.is_empty()
        || position >= checksum_start
    {
        return false;
    }

    let expected_length =
        checksum_start - position - 1;

    if expected_length > u8::MAX as usize {
        return false;
    }

    frames.iter().all(|frame| {
        if checksum_start > frame.len() {
            return false;
        }

        frame.get(position).copied()
            == Some(expected_length as u8)
    })
}

pub fn infer_field_hypothesis(
    frames: &[Vec<u8>],
    position: usize,
    checksum_start: usize,
) -> Option<FieldHypothesis> {
    let observations =
        analyze_byte_positions(
            frames,
            position,
            position + 1,
        );

    let observation = observations.first()?;

    let linear_step =
        detect_linear_byte_pattern(
            frames,
            position,
        );

    let kind =
    if is_length_field(
        frames,
        position,
        checksum_start,
    ) {
        FieldKind::Length
    } else if observation.is_constant {
        FieldKind::Constant
    } else if is_incrementing_byte(
        frames,
        position,
    ) {
        FieldKind::Incrementing
    } else if let Some(step) = linear_step {
        if step != 0 {
            FieldKind::Linear
        } else {
            FieldKind::Variable
        }
    } else if is_cyclic_byte(
        frames,
        position,
        3,
    ) {
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

pub fn infer_fields(
    frames: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Vec<FieldHypothesis> {
    if frames.is_empty() || start >= end {
        return Vec::new();
    }

    let max_position = frames
        .iter()
        .map(|frame| frame.len())
        .min()
        .unwrap_or(0);

    let end = end.min(max_position);

    if start >= end {
        return Vec::new();
    }

    (start..end)
        .filter_map(|position| {
            infer_field_hypothesis(
                frames,
                position,
                end,
            )
        })
        .collect()
}