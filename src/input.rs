use std::fs;
use std::path::Path;

pub fn parse_hex_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<Vec<u8>>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read input file: {error}"))?;

    let mut frames = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();

        // Ignore blank lines.
        if line.is_empty() {
            continue;
        }

        // Ignore comments.
        if line.starts_with('#') {
            continue;
        }

        let mut frame = Vec::new();

        for token in line.split_whitespace() {
            let byte = u8::from_str_radix(token, 16).map_err(|_| {
                format!(
                    "invalid hex byte '{}' on line {}",
                    token,
                    line_number + 1
                )
            })?;

            frame.push(byte);
        }

        if frame.is_empty() {
            return Err(format!(
                "empty frame on line {}",
                line_number + 1
            ));
        }

        frames.push(frame);
    }

    if frames.is_empty() {
        return Err("input contains no frames".to_string());
    }

    Ok(frames)
}
pub fn parse_hex_stream_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<u8>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read input file: {error}"))?;

    let mut stream = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for token in line.split_whitespace() {
            let byte = u8::from_str_radix(token, 16).map_err(|_| {
                format!(
                    "invalid hex byte '{}' on line {}",
                    token,
                    line_number + 1
                )
            })?;

            stream.push(byte);
        }
    }

    if stream.is_empty() {
        return Err("input contains no bytes".to_string());
    }

    Ok(stream)
}