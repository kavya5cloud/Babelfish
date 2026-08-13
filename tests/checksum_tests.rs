mod common;

use babelfish::{
    Checksum,
    Crc16Modbus,
    Crc8,
    Sum8,
    Sum16,
};

#[test]
fn crc16_modbus_known_value() {
    let crc = Crc16Modbus;

    let result = crc.calculate(b"123456789");

    assert_eq!(result, 0x4B37);
}
#[test]
fn sum16_known_value() {
    let sum = Sum16;

    let result = sum.calculate(&[0x01, 0x02, 0x03, 0x04]);

    assert_eq!(result, 0x000A);
}
#[test]
fn sum8_known_value() {
    let sum = Sum8;

    let result = sum.calculate(&[0x01, 0x02, 0x03, 0x04]);

    assert_eq!(result, 0x0A);
}

#[test]
fn crc8_known_value() {
    let crc = Crc8;

    let result = crc.calculate(b"123456789");

    assert_eq!(result, 0xF4);
}

#[test]
fn validates_crc16_modbus_frame() {
    let crc = Crc16Modbus;

    // CRC16/MODBUS of [0x01, 0x02, 0x03, 0x04]
    // is 0x2BA1, stored little-endian as A1 2B.
    let frame = [0x01, 0x02, 0x03, 0x04, 0xA1, 0x2B];

    let valid = babelfish::checksum::search::validate_frame(
        &crc,
        &frame,
        0,
        4,
    );

    assert!(valid);
}

#[test]
fn validates_multiple_crc16_modbus_frames() {
    let crc = Crc16Modbus;

    let data1 = vec![0x01, 0x02, 0x03, 0x04];
    let data2 = vec![0x10, 0x20, 0x30, 0x40];

    let crc1 = crc.calculate(&data1);
    let crc2 = crc.calculate(&data2);

    let mut frame1 = data1.clone();
    frame1.extend_from_slice(&(crc1 as u16).to_le_bytes());

    let mut frame2 = data2.clone();
    frame2.extend_from_slice(&(crc2 as u16).to_le_bytes());

    let invalid_frame = vec![
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00,
    ];

    let frames = vec![
        frame1,
        frame2,
        invalid_frame,
    ];

    let valid_count =
        babelfish::checksum::search::count_valid_frames(
            &crc,
            &frames,
            0,
        );

    assert_eq!(valid_count, 2);
}

#[test]
fn validates_100_synthetic_frames() {
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x01,
            i,
            i.wrapping_mul(3),
            i.wrapping_add(10),
        ];

        frames.push(
            common::make_crc16_modbus_frame(&data)
        );
    }

    let crc = Crc16Modbus;

    let valid_count =
        babelfish::checksum::search::count_valid_frames(
            &crc,
            &frames,
            0,
        );

    assert_eq!(valid_count, 100);
}

#[test]
fn discovers_crc16_modbus_checksum_position() {
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x01,
            i,
            i.wrapping_mul(3),
            i.wrapping_add(10),
        ];

        frames.push(
            common::make_crc16_modbus_frame(&data)
        );
    }

    let crc = Crc16Modbus;

    let positions =
        babelfish::checksum::search::find_checksum_position(
            &crc,
            &frames,
        );

    assert_eq!(positions, vec![4]);
}

#[test]
fn identifies_crc16_modbus_from_unknown_frames() {
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x01,
            i,
            i.wrapping_mul(3),
            i.wrapping_add(10),
        ];

        frames.push(
            common::make_crc16_modbus_frame(&data)
        );
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &frames,
        );

    let crc_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC16/MODBUS"
        })
        .expect(
            "CRC16/MODBUS candidate should exist"
        );

    assert_eq!(crc_candidate.validation_count, 100);
    assert_eq!(crc_candidate.total_frames, 100);

    let xor_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "XOR"
        })
        .expect("XOR candidate should exist");

    assert!(xor_candidate.validation_count < 100);
}

#[test]
fn returns_crc16_modbus_as_best_candidate() {
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x01,
            i,
            i.wrapping_mul(3),
            i.wrapping_add(10),
        ];

        frames.push(
            common::make_crc16_modbus_frame(&data)
        );
    }

    let best =
        babelfish::checksum::search::best_candidate(&frames)
            .expect("a candidate should exist");

    assert_eq!(
        best.algorithm.name(),
        "CRC16/MODBUS"
    );

    assert_eq!(best.validation_count, 100);
    assert_eq!(best.total_frames, 100);
    assert!(best.is_proven());
}

#[test]
fn discovers_checksum_coverage_after_header() {
    let crc = Crc16Modbus;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            i,
            i.wrapping_mul(3),
            i.wrapping_add(10),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = vec![0xAA];

        frame.extend_from_slice(&data);

        frame.extend_from_slice(
            &(checksum as u16).to_le_bytes()
        );

        frames.push(frame);
    }

    let positions =
        babelfish::checksum::search::coverage_candidates(
            &crc,
            &frames,
        );

    assert_eq!(positions, vec![1]);
}

#[test]
fn validates_variable_length_frames() {
    let crc = Crc16Modbus;

    let data1 = vec![0x01, 0x02, 0x03];
    let data2 = vec![
        0x10, 0x20, 0x30, 0x40, 0x50,
    ];
    let data3 = vec![
        0xAA, 0xBB, 0xCC, 0xDD,
    ];

    let make_frame = |data: &[u8]| {
        let checksum = crc.calculate(data);

        let mut frame = data.to_vec();

        frame.extend_from_slice(
            &(checksum as u16).to_le_bytes()
        );

        frame
    };

    let frames = vec![
        make_frame(&data1),
        make_frame(&data2),
        make_frame(&data3),
    ];

    let valid_count =
        babelfish::checksum::search::count_valid_frames(
            &crc,
            &frames,
            0,
        );

    assert_eq!(valid_count, 3);
}

#[test]
fn identifies_crc8_from_unknown_frames() {
    let crc = Crc8;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x10,
            i,
            i.wrapping_mul(5),
            i.wrapping_add(7),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &frames,
        );

    let crc8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(crc8_candidate.validation_count, 100);
    assert_eq!(crc8_candidate.total_frames, 100);

    let crc16_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC16/MODBUS"
        })
        .expect("CRC16/MODBUS candidate should exist");

    assert!(crc16_candidate.validation_count < 100);
}

#[test]
fn discovers_crc8_coverage_after_header() {
    let crc = Crc8;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            i,
            i.wrapping_mul(5),
            i.wrapping_add(7),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = vec![0xAA];
        frame.extend_from_slice(&data);
        frame.push(checksum as u8);

        frames.push(frame);
    }

    let positions =
        babelfish::checksum::search::coverage_candidates(
            &crc,
            &frames,
        );

    assert_eq!(positions, vec![1]);
}

#[test]
fn selects_crc8_over_other_algorithms() {
    let crc = Crc8;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x10,
            i,
            i.wrapping_mul(5),
            i.wrapping_add(7),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    let best =
        babelfish::checksum::search::best_candidate(&frames)
            .expect("a candidate should exist");

    assert_eq!(best.algorithm.name(), "CRC8");
    assert_eq!(best.validation_count, 100);
    assert_eq!(best.total_frames, 100);
    assert!(best.is_proven());
}

#[test]
fn calculates_candidate_confidence() {
    let frames = vec![
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
    ];

    let candidates =
        babelfish::checksum::search::search_algorithms(&frames);

    let crc8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(crc8_candidate.validation_rate(), 0.0);
    assert_eq!(crc8_candidate.confidence(), 0.0);
}

#[test]
fn confidence_increases_with_more_valid_frames() {
    let mut few_frames = Vec::new();

    for i in 0u8..5 {
        let data = vec![0x10, i, i.wrapping_add(1)];
        let crc = Crc8;
        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        few_frames.push(frame);
    }

    let mut many_frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![0x10, i, i.wrapping_add(1)];
        let crc = Crc8;
        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        many_frames.push(frame);
    }

    let few_candidates =
        babelfish::checksum::search::search_algorithms(
            &few_frames,
        );

    let many_candidates =
        babelfish::checksum::search::search_algorithms(
            &many_frames,
        );

    let few = few_candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    let many = many_candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(few.validation_count, 5);
    assert_eq!(many.validation_count, 100);

    assert_eq!(few.validation_rate(), 1.0);
    assert_eq!(many.validation_rate(), 1.0);

    assert!(many.confidence() > few.confidence());
}
#[test]
fn confidence_drops_when_frames_fail_validation() {
    let crc = Crc8;

    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x10,
            i,
            i.wrapping_add(1),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    // Corrupt 50 of the 100 frames.
    for frame in frames.iter_mut().take(50) {
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(&frames);

    let crc8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(crc8_candidate.validation_count, 50);
    assert_eq!(crc8_candidate.total_frames, 100);

    assert_eq!(crc8_candidate.validation_rate(), 0.5);

    assert!(crc8_candidate.confidence() < 0.5);
}

#[test]
fn candidate_verdicts_are_correct() {
    let crc = Crc8;

    // Build 100 valid CRC8 frames.
    let mut valid_frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x10,
            i,
            i.wrapping_add(1),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        valid_frames.push(frame);
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &valid_frames,
        );

    let proven = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(proven.verdict(), "PROVEN");
}

#[test]
fn candidate_verdict_rejects_low_confidence() {
    let crc = Crc8;

    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x10,
            i,
            i.wrapping_add(1),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    // Corrupt every frame.
    for frame in &mut frames {
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &frames,
        );

    let crc8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert_eq!(crc8_candidate.validation_count, 0);
    assert_eq!(crc8_candidate.verdict(), "REJECTED");
}
#[test]
fn identifies_sum8_from_unknown_frames() {
    let sum = Sum8;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x20,
            i,
            i.wrapping_mul(7),
            i.wrapping_add(3),
        ];

        let checksum = sum.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &frames,
        );

    let sum8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "SUM8"
        })
        .expect("SUM8 candidate should exist");

    assert_eq!(sum8_candidate.validation_count, 100);
    assert_eq!(sum8_candidate.total_frames, 100);
    assert!(sum8_candidate.is_proven());

    let crc8_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC8"
        })
        .expect("CRC8 candidate should exist");

    assert!(crc8_candidate.validation_count < 100);
}

#[test]
fn identifies_sum16_from_unknown_frames() {
    let sum = Sum16;
    let mut frames = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            0x20,
            i,
            i.wrapping_mul(7),
            i.wrapping_add(3),
        ];

        let checksum = sum.calculate(&data);

        let mut frame = data;
        frame.extend_from_slice(
            &(checksum as u16).to_le_bytes(),
        );

        frames.push(frame);
    }

    let candidates =
        babelfish::checksum::search::search_algorithms(
            &frames,
        );

    let sum16_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "SUM16"
        })
        .expect("SUM16 candidate should exist");

    assert_eq!(sum16_candidate.validation_count, 100);
    assert_eq!(sum16_candidate.total_frames, 100);
    assert!(sum16_candidate.is_proven());

    let crc16_candidate = candidates
        .iter()
        .find(|candidate| {
            candidate.algorithm.name() == "CRC16/MODBUS"
        })
        .expect("CRC16/MODBUS candidate should exist");

    assert!(crc16_candidate.validation_count < 100);
}

#[test]
fn parses_hex_capture_file() {
    use std::fs;

    let path = std::env::temp_dir()
        .join("babelfish_test_capture.txt");

    let content = "\
01 02 03 04 A1 2B
10 20 30 40 00 00

# This is a comment
AA BB CC
";

    fs::write(&path, content)
        .expect("failed to write test capture");

    let frames =
        babelfish::input::parse_hex_file(&path)
            .expect("capture should parse");

    assert_eq!(frames.len(), 3);

    assert_eq!(
        frames[0],
        vec![0x01, 0x02, 0x03, 0x04, 0xA1, 0x2B]
    );

    assert_eq!(
        frames[1],
        vec![0x10, 0x20, 0x30, 0x40, 0x00, 0x00]
    );

    assert_eq!(
        frames[2],
        vec![0xAA, 0xBB, 0xCC]
    );

    fs::remove_file(path).ok();
}

#[test]
fn reports_failed_frame_indexes() {
    let crc = Crc8;
    let mut frames = Vec::new();

    for i in 0u8..10 {
        let data = vec![
            0x10,
            i,
            i.wrapping_add(1),
        ];

        let checksum = crc.calculate(&data);

        let mut frame = data;
        frame.push(checksum as u8);

        frames.push(frame);
    }

    // Corrupt frames 2, 5, and 8.
    for index in [2usize, 5usize, 8usize] {
        let last = frames[index].len() - 1;
        frames[index][last] ^= 0xFF;
    }

    let failed =
        babelfish::checksum::search::failed_frame_indexes(
            &crc,
            &frames,
            0,
        );

    assert_eq!(failed, vec![2, 5, 8]);
}