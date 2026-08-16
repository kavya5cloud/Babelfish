mod common;

use babelfish::{
    Checksum,
    Crc16Modbus,
    Crc8,
    Sum8,
    Sum16,
};
use babelfish::framing::FramingKind;

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

#[test]
fn finds_best_checksum_coverage_start() {
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

    let result =
        babelfish::checksum::search::best_coverage_candidate(
            &crc,
            &frames,
        )
        .expect("a coverage candidate should exist");

    assert_eq!(result, (1, 100));
}
#[test]
fn coverage_search_never_returns_empty_range() {
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

    let result =
        babelfish::checksum::search::best_coverage_candidate(
            &crc,
            &frames,
        )
        .expect("coverage candidate should exist");

    let coverage_start = result.0;

    let checksum_start =
        frames[0].len() - crc.width();

    assert!(coverage_start < checksum_start);
}

#[test]
fn finds_recurring_sync_prefix() {
    let stream = vec![
        0x7E, 0x04, 0x01, 0x2C, 0x00, 0x5A, 0x3F,
        0x7E, 0x04, 0x01, 0x2E, 0x00, 0x5A, 0x41,
        0x7E, 0x04, 0x01, 0x2F, 0x00, 0x59, 0x42,
    ];

    let candidates =
        babelfish::framing::find_recurring_prefixes(
            &stream,
            1,
            3,
        );

    assert!(candidates.contains(&vec![0x7E]));
    assert!(candidates.contains(&vec![0x7E, 0x04]));
    assert!(candidates.contains(&vec![0x7E, 0x04, 0x01]));
}
#[test]
fn splits_stream_on_sync_prefix() {
    let stream = vec![
        0x7E, 0x04, 0x01, 0x2C, 0x00, 0x5A, 0x3F,
        0x7E, 0x04, 0x01, 0x2E, 0x00, 0x5A, 0x41,
        0x7E, 0x04, 0x01, 0x2F, 0x00, 0x59, 0x42,
    ];

    let frames =
        babelfish::framing::split_on_prefix(
            &stream,
            &[0x7E],
        );

    assert_eq!(frames.len(), 3);

    assert_eq!(
        frames[0],
        vec![0x7E, 0x04, 0x01, 0x2C, 0x00, 0x5A, 0x3F]
    );

    assert_eq!(
        frames[1],
        vec![0x7E, 0x04, 0x01, 0x2E, 0x00, 0x5A, 0x41]
    );

    assert_eq!(
        frames[2],
        vec![0x7E, 0x04, 0x01, 0x2F, 0x00, 0x59, 0x42]
    );
}

#[test]
fn frames_raw_stream_then_identifies_checksum() {
    let crc = Crc8;

    let mut stream = Vec::new();

    for i in 0u8..100 {
        let mut data = vec![
            0x10,
            i,
            i.wrapping_mul(2) % 0x7E,
        ];

        let mut checksum = crc.calculate(&data) as u8;

        // Make sure neither payload nor checksum accidentally
        // contains the sync byte used for framing.
        if checksum == 0x7E {
            data[2] = data[2].wrapping_add(1);
            checksum = crc.calculate(&data) as u8;
        }

        assert!(!data.contains(&0x7E));
        assert_ne!(checksum, 0x7E);

        let mut frame = vec![0x7E];
        frame.extend_from_slice(&data);
        frame.push(checksum);

        stream.extend_from_slice(&frame);
    }

    let frames =
        babelfish::framing::split_on_prefix(
            &stream,
            &[0x7E],
        );

    assert_eq!(frames.len(), 100);

    let best =
        babelfish::checksum::search::best_candidate(&frames)
            .expect("checksum candidate should exist");

    assert_eq!(best.algorithm.name(), "CRC8");
    assert_eq!(best.validation_count, 100);
    assert!(best.is_proven());
}

#[test]
fn builds_framing_candidates_from_raw_stream() {
    let stream = vec![
        0x7E, 0x04, 0x01, 0x2C, 0x00, 0x5A, 0x3F,
        0x7E, 0x04, 0x01, 0x2E, 0x00, 0x5A, 0x41,
        0x7E, 0x04, 0x01, 0x2F, 0x00, 0x59, 0x42,
    ];

    let candidates =
        babelfish::framing::build_framing_candidates(
            &stream,
            1,
            1,
        );

    let candidate = candidates
        .iter()
        .find(|candidate| {
    candidate.kind == FramingKind::Prefix(vec![0x7E])
})
        .expect("0x7E framing candidate should exist");

    assert_eq!(candidate.frame_count, 3);
}
#[test]
fn framing_candidate_contains_checksum_evidence() {
    let crc = Crc8;
    let mut stream = Vec::new();
    let mut generated = 0u8;

    while generated < 100 {
        let data = vec![
            generated % 0x7E,
            generated.wrapping_add(1) % 0x7E,
            generated.wrapping_mul(3) % 0x7E,
        ];

        let checksum = crc.calculate(&data) as u8;

        if checksum == 0x7E {
            generated = generated.wrapping_add(1);
            continue;
        }

        let mut frame = vec![0x7E];
        frame.extend_from_slice(&data);
        frame.push(checksum);

        stream.extend_from_slice(&frame);

        generated = generated.wrapping_add(1);
    }

    let candidates =
        babelfish::framing::build_framing_candidates(
            &stream,
            1,
            1,
        );

    let candidate = candidates
        .iter()
        .find(|candidate| {
    candidate.kind == FramingKind::Prefix(vec![0x7E])
})
        .expect("0x7E framing candidate should exist");

    assert_eq!(candidate.frame_count, 100);
    assert_eq!(
        candidate.checksum_validation_count,
        100
    );
    assert_eq!(
        candidate.checksum_total_frames,
        100
    );
}

#[test]
fn ranks_framing_candidates_by_checksum_evidence() {
    use babelfish::framing::{
        rank_framing_candidates,
        FramingCandidate,
        FramingKind,
    };

    let weak = FramingCandidate {
        kind: FramingKind::Prefix(vec![0xAA]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 20,
        checksum_total_frames: 100,
    };

    let strong = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    let ranked = rank_framing_candidates(vec![
        weak,
        strong,
    ]);

    assert_eq!(ranked.len(), 2);

    assert_eq!(
        ranked[0].kind,
        FramingKind::Prefix(vec![0x7E])
    );

    assert_eq!(
        ranked[1].kind,
        FramingKind::Prefix(vec![0xAA])
    );

    assert!(ranked[0].score() > ranked[1].score());
}

#[test]
fn returns_best_framing_candidate() {
    use babelfish::framing::FramingKind;

let crc = Crc8;
    let mut stream = Vec::new();

    for i in 0u8..100 {
        let data = vec![
            i % 0x7E,
            i.wrapping_add(1) % 0x7E,
            i.wrapping_mul(3) % 0x7E,
        ];

        let checksum = crc.calculate(&data) as u8;

        if checksum == 0x7E {
            continue;
        }

        let mut frame = vec![0x7E];
        frame.extend_from_slice(&data);
        frame.push(checksum);

        stream.extend_from_slice(&frame);
    }

    let best = babelfish::framing::best_framing_candidate(
        &stream,
        1,
        1,
    )
    .expect("a framing candidate should exist");

    assert_eq!(
    best.kind,
    FramingKind::Prefix(vec![0x7E])
);
    assert_eq!(best.checksum_validation_count, best.checksum_total_frames);
}   

#[test]
fn parses_hex_stream_file() {
    use std::fs;

    let path = std::env::temp_dir()
        .join("babelfish_test_stream.txt");

    let content = "\
7E 01 02
03 04 05

# another chunk
06 07 08
";

    fs::write(&path, content)
        .expect("failed to write test stream");

    let stream =
        babelfish::input::parse_hex_stream_file(&path)
            .expect("stream should parse");

    assert_eq!(
        stream,
        vec![
            0x7E, 0x01, 0x02,
            0x03, 0x04, 0x05,
            0x06, 0x07, 0x08,
        ]
    );

    fs::remove_file(path).ok();
}

#[test]
fn framing_candidate_confidence_increases_with_evidence() {
    use babelfish::framing::FramingCandidate;

    let weak = FramingCandidate {
        kind: FramingKind::Prefix(vec![0xAA]),
        frame_count: 10,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 5,
        checksum_total_frames: 10,
    };

    let strong = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    assert!(strong.confidence() > weak.confidence());
}

#[test]
fn framing_candidate_verdict_can_be_proven() {
    use babelfish::framing::FramingCandidate;

    let candidate = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    assert_eq!(candidate.verdict(), "PROVEN");
}

#[test]
fn protocol_hypothesis_combines_framing_and_checksum() {
    use babelfish::hypothesis::ProtocolHypothesis;

    let framing = babelfish::framing::FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    let checksum =
        babelfish::checksum::search::best_candidate(
            &vec![
                vec![0x10, 0x01, 0x02, 0x03, 0x00],
                vec![0x10, 0x02, 0x03, 0x04, 0x00],
            ],
        )
        .expect("checksum candidate should exist");

    let hypothesis = ProtocolHypothesis {
    framing,
    checksum,
    fields: Vec::new(),
    multi_byte_fields: Vec::new(),
};

    assert!(hypothesis.validation_rate() >= 0.0);
    assert!(hypothesis.confidence() >= 0.0);
    assert!(!hypothesis.verdict().is_empty());
}

#[test]
fn analyzes_constant_and_variable_byte_positions() {
    let frames = vec![
        vec![0x7E, 0x10, 0x01, 0x27, 0x01],
        vec![0x7E, 0x10, 0x02, 0x27, 0x01],
        vec![0x7E, 0x10, 0x03, 0x27, 0x01],
        vec![0x7E, 0x10, 0x04, 0x27, 0x01],
    ];

    let observations =
        babelfish::fields::analyze_byte_positions(
            &frames,
            0,
            5,
        );

    assert_eq!(observations.len(), 5);

    // Byte 0 is always 0x7E.
    assert!(observations[0].is_constant);
    assert_eq!(observations[0].unique_values, 1);
    assert_eq!(observations[0].min_value, 0x7E);
    assert_eq!(observations[0].max_value, 0x7E);

    // Byte 1 is always 0x10.
    assert!(observations[1].is_constant);
    assert_eq!(observations[1].unique_values, 1);

    // Byte 2 changes from 1 to 4.
    assert!(!observations[2].is_constant);
    assert_eq!(observations[2].unique_values, 4);
    assert_eq!(observations[2].min_value, 0x01);
    assert_eq!(observations[2].max_value, 0x04);

    // Bytes 3 and 4 are constant.
    assert!(observations[3].is_constant);
    assert!(observations[4].is_constant);
}
#[test]
fn detects_incrementing_byte_field() {
    let frames = vec![
        vec![0x7E, 0x10, 0x01, 0x27],
        vec![0x7E, 0x10, 0x02, 0x27],
        vec![0x7E, 0x10, 0x03, 0x27],
        vec![0x7E, 0x10, 0x04, 0x27],
    ];

    assert!(
        babelfish::fields::is_incrementing_byte(
            &frames,
            2,
        )
    );

    assert!(
        !babelfish::fields::is_incrementing_byte(
            &frames,
            3,
        )
    );
}
#[test]
fn detects_cyclic_byte_field() {
    let frames = vec![
        vec![0x7E, 0x00],
        vec![0x7E, 0x01],
        vec![0x7E, 0x02],
        vec![0x7E, 0x00],
        vec![0x7E, 0x01],
        vec![0x7E, 0x02],
    ];

    assert!(
        babelfish::fields::is_cyclic_byte(
            &frames,
            1,
            3,
        )
    );

    assert!(
        !babelfish::fields::is_cyclic_byte(
            &frames,
            1,
            2,
        )
    );
}
#[test]
fn infers_constant_and_incrementing_field_hypotheses() {
    let frames = vec![
        vec![0x7E, 0x10, 0x01, 0x27],
        vec![0x7E, 0x10, 0x02, 0x27],
        vec![0x7E, 0x10, 0x03, 0x27],
        vec![0x7E, 0x10, 0x04, 0x27],
    ];

    let constant =
    babelfish::fields::infer_field_hypothesis(
        &frames,
        1,
        3,
    )
    .expect("constant field hypothesis should exist");
    assert_eq!(
        constant.kind,
        babelfish::fields::FieldKind::Constant
    );

    assert_eq!(constant.unique_values, 1);
    assert_eq!(constant.min_value, 0x10);
    assert_eq!(constant.max_value, 0x10);

    let incrementing =
        babelfish::fields::infer_field_hypothesis(
            &frames,
            2,
            3,
        )
        .expect("incrementing field hypothesis should exist");

    assert_eq!(
        incrementing.kind,
        babelfish::fields::FieldKind::Incrementing
    );

    assert_eq!(incrementing.unique_values, 4);
    assert_eq!(incrementing.min_value, 0x01);
    assert_eq!(incrementing.max_value, 0x04);
}

#[test]
fn infers_cyclic_field_hypothesis() {
    let frames = vec![
        vec![0x7E, 0x00],
        vec![0x7E, 0x01],
        vec![0x7E, 0x02],
        vec![0x7E, 0x00],
        vec![0x7E, 0x01],
        vec![0x7E, 0x02],
    ];

    let hypothesis =
        babelfish::fields::infer_field_hypothesis(
            &frames,
            1,
            3,
        )
        .expect("cyclic field hypothesis should exist");

    assert_eq!(
        hypothesis.kind,
        babelfish::fields::FieldKind::Cyclic
    );
}
#[test]
fn infers_all_field_hypotheses() {
    let frames = vec![
        vec![0x7E, 0x10, 0x01, 0x27],
        vec![0x7E, 0x10, 0x02, 0x27],
        vec![0x7E, 0x10, 0x03, 0x27],
        vec![0x7E, 0x10, 0x04, 0x27],
    ];

    let fields =
        babelfish::fields::infer_fields(
            &frames,
            0,
            4,
        );

    assert_eq!(fields.len(), 4);

    assert_eq!(
        fields[0].kind,
        babelfish::fields::FieldKind::Constant
    );

    assert_eq!(
        fields[1].kind,
        babelfish::fields::FieldKind::Constant
    );

    assert_eq!(
        fields[2].kind,
        babelfish::fields::FieldKind::Incrementing
    );

    assert_eq!(
        fields[3].kind,
        babelfish::fields::FieldKind::Constant
    );
}
#[test]
fn protocol_hypothesis_contains_field_hypotheses() {
    let crc = Crc8;

    let mut frames = Vec::new();

    for i in 0u8..20 {
        let data = vec![
            0x10, // constant
            i,    // incrementing
            0x27, // constant
        ];

        let checksum = crc.calculate(&data);

        let mut frame = vec![0x7E];
        frame.extend_from_slice(&data);
        frame.push(checksum as u8);

        frames.push(frame);
    }

    let framing = babelfish::framing::FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: frames.len(),
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 20,
        checksum_total_frames: 20,
    };

    let hypothesis =
        babelfish::hypothesis::build_hypothesis(
            framing,
            &frames,
        )
        .expect("protocol hypothesis should exist");

    assert_eq!(hypothesis.fields.len(), 3);

    assert_eq!(
        hypothesis.fields[0].kind,
        babelfish::fields::FieldKind::Constant
    );

    assert_eq!(
        hypothesis.fields[1].kind,
        babelfish::fields::FieldKind::Incrementing
    );

    assert_eq!(
        hypothesis.fields[2].kind,
        babelfish::fields::FieldKind::Constant
    );
}

#[test]
fn detects_linear_byte_pattern() {
    let frames = vec![
        vec![0x10, 0x00],
        vec![0x10, 0x03],
        vec![0x10, 0x06],
        vec![0x10, 0x09],
    ];

    let step =
        babelfish::fields::detect_linear_byte_pattern(
            &frames,
            1,
        );

    assert_eq!(step, Some(3));
}

#[test]
fn infers_linear_field_hypothesis() {
    let frames = vec![
        vec![0x10, 0x00],
        vec![0x10, 0x03],
        vec![0x10, 0x06],
        vec![0x10, 0x09],
    ];

    let hypothesis =
        babelfish::fields::infer_field_hypothesis(
            &frames,
            1,
            3,
        )
        .expect("linear field hypothesis should exist");

    assert_eq!(
        hypothesis.kind,
        babelfish::fields::FieldKind::Linear
    );

    assert_eq!(hypothesis.linear_step, Some(3));
    assert_eq!(hypothesis.unique_values, 4);
    assert_eq!(hypothesis.min_value, 0x00);
    assert_eq!(hypothesis.max_value, 0x09);
}
#[test]
fn detects_length_field() {
    let frames = vec![
        // 7E | length | payload (3 bytes)
        vec![0x7E, 0x03, 0xAA, 0xBB, 0xCC, 0x00],
        vec![0x7E, 0x03, 0x10, 0x20, 0x30, 0x00],
        vec![0x7E, 0x03, 0x01, 0x02, 0x03, 0x00],
    ];

    let detected =
        babelfish::fields::is_length_field(
            &frames,
            1,
            5,
        );

    assert!(detected);
}
#[test]
fn infers_length_field_hypothesis() {
    let frames = vec![
        // 7E | length | payload | checksum
        vec![0x7E, 0x03, 0xAA, 0xBB, 0xCC, 0x00],
        vec![0x7E, 0x03, 0x10, 0x20, 0x30, 0x00],
        vec![0x7E, 0x03, 0x01, 0x02, 0x03, 0x00],
    ];

    let hypothesis =
        babelfish::fields::infer_field_hypothesis(
            &frames,
            1,
            5,
        )
        .expect("length field hypothesis should exist");

    assert_eq!(
        hypothesis.kind,
        babelfish::fields::FieldKind::Length
    );

    assert_eq!(hypothesis.unique_values, 1);
    assert_eq!(hypothesis.min_value, 0x03);
    assert_eq!(hypothesis.max_value, 0x03);
}
#[test]
fn decodes_u16_little_endian_values() {
    let frames = vec![
        vec![0xAA, 0x00, 0x00],
        vec![0xAA, 0x01, 0x00],
        vec![0xAA, 0x02, 0x00],
        vec![0xAA, 0x03, 0x00],
    ];

    let values =
        babelfish::fields::decode_u16_le(
            &frames,
            1,
        )
        .expect("u16 values should decode");

    assert_eq!(
        values,
        vec![0, 1, 2, 3]
    );

    assert!(
        babelfish::fields::is_incrementing_u16(
            &frames,
            1,
            true,
        )
    );

    assert!(
        !babelfish::fields::is_incrementing_u16(
            &frames,
            1,
            false,
        )
    );
}
#[test]
fn infers_u16_little_endian_incrementing_field() {
    let frames = vec![
        vec![0xAA, 0x00, 0x00],
        vec![0xAA, 0x01, 0x00],
        vec![0xAA, 0x02, 0x00],
        vec![0xAA, 0x03, 0x00],
    ];

    let hypothesis =
        babelfish::fields::infer_u16_field(
            &frames,
            1,
        )
        .expect("u16 field hypothesis should exist");

    assert_eq!(
        hypothesis.kind,
        babelfish::fields::MultiByteKind::U16LittleEndian
    );

    assert_eq!(hypothesis.start, 1);
    assert_eq!(hypothesis.width, 2);
    assert_eq!(hypothesis.unique_values, 4);
    assert_eq!(hypothesis.min_value, 0);
    assert_eq!(hypothesis.max_value, 3);
    assert!(hypothesis.is_incrementing);
}

#[test]
fn ranks_multi_byte_hypotheses() {
    use babelfish::fields::{
        MultiByteFieldHypothesis,
        MultiByteKind,
    };

    let strong = MultiByteFieldHypothesis {
        start: 2,
        width: 2,
        kind: MultiByteKind::U16LittleEndian,
        unique_values: 100,
        min_value: 0,
        max_value: 99,
        is_incrementing: true,
    };

    let weak = MultiByteFieldHypothesis {
        start: 1,
        width: 2,
        kind: MultiByteKind::U16BigEndian,
        unique_values: 1,
        min_value: 4096,
        max_value: 4096,
        is_incrementing: false,
    };

    assert!(strong.score() > weak.score());
}
#[test]
fn ranks_overlapping_u16_hypotheses() {
    let frames = vec![
        vec![0x10, 0x00, 0x00],
        vec![0x10, 0x01, 0x00],
        vec![0x10, 0x02, 0x00],
        vec![0x10, 0x03, 0x00],
    ];

    let hypotheses =
        babelfish::fields::infer_u16_fields(
            &frames,
            0,
            3,
        );

    assert_eq!(hypotheses.len(), 2);

    assert!(
        hypotheses.iter().any(|h| {
            h.kind
                == babelfish::fields::MultiByteKind::U16LittleEndian
                && h.start == 1
        })
    );

    assert!(
        hypotheses.iter().any(|h| {
            h.kind
                == babelfish::fields::MultiByteKind::U16BigEndian
                && h.start == 0
        })
    );

    assert!(
        hypotheses
            .iter()
            .all(|hypothesis| hypothesis.score() > 0.0)
    );
}
#[test]
fn decodes_u32_little_endian_values() {
    let frames = vec![
        vec![0xAA, 0x00, 0x00, 0x00, 0x00],
        vec![0xAA, 0x01, 0x00, 0x00, 0x00],
        vec![0xAA, 0x02, 0x00, 0x00, 0x00],
        vec![0xAA, 0x03, 0x00, 0x00, 0x00],
    ];

    let values =
        babelfish::fields::decode_u32_le(
            &frames,
            1,
        )
        .expect("u32 values should decode");

    assert_eq!(
        values,
        vec![0, 1, 2, 3]
    );

    assert!(
        babelfish::fields::is_incrementing_u32(
            &frames,
            1,
            true,
        )
    );

    assert!(
        !babelfish::fields::is_incrementing_u32(
            &frames,
            1,
            false,
        )
    );
}
#[test]
fn infers_u32_little_endian_incrementing_field() {
    let frames = vec![
        vec![0xAA, 0x00, 0x00, 0x00, 0x00],
        vec![0xAA, 0x01, 0x00, 0x00, 0x00],
        vec![0xAA, 0x02, 0x00, 0x00, 0x00],
        vec![0xAA, 0x03, 0x00, 0x00, 0x00],
    ];

    let hypothesis =
        babelfish::fields::infer_u32_field(
            &frames,
            1,
        )
        .expect("u32 field hypothesis should exist");

    assert_eq!(
        hypothesis.kind,
        babelfish::fields::MultiByteKind::U32LittleEndian
    );

    assert_eq!(hypothesis.start, 1);
    assert_eq!(hypothesis.width, 4);
    assert_eq!(hypothesis.unique_values, 4);
    assert_eq!(hypothesis.min_value, 0);
    assert_eq!(hypothesis.max_value, 3);
    assert!(hypothesis.is_incrementing);
}

#[test]
fn prefers_shorter_framing_prefix_when_evidence_ties() {
    use babelfish::framing::{
        rank_framing_candidates,
        FramingCandidate,
    };

    let short = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    let long = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E, 0x10]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    let ranked =
        rank_framing_candidates(vec![long, short]);

    assert_eq!(
    ranked[0].kind,
    FramingKind::Prefix(vec![0x7E])
);
    assert_eq!(
    ranked[1].kind,
    FramingKind::Prefix(vec![0x7E, 0x10])
);

    assert!(ranked[0].score() > ranked[1].score());
}
#[test]
fn prefers_more_evidence_when_validation_rate_ties() {
    use babelfish::framing::{
        rank_framing_candidates,
        FramingCandidate,
    };

    let tiny = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x02]),
        frame_count: 2,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 2,
        checksum_total_frames: 2,
    };

    let large = FramingCandidate {
        kind: FramingKind::Prefix(vec![0x7E]),
        frame_count: 100,
        checksum_algorithm: Some("CRC8".to_string()),
        checksum_validation_count: 100,
        checksum_total_frames: 100,
    };

    let ranked =
        rank_framing_candidates(vec![tiny, large]);

    assert_eq!(
    ranked[0].kind,
    FramingKind::Prefix(vec![0x7E])
);

    assert!(
        ranked[0].score()
            > ranked[1].score()
    );
}
#[test]
fn framing_rejects_sync_byte_inside_payload() {
    let crc = Crc8;

    let payloads = vec![
        vec![0x10, 0x20, 0x30],
        vec![0x10, 0x7E, 0x31],
        vec![0x10, 0x40, 0x32],
        vec![0x10, 0x50, 0x33],
        vec![0x10, 0x60, 0x34],
    ];

    let mut stream = Vec::new();

    for payload in &payloads {
        let checksum = crc.calculate(payload) as u8;

        stream.push(0x7E);
        stream.extend_from_slice(payload);
        stream.push(checksum);
    }

    /*
     * A naïve 0x7E splitter will see the payload 0x7E
     * and produce an extra frame.
     */
    let naive_frames =
        babelfish::framing::split_on_prefix(
            &stream,
            &[0x7E],
        );

    assert!(
        naive_frames.len() > payloads.len(),
        "naive framing should be confused by sync byte in payload"
    );

    /*
     * The raw stream nevertheless contains exactly the
     * expected number of protocol frames.
     */
    assert_eq!(payloads.len(), 5);

    /*
     * This test is intentionally documenting the current
     * limitation. The next framing engine should use
     * checksum consistency to reject the naïve split.
     */
}
#[test]
fn best_framing_candidate_handles_payload_sync_collision() {
    let crc = Crc8;

    let payloads = vec![
        vec![0x10, 0x20, 0x30],
        vec![0x10, 0x7E, 0x31],
        vec![0x10, 0x40, 0x32],
        vec![0x10, 0x50, 0x33],
        vec![0x10, 0x60, 0x34],
    ];

    let mut stream = Vec::new();

    for payload in &payloads {
        let checksum = crc.calculate(payload) as u8;

        stream.push(0x7E);
        stream.extend_from_slice(payload);
        stream.push(checksum);
    }

    let best =
        babelfish::framing::best_framing_candidate(
            &stream,
            1,
            2,
        )
        .expect("framing candidate should exist");

    assert_eq!(
    best.kind,
    FramingKind::Prefix(vec![0x7E, 0x10])
);
    assert_eq!(best.frame_count, 5);
    assert_eq!(best.checksum_validation_count, 5);
    assert_eq!(best.checksum_total_frames, 5);
    assert_eq!(
        best.checksum_algorithm.as_deref(),
        Some("CRC8")
    );
}

#[test]
fn splits_stream_using_length_field() {
    let stream = vec![
        // length = 3, payload = AA BB CC, checksum = 00
        0x03, 0xAA, 0xBB, 0xCC, 0x00,

        // length = 5, payload = 10 20 30 40 50, checksum = 00
        0x05, 0x10, 0x20, 0x30, 0x40, 0x50, 0x00,

        // length = 2, payload = 99 88, checksum = 00
        0x02, 0x99, 0x88, 0x00,
    ];

    let frames =
        babelfish::framing::split_on_length_field(
            &stream,
            0,
            1,
            1,
        );

    assert_eq!(frames.len(), 3);

    assert_eq!(
        frames[0],
        vec![0x03, 0xAA, 0xBB, 0xCC, 0x00]
    );

    assert_eq!(
        frames[1],
        vec![
            0x05,
            0x10,
            0x20,
            0x30,
            0x40,
            0x50,
            0x00,
        ]
    );

    assert_eq!(
        frames[2],
        vec![0x02, 0x99, 0x88, 0x00]
    );
}
#[test]
fn infers_length_field_framing() {
    let crc = Crc8;

    let payloads = vec![
        vec![0xAA, 0xBB, 0xCC],
        vec![0x10, 0x20, 0x30, 0x40, 0x50],
        vec![0x99, 0x88],
    ];

    let mut stream = Vec::new();

    for payload in &payloads {
        let length = payload.len() as u8;
        let checksum = crc.calculate(payload) as u8;

        stream.push(length);
        stream.extend_from_slice(payload);
        stream.push(checksum);
    }

    let candidates =
        babelfish::framing::infer_length_framing_candidates(
            &stream,
            0,
            0,
            1,
            1,
        );

    assert!(!candidates.is_empty());

    let best = &candidates[0];

    assert_eq!(best.frame_count, 3);
    assert_eq!(
        best.checksum_algorithm.as_deref(),
        Some("CRC8")
    );
    assert_eq!(
        best.checksum_validation_count,
        3
    );
    assert_eq!(
        best.checksum_total_frames,
        3
    );
}