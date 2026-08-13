mod common;

use babelfish::{Checksum, Crc16Modbus};

#[test]
fn crc16_modbus_known_value() {
    let crc = Crc16Modbus;

    let result = crc.calculate(b"123456789");

    assert_eq!(result, 0x4B37);
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