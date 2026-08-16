use std::env;
use std::process;

use babelfish::checksum::search::rank_candidates;
use babelfish::framing::{
    best_framing_candidate,
    FramingKind,
};
use babelfish::input::{
    parse_hex_file,
    parse_hex_stream_file,
};

fn print_checksum_candidates(frames: &[Vec<u8>]) {
    let candidates = rank_candidates(
        babelfish::checksum::search::search_algorithms(frames),
    );

    println!("Frames: {}", frames.len());
    println!();
    println!("Checksum candidates:");

    for candidate in &candidates {
        println!(
            "  {:<14} {:>4}/{:<4} {:>7.2}% {:>9}  coverage: bytes[{}..{}]  checksum: bytes[{}..{}]  failed: {}",
            candidate.algorithm.name(),
            candidate.validation_count,
            candidate.total_frames,
            candidate.validation_rate() * 100.0,
            candidate.verdict(),
            candidate.coverage_start,
            candidate.coverage_end,
            candidate.checksum_start,
            candidate.checksum_end,
            candidate.failed_frames.len(),
        );

        if !candidate.is_proven()
            && !candidate.failed_frames.is_empty()
        {
            let preview: Vec<String> = candidate
                .failed_frames
                .iter()
                .take(10)
                .map(|index| index.to_string())
                .collect();

            println!(
                "    failed indexes: [{}{}]",
                preview.join(", "),
                if candidate.failed_frames.len() > 10 {
                    ", ..."
                } else {
                    ""
                }
            );
        }
    }

    println!();

    if let Some(best) = candidates.first() {
        println!("Best checksum candidate:");
        println!("  {}", best.algorithm.name());
    } else {
        println!("No checksum candidates found.");
    }
}

fn crack_framed_file(path: &str) {
    let frames = match parse_hex_file(path) {
        Ok(frames) => frames,
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    };

    println!("Babelfish 🐟");
    println!();

    print_checksum_candidates(&frames);
}

fn print_framing_kind(kind: &FramingKind) {
    match kind {
        FramingKind::Prefix(prefix) => {
            println!("  type: prefix");
            println!("  prefix: {:02X?}", prefix);
        }

        FramingKind::Length {
            length_offset,
            payload_offset,
            checksum_width,
        } => {
            println!("  type: length");
            println!(
                "  length field: byte {}",
                length_offset
            );
            println!(
                "  payload starts: byte {}",
                payload_offset
            );
            println!(
                "  checksum width: {} byte(s)",
                checksum_width
            );
        }
    }
}

fn frames_from_framing(
    stream: &[u8],
    kind: &FramingKind,
) -> Vec<Vec<u8>> {
    match kind {
        FramingKind::Prefix(prefix) => {
            babelfish::framing::split_on_prefix(
                stream,
                prefix,
            )
        }

        FramingKind::Length {
            length_offset,
            payload_offset,
            checksum_width,
        } => {
            babelfish::framing::split_on_length_field(
                stream,
                *length_offset,
                *payload_offset,
                *checksum_width,
            )
        }
    }
}

fn crack_stream_file(path: &str) {
    let stream = match parse_hex_stream_file(path) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    };

    println!("Babelfish 🐟");
    println!();
    println!("Raw stream bytes: {}", stream.len());
    println!();

    let framing = match best_framing_candidate(
        &stream,
        1,
        3,
    ) {
        Some(candidate) => candidate,
        None => {
            eprintln!(
                "Could not find a framing hypothesis."
            );
            process::exit(1);
        }
    };

    println!("Best framing candidate:");
    print_framing_kind(&framing.kind);

    println!(
        "  frames: {}",
        framing.frame_count
    );

    match &framing.checksum_algorithm {
        Some(algorithm) => {
            println!(
                "  checksum: {}",
                algorithm
            );
        }

        None => {
            println!(
                "  checksum: unknown"
            );
        }
    }

    println!(
        "  validation: {}/{} ({:.2}%)",
        framing.checksum_validation_count,
        framing.checksum_total_frames,
        framing.checksum_validation_rate() * 100.0,
    );

    println!(
        "  confidence: {:.2}",
        framing.confidence()
    );

    println!(
        "  verdict: {}",
        framing.verdict()
    );

    println!();

    let frames =
        frames_from_framing(
            &stream,
            &framing.kind,
        );

    let hypothesis =
        match babelfish::hypothesis::build_hypothesis(
            framing,
            &frames,
        ) {
            Some(hypothesis) => hypothesis,

            None => {
                eprintln!(
                    "Could not build a protocol hypothesis."
                );
                process::exit(1);
            }
        };

    println!("Protocol hypothesis:");

    match &hypothesis.framing.kind {
        FramingKind::Prefix(prefix) => {
            println!(
                "  framing: prefix {:02X?}",
                prefix
            );
        }

        FramingKind::Length {
            length_offset,
            payload_offset,
            checksum_width,
        } => {
            println!(
                "  framing: length byte {}",
                length_offset
            );
            println!(
                "  payload starts: byte {}",
                payload_offset
            );
            println!(
                "  checksum width: {} byte(s)",
                checksum_width
            );
        }
    }

    println!(
        "  frames: {}",
        hypothesis.framing.frame_count
    );

    println!(
        "  checksum: {}",
        hypothesis.checksum.algorithm.name()
    );

    println!(
        "  coverage: bytes[{}..{}]",
        hypothesis.checksum.coverage_start,
        hypothesis.checksum.coverage_end
    );

    println!(
        "  checksum: bytes[{}..{}]",
        hypothesis.checksum.checksum_start,
        hypothesis.checksum.checksum_end
    );

    println!(
        "  validation: {}/{} ({:.2}%)",
        hypothesis.checksum.validation_count,
        hypothesis.checksum.total_frames,
        hypothesis.validation_rate() * 100.0
    );

    println!(
        "  confidence: {:.2}",
        hypothesis.confidence()
    );

    println!(
        "  verdict: {}",
        hypothesis.verdict()
    );

    println!();
    println!("Fields:");

    for field in &hypothesis.fields {
        match field.kind {
            babelfish::fields::FieldKind::Length => {
                println!(
                    "  byte {:<3} Length       unique: {:<4} range: 0x{:02X}..0x{:02X}",
                    field.position,
                    field.unique_values,
                    field.min_value,
                    field.max_value,
                );
            }

            babelfish::fields::FieldKind::Linear => {
                println!(
                    "  byte {:<3} Linear       step: {:+}  unique: {:<4} range: 0x{:02X}..0x{:02X}",
                    field.position,
                    field.linear_step.unwrap_or(0),
                    field.unique_values,
                    field.min_value,
                    field.max_value,
                );
            }

            _ => {
                println!(
                    "  byte {:<3} {:<12} unique: {:<4} range: 0x{:02X}..0x{:02X}",
                    field.position,
                    format!("{:?}", field.kind),
                    field.unique_values,
                    field.min_value,
                    field.max_value,
                );
            }
        }
    }

    if !hypothesis.multi_byte_fields.is_empty() {
        println!();
        println!("Multi-byte fields:");

        for field in &hypothesis.multi_byte_fields {
            println!(
                "  bytes[{}..{}]  {:?}  unique: {:<4} range: {}..{}  incrementing: {}",
                field.start,
                field.start + field.width,
                field.kind,
                field.unique_values,
                field.min_value,
                field.max_value,
                field.is_incrementing,
            );
        }
    }

    let ambiguous =
        hypothesis.ambiguous_multi_byte_fields();

    if ambiguous.len() > 1 {
        println!();
        println!("Multi-byte ambiguity:");

        for field in &ambiguous {
            println!(
                "  bytes[{}..{}]  {:?}  score: {:.2}",
                field.start,
                field.start + field.width,
                field.kind,
                field.score(),
            );
        }

        println!(
            "  multiple interpretations have equal evidence."
        );
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         babelfish crack <capture.txt>\n  \
         babelfish crack-stream <stream.txt>"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "crack" => {
            crack_framed_file(&args[2]);
        }

        "crack-stream" => {
            crack_stream_file(&args[2]);
        }

        _ => {
            eprintln!(
                "Unknown command '{}'.",
                args[1]
            );
            eprintln!();
            print_usage();
            process::exit(1);
        }
    }
}