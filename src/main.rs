use babelfish::checksum::search::rank_candidates;
use babelfish::framing::{
    FramingCandidate, FramingKind, infer_length_framing_candidates, rank_framing_candidates,
};
use babelfish::generator::generate_rust;
use babelfish::input::{parse_hex_file, parse_hex_stream_file};
use babelfish::model::ProtocolModel;
use std::env;
use std::process;

fn print_checksum_candidates(frames: &[Vec<u8>]) {
    let candidates = rank_candidates(babelfish::checksum::search::search_algorithms(frames));

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

        if !candidate.is_proven() && !candidate.failed_frames.is_empty() {
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
            println!("  length field: byte {}", length_offset);
            println!("  payload starts: byte {}", payload_offset);
            println!("  checksum width: {} byte(s)", checksum_width);
        }
    }
}

fn frames_from_framing(stream: &[u8], kind: &FramingKind) -> Vec<Vec<u8>> {
    match kind {
        FramingKind::Prefix(prefix) => {
            // First try fixed-width framing. This handles the case where
            // the sync prefix also occurs inside payload data.
            //
            // Only accept a width when:
            //   1. the stream divides evenly into frames,
            //   2. every frame starts with the detected prefix, and
            //   3. the resulting frames have a valid checksum candidate.
            for frame_len in (prefix.len() + 1)..=stream.len() {
                if stream.len() % frame_len != 0 {
                    continue;
                }

                let frame_count = stream.len() / frame_len;

                if frame_count < 2 {
                    continue;
                }

                let frames: Vec<Vec<u8>> = stream
                    .chunks_exact(frame_len)
                    .filter(|frame| frame.starts_with(prefix))
                    .map(|frame| frame.to_vec())
                    .collect();

                if frames.len() != frame_count {
                    continue;
                }

                if babelfish::checksum::search::best_candidate(&frames).is_some() {
                    return frames;
                }
            }

            // Fall back to normal prefix splitting for protocols where
            // fixed-width framing cannot be established.
            babelfish::framing::split_on_prefix(stream, prefix)
        }

        FramingKind::Length {
            length_offset,
            payload_offset,
            checksum_width,
        } => babelfish::framing::split_on_length_field(
            stream,
            *length_offset,
            *payload_offset,
            *checksum_width,
        ),
    }
}

fn crack_stream_file(path: &str, json: bool) {
    let stream = match parse_hex_stream_file(path) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    };

    let mut framing_candidates = Vec::<FramingCandidate>::new();

    // Search for length-field framing.
    //
    // Layout:
    //   [length][payload...][checksum]
    //
    // The length field is searched in the first four positions.
    for length_offset in 0..=3 {
        let payload_offset = length_offset + 1;

        framing_candidates.extend(infer_length_framing_candidates(
            &stream,
            length_offset,
            length_offset,
            payload_offset,
            1,
        ));
    }

    // Also consider normal prefix/sync framing.
    framing_candidates.extend(babelfish::framing::build_framing_candidates(&stream, 1, 3));

    let framing = match rank_framing_candidates(framing_candidates)
        .into_iter()
        .next()
    {
        Some(candidate) => candidate,

        None => {
            eprintln!("Could not find a framing hypothesis.");
            process::exit(1);
        }
    };

    let frames = frames_from_framing(&stream, &framing.kind);

    if frames.is_empty() {
        eprintln!("Could not recover any frames.");
        process::exit(1);
    }

    let hypothesis = match babelfish::hypothesis::build_hypothesis(framing.clone(), &frames) {
        Some(hypothesis) => hypothesis,

        None => {
            eprintln!("Could not build a protocol hypothesis.");
            process::exit(1);
        }
    };

    let model = ProtocolModel::from_hypothesis(&hypothesis);

    if json {
        match serde_json::to_string_pretty(&model) {
            Ok(output) => {
                println!("{output}");
            }

            Err(error) => {
                eprintln!("Could not serialize protocol model: {error}");
                process::exit(1);
            }
        }

        return;
    }

    println!("Babelfish 🐟");
    println!();
    println!("Raw stream bytes: {}", stream.len());
    println!();

    println!("Best framing candidate:");
    print_framing_kind(&framing.kind);

    println!("  frames: {}", framing.frame_count);

    match &framing.checksum_algorithm {
        Some(algorithm) => {
            println!("  checksum: {}", algorithm);
        }

        None => {
            println!("  checksum: unknown");
        }
    }

    println!(
        "  validation: {}/{} ({:.2}%)",
        framing.checksum_validation_count,
        framing.checksum_total_frames,
        if framing.checksum_total_frames == 0 {
            0.0
        } else {
            framing.checksum_validation_count as f64 / framing.checksum_total_frames as f64 * 100.0
        }
    );

    println!("  confidence: {:.2}", framing.confidence());
    println!("  verdict: {}", framing.verdict());

    println!();

    println!("Protocol hypothesis:");
    print_framing_kind(&hypothesis.framing.kind);
    println!("  frames: {}", hypothesis.framing.frame_count);
    println!("  checksum: {}", hypothesis.checksum.algorithm.name());
    println!(
        "  coverage: bytes[{}..{}]",
        hypothesis.checksum.coverage_start, hypothesis.checksum.coverage_end
    );
    println!(
        "  checksum: bytes[{}..{}]",
        hypothesis.checksum.checksum_start, hypothesis.checksum.checksum_end
    );
    println!(
        "  validation: {}/{} ({:.2}%)",
        hypothesis.checksum.validation_count,
        hypothesis.checksum.total_frames,
        hypothesis.checksum.validation_rate() * 100.0
    );
    println!("  confidence: {:.2}", hypothesis.checksum.confidence());
    println!("  verdict: {}", hypothesis.checksum.verdict());

    println!();

    println!("Evidence:");
    println!(
        "  [Framing   ] {} frames recovered with consistent framing  score: {:.2}",
        hypothesis.framing.frame_count,
        if hypothesis.framing.frame_count > 0 {
            1.0
        } else {
            0.0
        }
    );

    println!(
        "  [Checksum  ] {} validates {}/{} frames  score: {:.2}",
        hypothesis.checksum.algorithm.name(),
        hypothesis.checksum.validation_count,
        hypothesis.checksum.total_frames,
        hypothesis.checksum.validation_rate()
    );

    for field in &hypothesis.fields {
        println!("  [Field     ] byte {} → {:?}", field.position, field.kind);
    }

    println!();

    println!("Fields:");

    for field in &hypothesis.fields {
        println!(
            "  byte {}   {:?}  unique: {}  range: 0x{:02X}..0x{:02X}",
            field.position, field.kind, field.unique_values, field.min_value, field.max_value
        );

        println!("             interpretation: {:?}", field.interpretation());
    }
}
fn explain_model(model: &ProtocolModel) {
    println!("Babelfish 🐟");
    println!();
    println!("Protocol Explanation");
    println!("====================");
    println!();

    println!("Frames");
    println!("------");
    println!("  detected: {}", model.framing.frame_count);
    println!();

    println!("Framing");
    println!("-------");
    println!("  {}", model.framing.kind);

    if let Some(offset) = model.framing.length_offset {
        println!("  length field: byte {}", offset);
    }

    if let Some(offset) = model.framing.payload_offset {
        println!("  payload starts: byte {}", offset);
    }

    println!("  checksum width: {} byte(s)", model.framing.checksum_width);
    println!();

    println!("Checksum");
    println!("--------");
    println!("  algorithm: {}", model.checksum.algorithm);
    println!(
        "  coverage: bytes[{}..{}]",
        model.checksum.coverage_start, model.checksum.coverage_end
    );
    println!(
        "  checksum: bytes[{}..{}]",
        model.checksum.checksum_start, model.checksum.checksum_end
    );
    println!();

    println!("Fields");
    println!("------");

    if model.protocol_fields.is_empty() {
        println!("  No protocol fields inferred.");
    } else {
        for field in &model.protocol_fields {
            println!(
                "  byte[{}..{}]  {:<16} {:<6} {:<24} confidence: {:.0}%",
                field.offset,
                field.offset + field.width,
                field.name,
                field.data_type,
                field.interpretation,
                field.confidence * 100.0
            );
        }
    }

    println!();

    println!("Evidence");
    println!("--------");
    println!("  evidence items: {}", model.evidence.items.len());

    for item in &model.evidence.items {
        println!(
            "  [{:<9}] score: {:.2}  {}",
            item.category, item.score, item.statement
        );
    }

    if let Some(best) = model.evidence.items.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        println!();
        println!("  strongest evidence: {:.2}", best.score);
        println!("  {}", best.statement);
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.len() > 5 {
        print_usage();
        process::exit(1);
    }
    match args[1].as_str() {
        "crack" => {
            if args.len() != 3 {
                print_usage();
                process::exit(1);
            }

            crack_framed_file(&args[2]);
        }

        "crack-stream" => {
            let json = args.get(3).map(|arg| arg == "--json").unwrap_or(false);

            if args.len() == 4 && !json {
                eprintln!("Unknown option '{}'.", args[3]);
                print_usage();
                process::exit(1);
            }

            if args.len() != 3 && args.len() != 4 {
                print_usage();
                process::exit(1);
            }

            crack_stream_file(&args[2], json);
        }
        "explain" => {
            if args.len() != 3 {
                print_usage();
                process::exit(1);
            }

            let frames = match parse_hex_file(&args[2]) {
                Ok(frames) => frames,
                Err(error) => {
                    eprintln!("Error: {error}");
                    process::exit(1);
                }
            };

            if frames.is_empty() {
                eprintln!("No frames found.");
                process::exit(1);
            }

            let framing = FramingCandidate {
                kind: FramingKind::Prefix(Vec::new()),
                frame_count: frames.len(),
                checksum_algorithm: None,
                checksum_validation_count: 0,
                checksum_total_frames: frames.len(),
            };

            let hypothesis = match babelfish::hypothesis::build_hypothesis(framing, &frames) {
                Some(hypothesis) => hypothesis,
                None => {
                    eprintln!("Could not build a protocol hypothesis.");
                    process::exit(1);
                }
            };

            let model = ProtocolModel::from_hypothesis(&hypothesis);

            explain_model(&model);
        }
        "generate" => {
            if args.len() != 5 || args[3] != "--lang" {
                print_usage();
                process::exit(1);
            }

            if args[4] != "rust" {
                eprintln!("Unsupported language '{}'.", args[4]);
                eprintln!("Currently supported: rust");
                process::exit(1);
            }

            // `generate` operates on an already-framed capture.
            // Each line is one complete frame.
            let frames = match parse_hex_file(&args[2]) {
                Ok(frames) => frames,
                Err(error) => {
                    eprintln!("Error: {error}");
                    process::exit(1);
                }
            };

            if frames.is_empty() {
                eprintln!("No frames found.");
                process::exit(1);
            }

            // The capture already gives us frame boundaries.
            //
            // Do NOT blindly interpret byte 0 as a length field.
            // The generator must preserve the fact that these are
            // already-delimited frames.
            //
            // The checksum/field analysis is performed by the
            // hypothesis builder.
            let framing = FramingCandidate {
                kind: FramingKind::Prefix(Vec::new()),
                frame_count: frames.len(),
                checksum_algorithm: None,
                checksum_validation_count: 0,
                checksum_total_frames: frames.len(),
            };

            let hypothesis = match babelfish::hypothesis::build_hypothesis(framing, &frames) {
                Some(hypothesis) => hypothesis,
                None => {
                    eprintln!("Could not build a protocol hypothesis.");
                    process::exit(1);
                }
            };

            let model = ProtocolModel::from_hypothesis(&hypothesis);

            let generated = generate_rust(&model, &frames);

            println!("{generated}");
        }
        _ => {
            eprintln!("Unknown command '{}'.", args[1]);
            eprintln!();
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  babelfish crack <hex-file>");
    println!("  babelfish crack-stream <hex-stream-file> [--json]");
    println!("  babelfish generate <hex-file> --lang rust");
    println!("  babelfish explain <hex-file>");
}
