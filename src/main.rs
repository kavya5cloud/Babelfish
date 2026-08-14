use std::env;
use std::process;

use babelfish::checksum::search::rank_candidates;
use babelfish::framing::best_framing_candidate;
use babelfish::input::{
    parse_hex_file,
    parse_hex_stream_file,
};

fn print_checksum_candidates(
    frames: &[Vec<u8>],
) {
    let candidates = rank_candidates(
        babelfish::checksum::search::search_algorithms(frames)
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
            eprintln!("Could not find a framing hypothesis.");
            process::exit(1);
        }
    };

    println!("Best framing candidate:");
    println!(
        "  prefix: {:02X?}",
        framing.prefix
    );
    println!(
        "  frames: {}",
        framing.frame_count
    );
    println!(
        "  checksum validation: {}/{} ({:.2}%)",
        framing.checksum_validation_count,
        framing.checksum_total_frames,
        if framing.checksum_total_frames == 0 {
            0.0
        } else {
            framing.checksum_validation_count as f64
                / framing.checksum_total_frames as f64
                * 100.0
        }
    );
    println!();

    let frames =
        babelfish::framing::split_on_prefix(
            &stream,
            &framing.prefix,
        );

    print_checksum_candidates(&frames);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!(
            "Usage:\n  babelfish crack <capture.txt>\n  babelfish crack-stream <stream.txt>"
        );
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
                "Unknown command '{}'.\n\nUsage:\n  babelfish crack <capture.txt>\n  babelfish crack-stream <stream.txt>",
                args[1]
            );
            process::exit(1);
        }
    }
}