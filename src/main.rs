use std::env;
use std::process;

use babelfish::input::parse_hex_file;
use babelfish::checksum::search::rank_candidates;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 || args[1] != "crack" {
        eprintln!("Usage: babelfish crack <capture.txt>");
        process::exit(1);
    }

    let path = &args[2];

    let frames = match parse_hex_file(path) {
        Ok(frames) => frames,
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    };

    let candidates =
        rank_candidates(
            babelfish::checksum::search::search_algorithms(&frames)
        );

    println!("Babelfish 🐟");
    println!();
    println!("Frames: {}", frames.len());
    println!();

    println!("Candidates:");

    for candidate in &candidates {
        println!(
            "  {:<14} {:>4}/{:<4} {:>7.2}% {:>9}",
            candidate.algorithm.name(),
            candidate.validation_count,
            candidate.total_frames,
            candidate.validation_rate() * 100.0,
            candidate.verdict(),
        );
    }

    println!();

    if let Some(best) = candidates.first() {
        println!("Best candidate:");
        println!(
            "  {}",
            best.algorithm.name()
        );
    } else {
        println!("No viable checksum candidates found.");
    }
}