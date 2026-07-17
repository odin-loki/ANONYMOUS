//! Consortium key-ceremony CLI (ops).
//!
//! ```text
//! cargo run -p aegis-topology --bin aegis-ceremony -- --help
//! cargo run -p aegis-topology --bin aegis-ceremony -- \
//!   --out ./ceremony-out --n 3 --threshold 2 --jurisdiction US
//! cargo run -p aegis-topology --bin aegis-ceremony -- \
//!   --out ./ceremony-out --n 3 --threshold 2 \
//!   --shamir-n 3 --shamir-threshold 2
//! cargo run -p aegis-topology --bin aegis-ceremony -- \
//!   --reconstruct share-0.hex share-1.hex --reconstruct-out seed.hex
//! ```
//!
//! See `docs/ops/consortium_key_ceremony.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_topology::ceremony::{
    reconstruct_seed_from_files, run_ceremony, write_reconstructed_seed, CeremonyConfig,
};
use clap::Parser;
use rand_core::OsRng;

#[derive(Parser, Debug)]
#[command(
    name = "aegis-ceremony",
    about = "Generate M-of-N consortium authority keys and a sample signed RelayRecord admission",
    after_help = "Dry-run: cargo run -p aegis-topology --bin aegis-ceremony -- --help"
)]
struct Args {
    /// Output directory for keys and sample admission JSON.
    #[arg(long, default_value = "ceremony-out")]
    out: PathBuf,

    /// Number of authority keys (N).
    #[arg(long, default_value_t = 3)]
    n: usize,

    /// Admission threshold (M). Must satisfy 1 <= M <= N.
    #[arg(long, default_value_t = 2)]
    threshold: usize,

    /// Jurisdiction label for the sample relay record.
    #[arg(long, default_value = "US")]
    jurisdiction: String,

    /// Write authority signing seeds as hex (lab only; protect offline).
    #[arg(long, default_value_t = true)]
    write_seeds: bool,

    /// Optional Shamir share count per authority seed.
    #[arg(long)]
    shamir_n: Option<usize>,

    /// Optional Shamir reconstruction threshold (requires --shamir-n).
    #[arg(long)]
    shamir_threshold: Option<usize>,

    /// Lab: reconstruct a seed from these Shamir share hex files (skips ceremony).
    #[arg(long, num_args = 1.., value_name = "SHARE_HEX")]
    reconstruct: Option<Vec<PathBuf>>,

    /// Lab: write reconstructed seed hex here (with --reconstruct).
    #[arg(long, default_value = "reconstructed.seed.hex")]
    reconstruct_out: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(share_paths) = args.reconstruct {
        return match reconstruct_seed_from_files(&share_paths) {
            Ok(seed) => {
                if let Err(e) = write_reconstructed_seed(&args.reconstruct_out, &seed) {
                    eprintln!("aegis-ceremony: write seed: {e}");
                    return ExitCode::FAILURE;
                }
                eprintln!(
                    "reconstructed seed -> {} (SECRET — offline only)",
                    args.reconstruct_out.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("aegis-ceremony: reconstruct: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let cfg = CeremonyConfig {
        n: args.n,
        threshold: args.threshold,
        jurisdiction: args.jurisdiction,
        write_seeds: args.write_seeds,
        shamir_n: args.shamir_n,
        shamir_threshold: args.shamir_threshold,
    };
    match run_ceremony(&args.out, &cfg, &mut OsRng) {
        Ok(out) => {
            eprintln!(
                "ceremony complete: N={} M={} out={}",
                cfg.n,
                cfg.threshold,
                args.out.display()
            );
            eprintln!("  authorities/authority-*.pub.hex");
            if cfg.write_seeds {
                eprintln!("  authorities/authority-*.seed.hex  (SECRET — offline only)");
            }
            if cfg.shamir_n.is_some() {
                eprintln!(
                    "  authorities/authority-*/share-*.hex  (Shamir {}-of-{}; SECRET)",
                    cfg.shamir_threshold.unwrap_or(0),
                    cfg.shamir_n.unwrap_or(0)
                );
                let total: usize = out.shamir_share_paths.iter().map(|v| v.len()).sum();
                eprintln!("  wrote {total} share file(s)");
            }
            eprintln!("  sample_admission.json (verified M-of-N)");
            eprintln!("  consortium.json");
            eprintln!("  roster_authority.toml.snippet");
            eprintln!("  pubkeys: {}", out.authority_pubkeys_hex.join(", "));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aegis-ceremony: {e}");
            ExitCode::FAILURE
        }
    }
}
