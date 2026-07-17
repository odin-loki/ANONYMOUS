//! Consortium key-ceremony CLI (ops).
//!
//! ```text
//! cargo run -p aegis-topology --bin aegis-ceremony -- --help
//! cargo run -p aegis-topology --bin aegis-ceremony -- \
//!   --out ./ceremony-out --n 3 --threshold 2 --jurisdiction US
//! ```
//!
//! See `docs/ops/consortium_key_ceremony.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_topology::ceremony::{run_ceremony, CeremonyConfig};
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
}

fn main() -> ExitCode {
    let args = Args::parse();
    let cfg = CeremonyConfig {
        n: args.n,
        threshold: args.threshold,
        jurisdiction: args.jurisdiction,
        write_seeds: args.write_seeds,
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
            eprintln!("  sample_admission.json (verified M-of-N)");
            eprintln!("  consortium.json");
            eprintln!("  roster_authority.toml.snippet");
            eprintln!(
                "  pubkeys: {}",
                out.authority_pubkeys_hex.join(", ")
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aegis-ceremony: {e}");
            ExitCode::FAILURE
        }
    }
}
