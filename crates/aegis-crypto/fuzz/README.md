# aegis-crypto fuzz targets

LibFuzzer harnesses for Sphinx / link / KEM / fragment parsers.  
**Not a formal proof** — crash and panic finding only.

## Targets

| Binary | Entry | Notes |
|--------|-------|-------|
| `fuzz_sphinx_process` | `sphinx::process` | Fixed deterministic relay key; pads/truncates input to `SPHINX_PACKET_LEN` (8512) |
| `fuzz_kem_decap` | hybrid KEM decap | Malformed ciphertext surface |
| `fuzz_link_open` | link AEAD open | Frame parse / tag fail |
| `fuzz_fragment_reassemble` | fragment reassembly | Count / size edges |

## Prerequisites (no Docker)

- Nightly Rust with `cargo-fuzz` (`cargo install cargo-fuzz`)
- On Windows: prefer **WSL2** (libFuzzer MSVC support is fragile). Native Windows may fail to link `libfuzzer-sys`.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Seed corpus (recommended before overnight)

```bash
# from repo root
python scripts/seed_sphinx_fuzz_corpus.py
# python scripts/seed_sphinx_fuzz_corpus.py --list
```

Writes fixed-size, truncated, layout-boundary, and region-pattern seeds under
`crates/aegis-crypto/fuzz/corpus/fuzz_sphinx_process/` (alpha/beta/gamma/delta).

## Evidence pack (preferred)

Agent-friendly timed run (~12 min) + honest summary under `sim/sphinx_fuzz_evidence.txt`:

```bash
# WSL / Linux
SPHINX_FUZZ_MODE=short bash scripts/run_sphinx_fuzz_evidence.sh

# Windows host → WSL
powershell -File scripts/run_sphinx_fuzz_evidence.ps1 -Mode short
```

## Overnight Sphinx process fuzz (WSL / Linux) — 8h

```bash
SPHINX_FUZZ_MODE=overnight bash scripts/run_sphinx_fuzz_evidence.sh

# or manually:
cd crates/aegis-crypto/fuzz
python3 ../../../scripts/seed_sphinx_fuzz_corpus.py
cargo +nightly fuzz run fuzz_sphinx_process -- \
  -max_total_time=28800 \
  -rss_limit_mb=4096 \
  -timeout=5 \
  -artifact_prefix=artifacts/fuzz_sphinx_process/
```

Shorter manual smoke (5 minutes):

```bash
cargo +nightly fuzz run fuzz_sphinx_process -- -max_total_time=300
```

## Interpreting results

- Exit 0 with no new files under `artifacts/fuzz_sphinx_process/` ⇒ no crash found in that window.
- Any `crash-*` / `oom-*` / `timeout-*` artifact is a finding: minimize with
  `cargo +nightly fuzz tmin fuzz_sphinx_process <artifact>` and open a bug.
- Valid packets for the harness's fixed key are rare; most inputs hit
  `IntegrityFailure` / `Malformed` / `Kem` early — still useful for panic/UB search.

## Harness notes (wave S1)

- Input is copied into a fixed `[u8; SPHINX_PACKET_LEN]` buffer (zero-padded).
- Replay cache capacity is 256 (keeps RSS bounded under long runs).
- Do **not** claim overnight fuzz equals verification or a Sphinx proof.
