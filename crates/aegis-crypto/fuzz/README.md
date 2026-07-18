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
```

Writes a few fixed-size and truncated seeds under
`crates/aegis-crypto/fuzz/corpus/fuzz_sphinx_process/`.

## Overnight Sphinx process fuzz (WSL / Linux)

```bash
cd crates/aegis-crypto/fuzz
# optional: seed first from Windows host or inside WSL
python3 ../../../scripts/seed_sphinx_fuzz_corpus.py

# ~8h overnight; adjust -max_total_time=
cargo +nightly fuzz run fuzz_sphinx_process -- \
  -max_total_time=28800 \
  -rss_limit_mb=4096 \
  -timeout=5 \
  -artifact_prefix=artifacts/fuzz_sphinx_process/
```

Shorter smoke (5 minutes):

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
