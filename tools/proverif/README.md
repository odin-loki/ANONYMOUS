# AEGIS Sphinx — ProVerif symbolic model (Wave S3)

Best-effort Dolev–Yao model of idealized Sphinx **hop peel + gamma MAC + replay**.

## Honesty

| This is | This is not |
|---------|-------------|
| Symbolic protocol model (ProVerif 2.05) | Computational proof of ML-KEM-768 / X25519 |
| Idealized `aenc` / `senc` / `mac` | EasyCrypt / CryptoVerif |
| Secrecy / integrity / replay lemmas | Anonymity or traffic-analysis proof |
| Mapped to `sphinx.rs` processing order | Bit-exact rewrite of Rust Sphinx |

## Models

| File | Lemmas |
|------|--------|
| `sphinx_hop.pv` | **L1** secrecy of payload; **L2** integrity (`ExitDeliver` ⇒ `ClientBuilt`) |
| `sphinx_replay.pv` | **L3** injective replay (`HopAccept(t)` ⇒ `ClientBuilt(t)`, at most once) |

Idealized hop (N=3): client builds with fresh per-hop secrets → peel reveals `next_hop` → bad MAC → `MacReject` → duplicate tag → `ReplayReject`.

## Run

```bash
# Linux / WSL
./run_proverif.sh

# Windows (probes WSL)
powershell -File run_proverif.ps1
```

Override binary: `PROVERIF=/path/to/proverif ./run_proverif.sh`

## Install (if probe says MISSING)

1. **opam:** `opam install proverif`
2. **From source:** <https://bblanche.gitlabpages.inria.fr/proverif/> — needs OCaml; `./build` in the tarball
3. **Static amd64 (no sudo / no OCaml):** place executable at `~/tools/proverif_linux_amd64_static` (or set `PROVERIF`)

This PC (2026-07-18): WSL2 Ubuntu available; ProVerif 2.05 static binary used under `~/tools/`.

## Expected results (when ProVerif present)

```
# sphinx_hop.pv
RESULT not attacker_bitstring(secret_payload[]) is true.
RESULT event(ExitDeliver(...secret_payload...)) ==> event(ClientBuilt(...)) is true.

# sphinx_replay.pv
RESULT inj-event(HopAccept(t)) ==> inj-event(ClientBuilt(t)) is true.
```

See also [`docs/ops/sphinx_symbolic_model.md`](../../docs/ops/sphinx_symbolic_model.md).
