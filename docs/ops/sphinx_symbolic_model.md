# Sphinx symbolic model (Wave S3)

**Date:** 2026-07-18  
**Tip baseline:** 3819c1b  
**Tooling:** ProVerif 2.05 (Dolev–Yao) under `tools/proverif/`  
**Not claimed:** EasyCrypt, computational ML-KEM proof, anonymity

## Mapping to Rust Sphinx

Processing order in `crates/aegis-crypto/src/sphinx.rs`:

1. Decap (hybrid KEM header / alpha) → per-hop shared secret  
2. Verify gamma MAC over beta  
3. Replay tag check (`ReplayCache`)  
4. Peel: reveal `next_hop`, shift beta, refresh alpha/gamma, XOR delta  

Symbolic stand-ins:

| Rust | Model |
|------|--------|
| Hybrid KEM SS | `aenc(ss, pk(sk))` / `adec` |
| SHA3 stream XOR (beta/delta) | `senc` / `sdec` |
| Keyed SHA3 gamma | `mac(beta, ss)` |
| Replay tag | `rtag(ss)` + table / phase reject |

## Models and lemmas

### `tools/proverif/sphinx_hop.pv` (N=3 path)

| ID | Lemma | ProVerif query | Status (this PC) |
|----|-------|----------------|------------------|
| L1 | Secrecy of payload from non-path adversary | `not attacker(secret_payload)` | **proved** |
| L2 | Integrity — deliver of confidential payload only after client build | `ExitDeliver(sid, secret_payload) ==> ClientBuilt(sid)` | **proved** |

Operational (encoded in processes, not separate correspondence queries):

- Bad gamma → `MacReject`  
- Duplicate `rtag(ss)` → `ReplayReject`  
- Peel reveals next hop id (`HB` / `HC` / `END`)

### `tools/proverif/sphinx_replay.pv` (single hop)

| ID | Lemma | ProVerif query | Status (this PC) |
|----|-------|----------------|------------------|
| L3 | Replay — at most one accept per client session tag | `inj-event(HopAccept(t)) ==> inj-event(ClientBuilt(t))` | **proved** |

Phase 0: MAC-valid packet accepted once. Phase 1: re-presentation → `ReplayReject` only (no second `HopAccept`).

## How to run

```bash
# WSL / Linux
tools/proverif/run_proverif.sh

# Windows host
powershell -File tools/proverif/run_proverif.ps1
```

If ProVerif is missing, scripts exit `2` with install steps and still document expected lemmas (see `tools/proverif/README.md`).

## Limits (read before citing)

- Idealized cryptography: MAC/enc are perfect symbolic primitives.  
- **≠** a reduction to ML-KEM-768 or X25519 IND-CCA.  
- **≠** EasyCrypt / machine-checked computational proof.  
- Public mix KEM keys allow third-party cover packets; L2 is about the **confidential client payload**, not “no packet is ever accepted unless from our client.”  
- No anonymity, unlinkability, or traffic-analysis lemmas (out of scope for S3).
