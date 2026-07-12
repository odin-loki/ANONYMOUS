#!/usr/bin/env python3
"""
Attempt multi-process trace capture: 4 aegis-node relays + repeated aegis-client sends.

Writes sim/data/real_testnet_trace_multiprocess.csv on success. This script is
best-effort; the in-process Rust gate in crates/aegis-node/tests/trace_capture.rs
is the reliable fallback when OS process orchestration is flaky.
"""
from __future__ import annotations

import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
SIM_DATA = ROOT / "sim" / "data"
CONFIG_DIR = SIM_DATA / "testnet_configs"
CELL_COUNT = 18
N_SENDS = 48
PATH_LEN = 4
BASE_PORT = 19200


def hex32(b0: int, b1: int = 0) -> str:
    buf = bytearray(32)
    buf[0] = b0 & 0xFF
    buf[1] = b1 & 0xFF
    return buf.hex()


def link_key(tag: int) -> str:
    return hex32(tag)


def write_configs() -> tuple[Path, list[int]]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ports = [BASE_PORT + i for i in range(PATH_LEN)]
    ids = [hex32(i + 1) for i in range(PATH_LEN)]

    for i in range(PATH_LEN):
        peers = []
        if i > 0:
            peers.append(
                {
                    "id": ids[i - 1],
                    "addr": f"127.0.0.1:{ports[i - 1]}",
                    "link_key": link_key(i),
                }
            )
        if i + 1 < PATH_LEN:
            peers.append(
                {
                    "id": ids[i + 1],
                    "addr": f"127.0.0.1:{ports[i + 1]}",
                    "link_key": link_key(i + 1),
                }
            )

        ingress = ""
        if i == 0:
            ingress = f"""
[ingress]
link_key = "{link_key(0xC0)}"
"""

        kem_seed = hex32(0x10 + i, 0x20 + i)
        kem_d = hex32(0x30 + i, 0x40 + i)
        kem_z = hex32(0x50 + i, 0x60 + i)

        toml = f"""relay_id = "{ids[i]}"
listen = "127.0.0.1:{ports[i]}"
mu = 80.0

[kem]
x25519_seed = "{kem_seed}"
mlkem_d = "{kem_d}"
mlkem_z = "{kem_z}"
{ingress}
"""
        for j, peer in enumerate(peers):
            toml += f"""
[[peers]]
id = "{peer['id']}"
addr = "{peer['addr']}"
link_key = "{peer['link_key']}"
"""

        (CONFIG_DIR / f"node{i}.toml").write_text(toml, encoding="utf-8")

    hops_toml = ""
    for i in range(PATH_LEN):
        hops_toml += f"""
[[hops]]
id = "{ids[i]}"
kem_x25519_seed = "{hex32(0x10 + i, 0x20 + i)}"
kem_mlkem_d = "{hex32(0x30 + i, 0x40 + i)}"
kem_mlkem_z = "{hex32(0x50 + i, 0x60 + i)}"
"""

    client_toml = f"""first_hop_addr = "127.0.0.1:{ports[0]}"
ingress_link_key = "{link_key(0xC0)}"
payload = "mp-trace"
{hops_toml}
"""
    client_path = CONFIG_DIR / "client.toml"
    client_path.write_text(client_toml, encoding="utf-8")
    return client_path, ports


def bursty_gaps_ms(rng: random.Random, n: int) -> list[int]:
    gaps: list[int] = []
    while len(gaps) < n:
        if len(gaps) + 1 < n and len(gaps) % 11 < 4:
            cluster = min(4, n - len(gaps))
            gaps.extend(50 + rng.randint(0, 130) for _ in range(cluster))
        else:
            gaps.append(800 + rng.randint(0, 2700))
    return gaps[:n]


def cargo_bin(pkg: str) -> list[str]:
    return ["cargo", "run", "--quiet", "-p", pkg, "--"]


def main() -> int:
    SIM_DATA.mkdir(parents=True, exist_ok=True)
    out_path = SIM_DATA / "real_testnet_trace_multiprocess.csv"

    print("building aegis-node and aegis-client...")
    subprocess.run(
        ["cargo", "build", "--quiet", "-p", "aegis-node", "-p", "aegis-client"],
        cwd=CRATES,
        check=True,
    )

    client_cfg, ports = write_configs()
    print(f"wrote configs under {CONFIG_DIR}")

    node_procs: list[subprocess.Popen] = []
    try:
        for i in range(PATH_LEN):
            cfg = CONFIG_DIR / f"node{i}.toml"
            proc = subprocess.Popen(
                cargo_bin("aegis-node") + ["--config", str(cfg)],
                cwd=CRATES,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            node_procs.append(proc)

        time.sleep(2.0)
        for i, proc in enumerate(node_procs):
            if proc.poll() is not None:
                err = proc.stderr.read().decode() if proc.stderr else ""
                raise RuntimeError(f"node{i} exited early: {err}")

        rng = random.Random(42)
        gaps = bursty_gaps_ms(rng, N_SENDS - 1)
        rows: list[tuple[float, int, int]] = []

        for i in range(N_SENDS):
            payload_len = 32 + (i * 17) % 225
            ts = time.time()
            subprocess.run(
                cargo_bin("aegis-client")
                + [
                    "--config",
                    str(client_cfg),
                    "--payload",
                    f"mp-{i}-{payload_len}",
                ],
                cwd=CRATES,
                check=True,
                capture_output=True,
            )
            rows.append((ts, payload_len, CELL_COUNT))
            if i + 1 < N_SENDS:
                time.sleep(gaps[i] / 1000.0)

        with out_path.open("w", encoding="utf-8") as f:
            f.write("timestamp,payload_bytes,cell_count\n")
            f.write("# vantage=orchestrator_wall_clock_at_client_invoke\n")
            f.write(
                f"# capture=multiprocess_tcp_testnet path_len={PATH_LEN} "
                f"n_sends={N_SENDS} ports={ports}\n"
            )
            for ts, payload_bytes, cell_count in rows:
                f.write(f"{ts:.6f},{payload_bytes},{cell_count}\n")

        duration = rows[-1][0] - rows[0][0]
        print(f"wrote {len(rows)} events ({duration:.1f}s span) to {out_path}")
        return 0
    finally:
        for proc in node_procs:
            proc.terminate()
        for proc in node_procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"multiprocess capture failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
