#!/usr/bin/env python3
"""
Multi-process trace capture: 4 aegis-node relays + repeated aegis-client sends.

Uses pre-built binaries (not `cargo run` per send), OS-assigned loopback ports,
readiness probes, and `--raw` unpaced sends for a reliable Windows-friendly run.

Writes sim/data/real_multiprocess_trace.csv on success.
"""
from __future__ import annotations

import os
import random
import shutil
import socket
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


def hex32(b0: int, b1: int = 0) -> str:
    buf = bytearray(32)
    buf[0] = b0 & 0xFF
    buf[1] = b1 & 0xFF
    return buf.hex()


def link_key(tag: int) -> str:
    return hex32(tag)


def find_cargo() -> str:
    cargo = shutil.which("cargo")
    if cargo:
        return cargo
    home = Path.home()
    for candidate in (
        home / ".cargo" / "bin" / "cargo.exe",
        home / ".cargo" / "bin" / "cargo",
    ):
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("cargo not found in PATH or ~/.cargo/bin")


def debug_binary(name: str) -> Path:
    exe = f"{name}.exe" if os.name == "nt" else name
    path = CRATES / "target" / "debug" / exe
    if not path.is_file():
        raise RuntimeError(
            f"missing {path}; run: cargo build -p aegis-node -p aegis-client (from crates/)"
        )
    return path


def allocate_loopback_ports(count: int) -> list[int]:
    """Reserve ephemeral loopback ports by bind-then-close (same pattern as Rust :0)."""
    ports: list[int] = []
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            ports.append(int(sock.getsockname()[1]))
            sockets.append(sock)
    finally:
        for sock in sockets:
            sock.close()
    return ports


def wait_for_listen(host: str, port: int, timeout_secs: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_secs
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {host}:{port}: {last_err}")


def write_configs(ports: list[int]) -> tuple[Path, list[str]]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ids = [hex32(i + 1) for i in range(PATH_LEN)]

    for i in range(PATH_LEN):
        peers: list[dict[str, str]] = []
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

        exit_section = ""
        if i == PATH_LEN - 1:
            exit_log = (CONFIG_DIR / "exit_peels.log").resolve()
            exit_path = str(exit_log).replace("\\", "/")
            exit_section = f"""
[exit]
deliver_to = "file:{exit_path}"
"""

        toml = f"""relay_id = "{ids[i]}"
listen = "127.0.0.1:{ports[i]}"
mu = 80.0

[kem]
x25519_seed = "{kem_seed}"
mlkem_d = "{kem_d}"
mlkem_z = "{kem_z}"
{ingress}{exit_section}"""
        for peer in peers:
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
    return client_path, ids


def bursty_gaps_ms(rng: random.Random, n: int) -> list[int]:
    gaps: list[int] = []
    while len(gaps) < n:
        if len(gaps) + 1 < n and len(gaps) % 11 < 4:
            cluster = min(4, n - len(gaps))
            gaps.extend(50 + rng.randint(0, 130) for _ in range(cluster))
        else:
            gaps.append(800 + rng.randint(0, 2700))
    return gaps[:n]


def terminate_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def drain_stderr(proc: subprocess.Popen) -> str:
    if proc.stderr is None:
        return ""
    try:
        return proc.stderr.read().decode(errors="replace")
    except Exception:
        return ""


def main() -> int:
    SIM_DATA.mkdir(parents=True, exist_ok=True)
    out_path = SIM_DATA / "real_multiprocess_trace.csv"

    cargo = find_cargo()
    print(f"building aegis-node and aegis-client via {cargo}...")
    subprocess.run(
        [cargo, "build", "--quiet", "-p", "aegis-node", "-p", "aegis-client"],
        cwd=CRATES,
        check=True,
    )

    node_bin = debug_binary("aegis-node")
    client_bin = debug_binary("aegis-client")

    ports = allocate_loopback_ports(PATH_LEN)
    client_cfg, relay_ids = write_configs(ports)
    print(f"wrote configs under {CONFIG_DIR} (ports={ports})")

    node_procs: list[subprocess.Popen] = []
    try:
        for i in range(PATH_LEN):
            cfg = CONFIG_DIR / f"node{i}.toml"
            proc = subprocess.Popen(
                [str(node_bin), "--config", str(cfg)],
                cwd=CRATES,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            node_procs.append(proc)

        for port in ports:
            wait_for_listen("127.0.0.1", port)

        for i, proc in enumerate(node_procs):
            if proc.poll() is not None:
                err = drain_stderr(proc)
                raise RuntimeError(f"node{i} exited before ready: {err}")

        rng = random.Random(42)
        gaps = bursty_gaps_ms(rng, N_SENDS - 1)
        rows: list[tuple[float, int, int]] = []

        for i in range(N_SENDS):
            payload_len = 32 + (i * 17) % 225
            ts = time.time()
            result = subprocess.run(
                [
                    str(client_bin),
                    "--config",
                    str(client_cfg),
                    "--payload",
                    f"mp-{i}-{payload_len}",
                    "--raw",
                ],
                cwd=CRATES,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                tail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(
                    f"client send {i}/{N_SENDS} failed (exit {result.returncode}): {tail}"
                )
            rows.append((ts, payload_len, CELL_COUNT))
            if i + 1 < N_SENDS:
                time.sleep(gaps[i] / 1000.0)

            if any(proc.poll() is not None for proc in node_procs):
                dead = next(idx for idx, p in enumerate(node_procs) if p.poll() is not None)
                err = drain_stderr(node_procs[dead])
                raise RuntimeError(f"node{dead} exited during capture: {err}")

        with out_path.open("w", encoding="utf-8") as f:
            f.write("timestamp,payload_bytes,cell_count\n")
            f.write("# vantage=orchestrator_wall_clock_at_client_invoke\n")
            f.write(
                f"# capture=multiprocess_tcp_testnet path_len={PATH_LEN} "
                f"n_sends={N_SENDS} ports={ports} relay_ids={relay_ids}\n"
            )
            for ts, payload_bytes, cell_count in rows:
                f.write(f"{ts:.6f},{payload_bytes},{cell_count}\n")

        duration = rows[-1][0] - rows[0][0]
        print(f"wrote {len(rows)} events ({duration:.1f}s span) to {out_path}")
        return 0
    finally:
        for proc in node_procs:
            terminate_process(proc)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"multiprocess capture failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
