#!/usr/bin/env python3
"""
Paced multi-process relay forward trace capture.

4 aegis-node relays + repeated paced aegis-client sends (NOT --raw).
Enables [trace].path on ingress (forward/cover) and exit (exit rows), merges
into sim/data/real_multiprocess_relay_forward_trace.csv.

Regen (Windows):
  cd sim && python scripts/capture_multiprocess_relay_forward_trace.py

Requires pre-built binaries under crates/target/debug/ (script builds once).
"""
from __future__ import annotations

import argparse
import os
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
DEFAULT_N_SENDS = 12
PATH_LEN = 4
TAU_SECS = 0.05
COVER_SECS = 0.1
DRAIN_SECS = 8.0
OUT_PATH = SIM_DATA / "real_multiprocess_relay_forward_trace.csv"


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


def toml_path(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/")


def write_configs(ports: list[int]) -> tuple[Path, list[str], Path, Path]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ids = [hex32(i + 1) for i in range(PATH_LEN)]
    ingress_trace = CONFIG_DIR / "ingress_relay_forward_trace.csv"
    exit_trace = CONFIG_DIR / "exit_relay_forward_trace.csv"

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

        trace_section = ""
        if i == 0:
            trace_section = f"""
[trace]
path = "{toml_path(ingress_trace)}"
"""
        elif i == PATH_LEN - 1:
            trace_section = f"""
[trace]
path = "{toml_path(exit_trace)}"
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

[link]
max_cells_per_sec = 0.0
burst = 0
global_max_cells_per_sec = 0.0

[kem]
x25519_seed = "{kem_seed}"
mlkem_d = "{kem_d}"
mlkem_z = "{kem_z}"
{ingress}{trace_section}{exit_section}"""
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
payload = "mp-relay-trace"
{hops_toml}
"""
    client_path = CONFIG_DIR / "client.toml"
    client_path.write_text(client_toml, encoding="utf-8")
    return client_path, ids, ingress_trace, exit_trace


def parse_trace_rows(path: Path) -> list[tuple[float, int, str]]:
    if not path.is_file():
        return []
    rows: list[tuple[float, int, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("timestamp,"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        rows.append((float(parts[0]), int(parts[1]), parts[2]))
    return rows


def merge_traces(
    ingress_trace: Path,
    exit_trace: Path,
    out_path: Path,
    *,
    path_len: int,
    n_sends: int,
    ports: list[int],
    relay_ids: list[str],
) -> dict[str, int]:
    ingress_rows = parse_trace_rows(ingress_trace)
    exit_rows = [(ts, cc, ev) for ts, cc, ev in parse_trace_rows(exit_trace) if ev == "exit"]
    merged = sorted(ingress_rows + exit_rows, key=lambda r: r[0])

    counts: dict[str, int] = {}
    for _, _, ev in merged:
        counts[ev] = counts.get(ev, 0) + 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("timestamp,cell_count,event_type\n")
        f.write("# vantage=relay_post_forward\n")
        f.write(
            f"# capture=multiprocess_paced path_len={path_len} n_sends={n_sends} "
            f"tau_secs={TAU_SECS} cover_secs={COVER_SECS} ports={ports} "
            f"relay_ids={relay_ids}\n"
        )
        for ts, cell_count, event_type in merged:
            f.write(f"{ts:.6f},{cell_count},{event_type}\n")

    return counts


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--n-sends",
        type=int,
        default=DEFAULT_N_SENDS,
        help=(
            "paced CLI send count (default 12 for CI-friendly relay-forward capture; "
            "use 48 to match client-send schedule in phase8 §4 — ~4× wall time)"
        ),
    )
    args = parser.parse_args()
    n_sends = args.n_sends
    if n_sends < 1:
        raise SystemExit("--n-sends must be >= 1")

    SIM_DATA.mkdir(parents=True, exist_ok=True)
    for stale in (
        CONFIG_DIR / "ingress_relay_forward_trace.csv",
        CONFIG_DIR / "exit_relay_forward_trace.csv",
        OUT_PATH,
    ):
        if stale.is_file():
            stale.unlink()

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
    client_cfg, relay_ids, ingress_trace, exit_trace = write_configs(ports)
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

        for i in range(n_sends):
            payload_len = 32 + (i * 17) % 225
            result = subprocess.run(
                [
                    str(client_bin),
                    "--config",
                    str(client_cfg),
                    "--payload",
                    f"mp-rf-{i}-{payload_len}",
                    "--tau-secs",
                    str(TAU_SECS),
                    "--cover-secs",
                    str(COVER_SECS),
                    "--no-require-kem-binding",
                ],
                cwd=CRATES,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                tail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(
                    f"paced client send {i + 1}/{n_sends} failed (exit {result.returncode}): {tail}"
                )

            if any(proc.poll() is not None for proc in node_procs):
                dead = next(idx for idx, p in enumerate(node_procs) if p.poll() is not None)
                err = drain_stderr(node_procs[dead])
                raise RuntimeError(f"node{dead} exited during capture: {err}")

        # Allow last fragments to traverse 4 hops and trace writers to flush.
        time.sleep(DRAIN_SECS)

        counts = merge_traces(
            ingress_trace,
            exit_trace,
            OUT_PATH,
            path_len=PATH_LEN,
            n_sends=n_sends,
            ports=ports,
            relay_ids=relay_ids,
        )
        total = sum(counts.values())
        if total == 0:
            raise RuntimeError("no relay forward trace rows captured")
        for kind in ("forward", "cover", "exit"):
            if counts.get(kind, 0) == 0:
                raise RuntimeError(
                    f"missing {kind} rows (counts={counts}); "
                    f"ingress={ingress_trace} exit={exit_trace}"
                )

        duration = 0.0
        rows = parse_trace_rows(OUT_PATH)
        if len(rows) >= 2:
            duration = rows[-1][0] - rows[0][0]
        print(
            f"wrote {total} events ({counts}) span={duration:.1f}s to {OUT_PATH}"
        )
        return 0
    finally:
        for proc in node_procs:
            terminate_process(proc)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"relay forward trace capture failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
