#!/usr/bin/env python3
"""
Generate operator-pilot configs via aegis-pilot-gen (verified roster, production defaults).

Writes sim/data/pilot_configs/ by default, or --out with optional ephemeral loopback ports.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
DEFAULT_OUT = ROOT / "sim" / "data" / "pilot_configs"
PATH_LEN = 4
DEFAULT_PORTS = [17419, 17420, 17421, 17422]


def find_cargo() -> str:
    cargo = shutil.which("cargo")
    if cargo:
        return cargo
    home = Path.home()
    for candidate in (home / ".cargo" / "bin" / "cargo.exe", home / ".cargo" / "bin" / "cargo"):
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("cargo not found in PATH or ~/.cargo/bin")


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AEGIS operator pilot configs")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output directory")
    parser.add_argument(
        "--ephemeral-ports",
        action="store_true",
        help="Use OS-assigned loopback ports instead of fixed 17419-17422",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default="",
        help="Comma-separated ports (4 values); overrides --ephemeral-ports when set",
    )
    parser.add_argument(
        "--network",
        choices=("loopback", "bridge"),
        default="loopback",
        help="Peer addressing: loopback (127.0.0.1) or bridge (Docker service names)",
    )
    parser.add_argument("--skip-build", action="store_true", help="Skip cargo build of aegis-pilot-gen")
    args = parser.parse_args()

    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
        if len(ports) != PATH_LEN:
            print(f"expected {PATH_LEN} ports, got {len(ports)}", file=sys.stderr)
            return 1
    elif args.ephemeral_ports:
        ports = allocate_loopback_ports(PATH_LEN)
    else:
        ports = DEFAULT_PORTS

    cargo = find_cargo()
    if not args.skip_build:
        subprocess.run(
            [cargo, "build", "--quiet", "-p", "aegis-topology", "--bin", "aegis-pilot-gen"],
            cwd=CRATES,
            check=True,
        )

    pilot_gen = CRATES / "target" / "debug" / ("aegis-pilot-gen.exe" if os.name == "nt" else "aegis-pilot-gen")
    if not pilot_gen.is_file():
        print(f"missing {pilot_gen}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    ports_arg = ",".join(str(p) for p in ports)
    subprocess.run(
        [
            str(pilot_gen),
            "--out",
            str(args.out.resolve()),
            "--ports",
            ports_arg,
            "--network",
            args.network,
        ],
        check=True,
    )
    print(f"pilot configs ready under {args.out} (ports={ports}, network={args.network})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"generate_pilot_configs failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
