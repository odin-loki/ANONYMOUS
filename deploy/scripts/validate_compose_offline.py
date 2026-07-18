#!/usr/bin/env python3
"""Offline validation for the AEGIS Docker compose pilot pack.

Runs without a Docker daemon: YAML compose lint, TOML structural checks,
and optional `aegis-node validate` (pilot configs are expected to FAIL on
lab KEM flags; production templates are shape-checked only).

Exit 0 = pack structurally OK. Does NOT claim containers ran.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
PILOT_CFG = COMPOSE_DIR / "pilot_configs"
TEMPLATES = REPO_ROOT / "deploy" / "templates"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence"

EXPECTED_SERVICES = ("node0", "node1", "node2", "node3", "client")
NODE_PORTS = {
    "node0": 17419,
    "node1": 17420,
    "node2": 17421,
    "node3": 17422,
}
# Pilot intentionally uses lab KEM convenience; production validate must report these.
EXPECTED_PILOT_LAB_ERRORS = {
    "kem.allow_plaintext_kem",
    "kem inline seeds",
}


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def note(self, msg: str) -> None:
        self.info.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_compose(findings: Findings) -> dict | None:
    if not COMPOSE_FILE.is_file():
        findings.error(f"missing compose file: {COMPOSE_FILE}")
        return None
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    if yaml is None:
        findings.error("PyYAML not installed — run: pip install pyyaml")
        # Minimal fallback: ensure file is non-empty YAML-looking
        if "services:" not in text:
            findings.error("compose file lacks services: key (raw check)")
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        findings.error(f"compose YAML parse failed: {e}")
        return None
    if not isinstance(data, dict):
        findings.error("compose root must be a mapping")
        return None
    findings.note(f"compose YAML parsed OK ({COMPOSE_FILE.relative_to(REPO_ROOT)})")
    return data


def lint_compose(data: dict, findings: Findings) -> None:
    services = data.get("services")
    if not isinstance(services, dict):
        findings.error("compose.services missing or not a mapping")
        return

    for name in EXPECTED_SERVICES:
        if name not in services:
            findings.error(f"compose missing service: {name}")

    networks = data.get("networks")
    if not isinstance(networks, dict) or "aegis-pilot" not in networks:
        findings.error("compose.networks.aegis-pilot missing")

    for name, svc in services.items():
        if not isinstance(svc, dict):
            findings.error(f"service {name}: not a mapping")
            continue
        if "build" not in svc and "image" not in svc:
            findings.error(f"service {name}: needs build or image")
        vols = svc.get("volumes") or []
        if not any("pilot_configs" in str(v) or "/config" in str(v) for v in vols):
            findings.warn(f"service {name}: no /config or pilot_configs volume mount")
        if name.startswith("node") and "healthcheck" not in svc:
            findings.warn(f"service {name}: no healthcheck (recommended for pilot realism)")
        if name.startswith("node") and "restart" not in svc:
            findings.warn(f"service {name}: no restart policy")

    client = services.get("client")
    if isinstance(client, dict):
        profiles = client.get("profiles") or []
        if "client" not in profiles:
            findings.error("client service should use profiles: [client]")
        deps = client.get("depends_on")
        if not deps:
            findings.warn("client: depends_on empty")

    findings.note(
        "compose structure: "
        + ", ".join(sorted(services.keys()))
        + f" | networks={list((networks or {}).keys())}"
    )


def load_toml(path: Path, findings: Findings) -> dict | None:
    if tomllib is None:
        findings.error("tomllib unavailable (need Python 3.11+)")
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        findings.error(f"TOML parse failed {path.name}: {e}")
        return None


def check_pilot_tomls(findings: Findings) -> None:
    if not PILOT_CFG.is_dir():
        findings.error(f"missing pilot_configs dir: {PILOT_CFG}")
        return

    required = [f"node{i}.toml" for i in range(4)] + [
        "client.toml",
        "roster.json",
        "authority.pub.hex",
    ]
    for name in required:
        if not (PILOT_CFG / name).is_file():
            findings.error(f"pilot_configs missing: {name}")

    for i in range(4):
        path = PILOT_CFG / f"node{i}.toml"
        if not path.is_file():
            continue
        cfg = load_toml(path, findings)
        if cfg is None:
            continue
        listen = str(cfg.get("listen", ""))
        port = NODE_PORTS[f"node{i}"]
        if f":{port}" not in listen:
            findings.error(f"{path.name}: listen expected port {port}, got {listen!r}")
        if not listen.startswith("0.0.0.0:"):
            findings.warn(f"{path.name}: bridge pilot should listen on 0.0.0.0 (got {listen})")

        roster = cfg.get("roster") or {}
        if roster.get("path") != "roster.json":
            findings.error(f"{path.name}: [roster].path must be roster.json for compose mount")
        if roster.get("allow_unverified_roster") is not False:
            findings.error(f"{path.name}: allow_unverified_roster must be false")
        if not roster.get("authority_pubkeys"):
            findings.error(f"{path.name}: authority_pubkeys empty")

        cover = cfg.get("cover") or {}
        if not cover.get("enabled") or not cover.get("require"):
            findings.error(f"{path.name}: [cover] enabled+require must be true")

        gossip = cfg.get("health_gossip") or {}
        if not gossip.get("enabled"):
            findings.error(f"{path.name}: [health_gossip] enabled must be true")

        link = cfg.get("link") or {}
        if str(link.get("handshake", "")).lower() != "auto":
            findings.error(f"{path.name}: [link].handshake must be auto")

        text = path.read_text(encoding="utf-8")
        if "guard_mitigation" not in text:
            findings.warn(f"{path.name}: missing guard_mitigation documentation comment")
        if not any(p in text for p in ("adaptive_v3", "adaptive_v2", "adaptive_first")):
            findings.warn(f"{path.name}: guard_mitigation comment should mention adaptive_v3")

        peers = cfg.get("peers") or []
        for peer in peers:
            addr = str(peer.get("addr", ""))
            host = addr.split(":")[0]
            if host not in NODE_PORTS and host != f"node{i}":
                # peers should be docker DNS names node0..node3
                if not re.match(r"^node[0-3]$", host):
                    findings.error(f"{path.name}: peer addr host {host!r} not docker DNS nodeN")

    client_path = PILOT_CFG / "client.toml"
    if client_path.is_file():
        cfg = load_toml(client_path, findings)
        if cfg is not None:
            if not str(cfg.get("first_hop_addr", "")).startswith("node0:"):
                findings.error("client.toml: first_hop_addr should target node0:<port>")
            roster = cfg.get("roster") or {}
            if roster.get("path") != "roster.json":
                findings.error("client.toml: [roster].path must be roster.json")
            hops = cfg.get("hops") or []
            if len(hops) != 4:
                findings.warn(f"client.toml: expected 4 explicit [[hops]] for pilot (got {len(hops)})")
            text = client_path.read_text(encoding="utf-8")
            if "guard_mitigation" not in text:
                findings.warn("client.toml: missing guard_mitigation documentation")
            if "roster-path" not in text and "roster_path" not in text and "[path]" not in text:
                findings.warn("client.toml: should document roster-path / [path] wiring")
            if not any(p in text for p in ("adaptive_v3", "adaptive_v2", "adaptive_first")):
                findings.warn("client.toml: should document preset = adaptive_v3")

    findings.note("pilot TOML structural checks complete")


def check_templates(findings: Findings) -> None:
    for name in ("node.production.toml", "client.production.toml"):
        path = TEMPLATES / name
        if not path.is_file():
            findings.error(f"missing template: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        if "guard_mitigation" not in text:
            findings.warn(f"{name}: missing [guard_mitigation] docs")
        if not any(p in text for p in ("adaptive_v3", "adaptive_v2", "adaptive_first")):
            findings.warn(f"{name}: should document preset = \"adaptive_v3\"")
        if name == "client.production.toml" and "roster-path" not in text and "[path]" not in text:
            findings.warn(f"{name}: should document roster-path / [path]")
        if "allow_unverified_roster = false" not in text:
            findings.error(f"{name}: must set allow_unverified_roster = false")
        findings.note(f"template present: {name}")


def _is_windows() -> bool:
    return os.name == "nt"


def find_aegis_node() -> tuple[Path | None, list[str] | None]:
    """Return (path, wsl_prefix_or_None).

    On Windows, a Linux ELF under crates/target is runnable via `wsl`.
    """
    env = os.environ.get("AEGIS_NODE")
    if env and Path(env).is_file():
        return Path(env), None
    candidates = [
        REPO_ROOT / "crates" / "target" / "debug" / "aegis-node.exe",
        REPO_ROOT / "crates" / "target" / "release" / "aegis-node.exe",
        REPO_ROOT / "crates" / "target" / "debug" / "aegis-node",
        REPO_ROOT / "crates" / "target" / "release" / "aegis-node",
    ]
    which = shutil.which("aegis-node")
    if which:
        candidates.insert(0, Path(which))
    for c in candidates:
        if not c.is_file():
            continue
        if _is_windows() and c.suffix.lower() != ".exe":
            wsl = shutil.which("wsl")
            if not wsl:
                continue
            # /mnt/c/... path for WSL
            win = str(c.resolve())
            if len(win) >= 2 and win[1] == ":":
                drive = win[0].lower()
                rest = win[2:].replace("\\", "/")
                linux_path = f"/mnt/{drive}{rest}"
            else:
                linux_path = win.replace("\\", "/")
            return c, [wsl, "-e", linux_path]
        return c, None
    return None, None


def run_aegis_validate(findings: Findings) -> dict:
    result: dict = {"binary": None, "nodes": {}, "skipped": False, "via_wsl": False}
    binary, wsl_cmd = find_aegis_node()
    if binary is None:
        findings.warn(
            "aegis-node binary not found — skipped validate "
            "(build: cargo build -p aegis-node, or set AEGIS_NODE=)"
        )
        result["skipped"] = True
        return result
    result["binary"] = str(binary)
    result["via_wsl"] = wsl_cmd is not None
    findings.note(
        f"using aegis-node: {binary}"
        + (" (via WSL)" if wsl_cmd is not None else "")
    )

    for i in range(4):
        cfg = PILOT_CFG / f"node{i}.toml"
        if not cfg.is_file():
            continue
        if wsl_cmd is not None:
            win_cfg = str(PILOT_CFG.resolve())
            drive = win_cfg[0].lower()
            rest = win_cfg[2:].replace("\\", "/")
            linux_cwd = f"/mnt/{drive}{rest}"
            linux_bin = wsl_cmd[-1]
            shell = (
                f"cd '{linux_cwd}' && '{linux_bin}' validate --config '{cfg.name}'"
            )
            proc = subprocess.run(
                ["wsl", "-e", "bash", "-lc", shell],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        else:
            proc = subprocess.run(
                [str(binary), "validate", "--config", str(cfg.name)],
                cwd=str(PILOT_CFG),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        out = (proc.stdout or "") + (proc.stderr or "")
        # Extract ERROR field names; tolerate UTF-8 emdash mojibake on Windows consoles.
        fields = set()
        for line in out.splitlines():
            if "[ERROR]" not in line:
                continue
            after = line.split("[ERROR]", 1)[1].strip()
            # Field is text before the first dash-like separator (—, –, -, or mojibake).
            field = re.split(r"\s+(?:[—–\-]|â€”|\ufeff)\s+", after, maxsplit=1)[0].strip()
            if field:
                fields.add(field)
        # Also accept substring presence (robust if separator parsing fails).
        for expected in EXPECTED_PILOT_LAB_ERRORS:
            if expected in out:
                fields.add(expected)

        unexpected = {
            f
            for f in fields
            if f not in EXPECTED_PILOT_LAB_ERRORS and f != "roster.path"
        }
        missing_expected = EXPECTED_PILOT_LAB_ERRORS - fields
        entry = {
            "exit": proc.returncode,
            "error_fields": sorted(fields),
            "stdout_tail": out.strip().splitlines()[-12:],
        }
        result["nodes"][f"node{i}"] = entry
        if "roster.path" in fields:
            findings.warn(
                f"node{i}: roster.path failed to load — run validate with cwd "
                f"= deploy/compose/pilot_configs (compose mount uses relative path)"
            )
        if unexpected:
            findings.error(
                f"node{i} validate unexpected errors: {sorted(unexpected)} "
                "(pilot should only fail on lab KEM flags when roster resolves)"
            )
        elif missing_expected and proc.returncode == 0:
            findings.warn(
                f"node{i} validate passed unexpectedly - pilot should use lab KEM flags"
            )
        elif missing_expected:
            findings.warn(
                f"node{i} validate missing expected lab errors {sorted(missing_expected)}; "
                f"got {sorted(fields)}"
            )
        else:
            findings.note(
                f"node{i}: aegis-node validate FAIL as expected "
                f"(lab KEM only: {sorted(EXPECTED_PILOT_LAB_ERRORS & fields)})"
            )
    return result


def write_evidence(findings: Findings, validate_meta: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "docker_claimed_running": False,
        "honest_note": (
            "Offline pack validation only. Containers were not started by this script."
        ),
        "ok": findings.ok,
        "errors": findings.errors,
        "warnings": findings.warnings,
        "info": findings.info,
        "aegis_node_validate": validate_meta,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    findings.note(f"evidence written: {path.relative_to(REPO_ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=EVIDENCE_DIR / "offline_validate.json",
        help="Write JSON evidence path",
    )
    parser.add_argument(
        "--skip-aegis-validate",
        action="store_true",
        help="Skip aegis-node validate even if binary present",
    )
    args = parser.parse_args()

    findings = Findings()
    print("== AEGIS compose offline validate ==")
    print("HONEST: this does not start containers.\n")

    data = load_compose(findings)
    if data is not None:
        lint_compose(data, findings)
    check_pilot_tomls(findings)
    check_templates(findings)

    validate_meta: dict = {"skipped": True}
    if not args.skip_aegis_validate:
        validate_meta = run_aegis_validate(findings)

    write_evidence(findings, validate_meta, args.evidence.resolve())

    for w in findings.warnings:
        print(f"  WARN  {w}")
    for e in findings.errors:
        print(f"  ERROR {e}")
    for n in findings.info:
        print(f"  OK    {n}")

    print()
    if findings.ok:
        print("Offline pack validation PASSED (structure only; Docker not required).")
        return 0
    print("Offline pack validation FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
