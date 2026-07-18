#!/usr/bin/env bash
# Probe for ProVerif and run AEGIS Sphinx symbolic models (Wave S3).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPORT="${ROOT}/last_run.txt"

find_proverif() {
  if [[ -n "${PROVERIF:-}" && -x "${PROVERIF}" ]]; then
    echo "${PROVERIF}"
    return 0
  fi
  if command -v proverif >/dev/null 2>&1; then
    command -v proverif
    return 0
  fi
  for cand in \
    "${HOME}/tools/proverif_linux_amd64_static" \
    "${HOME}/tools/proverif2.05/proverif" \
    "${ROOT}/bin/proverif"; do
    if [[ -x "${cand}" ]]; then
      echo "${cand}"
      return 0
    fi
  done
  return 1
}

exec > >(tee "${REPORT}") 2>&1

echo "=== AEGIS Sphinx ProVerif probe ==="
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host: $(uname -a 2>/dev/null || echo unknown)"
echo

if ! PV="$(find_proverif)"; then
  echo "STATUS: MISSING"
  echo "proverif not found on PATH or in ~/tools/"
  echo
  echo "Install (pick one):"
  echo "  1) opam install proverif"
  echo "  2) https://bblanche.gitlabpages.inria.fr/proverif/ (tarball + ./build)"
  echo "  3) Static amd64 binary at ~/tools/proverif_linux_amd64_static"
  echo
  echo "Expected lemmas (when installed):"
  echo "  L1 secrecy  — not attacker(secret_payload)                 [sphinx_hop.pv]"
  echo "  L2 integrity — ExitDeliver(sid,payload) ==> ClientBuilt   [sphinx_hop.pv]"
  echo "  L3 replay   — inj-event(HopAccept(t)) ==> ClientBuilt(t)  [sphinx_replay.pv]"
  echo
  echo "See README.md and docs/ops/sphinx_symbolic_model.md"
  exit 2
fi

echo "STATUS: FOUND"
echo "binary: ${PV}"
"${PV}" -help 2>&1 | head -1 || true
echo

rc=0
for model in sphinx_hop.pv sphinx_replay.pv; do
  echo "=== Running ${model} ==="
  set +e
  "${PV}" "${ROOT}/${model}"
  mrc=$?
  set -e
  echo "exit_code_${model}: ${mrc}"
  echo
  if [[ "${mrc}" -ne 0 ]]; then
    rc="${mrc}"
  fi
done

echo "=== Summary grep ==="
grep -E '^RESULT |^Query ' "${REPORT}" || true
echo
echo "overall_exit: ${rc}"
exit "${rc}"
