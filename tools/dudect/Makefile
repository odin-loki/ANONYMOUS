# AEGIS dudect lab boundary (Linux-only build)
#
# Builds Rust FFI staticlib + optional oreparaz/dudect C harnesses.
# Default `cargo test --workspace` on Windows stays green (FFI crate is safe to compile).
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt install build-essential clang git
#   rustup default stable
#
# Quick lab (auto-clones dudect if missing):
#   make lab
#   DUDECT_MEASUREMENTS=5000 make lab          # short statistical attempt
#   make lab-deepen                            # longer bounded deepen (timeout + max chunks)
#
# Tunables:
#   DUDECT_MEASUREMENTS   chunk size per dudect_main (default 100000)
#   DUDECT_MAX_CHUNKS     stop after N chunks; 0 = until leakage (default 0)
#   DUDECT_TIMEOUT_SEC    per-harness wall clock when using `lab` (default 180)
#   DUDECT_TIMEOUT_REPLAY / DUDECT_TIMEOUT_MAC  optional per-harness overrides
#
# See docs/ops/constant_time_ci.md

CC ?= gcc
CRATE_ROOT := ../../crates
TARGET_DIR := $(CRATE_ROOT)/target/dudect-ffi
STATICLIB := $(TARGET_DIR)/release/libaegis_crypto_dudect_ffi.a

DUDECT_DIR ?= $(CURDIR)/../dudect-upstream
DUDECT_REPO := https://github.com/oreparaz/dudect.git
DUDECT_MARKER := $(DUDECT_DIR)/src/dudect.h
DUDECT_INC := -I$(DUDECT_DIR)/src

DUDECT_MEASUREMENTS ?= 100000
DUDECT_MAX_CHUNKS ?= 0
# Optional per-harness overrides (deepen: large replay chunks, smaller MAC chunks).
DUDECT_MEASUREMENTS_REPLAY ?= $(DUDECT_MEASUREMENTS)
DUDECT_MEASUREMENTS_MAC ?= $(DUDECT_MEASUREMENTS)
DUDECT_MAX_CHUNKS_REPLAY ?= $(DUDECT_MAX_CHUNKS)
DUDECT_MAX_CHUNKS_MAC ?= $(DUDECT_MAX_CHUNKS)
DUDECT_TIMEOUT_SEC ?= 180
DUDECT_TIMEOUT_REPLAY ?= $(DUDECT_TIMEOUT_SEC)
DUDECT_TIMEOUT_MAC ?= $(DUDECT_TIMEOUT_SEC)

.PHONY: all staticlib ffi-smoke clean harnesses lab lab-deepen dudect-upstream dudect-short \
	run-replay run-mac

all: ffi-smoke

staticlib:
	cd $(CRATE_ROOT) && \
		CARGO_TARGET_DIR=target/dudect-ffi \
		cargo build --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --release

ffi-smoke: staticlib harnesses
	@echo "--- FFI smoke (no dudect statistical test) ---"
	./harness_replay_contains_stub
	./harness_verify_mac_stub

dudect-upstream: $(DUDECT_MARKER)

$(DUDECT_MARKER):
	@if [ ! -f "$(DUDECT_MARKER)" ]; then \
		echo "Cloning oreparaz/dudect into $(DUDECT_DIR)..."; \
		git clone --depth 1 "$(DUDECT_REPO)" "$(DUDECT_DIR)"; \
	else \
		echo "dudect already present at $(DUDECT_DIR)"; \
	fi

harnesses: staticlib harness_replay_contains_stub harness_verify_mac_stub

harness_replay_contains_stub: harness_replay_contains.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 harness_replay_contains.c $(STATICLIB) \
		-o harness_replay_contains_stub \
		-I. -pthread -ldl -lm

harness_verify_mac_stub: harness_verify_mac.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 harness_verify_mac.c $(STATICLIB) \
		-o harness_verify_mac_stub \
		-I. -pthread -ldl -lm

harness_replay_contains: harness_replay_contains.c aegis_dudect.h $(STATICLIB) $(DUDECT_MARKER)
	$(CC) -O2 -Wall -Wextra -std=c11 -DDUDECT_AVAILABLE \
		-DAEGIS_DUDECT_MEASUREMENTS=$(DUDECT_MEASUREMENTS_REPLAY) \
		-DAEGIS_DUDECT_MAX_CHUNKS=$(DUDECT_MAX_CHUNKS_REPLAY) \
		harness_replay_contains.c $(STATICLIB) \
		-o harness_replay_contains \
		-I. $(DUDECT_INC) -pthread -ldl -lm

harness_verify_mac: harness_verify_mac.c aegis_dudect.h $(STATICLIB) $(DUDECT_MARKER)
	$(CC) -O2 -Wall -Wextra -std=c11 -DDUDECT_AVAILABLE \
		-DAEGIS_DUDECT_MEASUREMENTS=$(DUDECT_MEASUREMENTS_MAC) \
		-DAEGIS_DUDECT_MAX_CHUNKS=$(DUDECT_MAX_CHUNKS_MAC) \
		harness_verify_mac.c $(STATICLIB) \
		-o harness_verify_mac \
		-I. $(DUDECT_INC) -pthread -ldl -lm

harnesses-full: staticlib dudect-upstream harness_replay_contains harness_verify_mac

# Exit codes: 0=LEAKAGE_FOUND, 2=BUDGET_EXHAUSTED, 124=timeout; always continue lab.
run-replay: harness_replay_contains
	@echo "--- run harness_replay_contains (timeout=$(DUDECT_TIMEOUT_REPLAY)s meas=$(DUDECT_MEASUREMENTS_REPLAY) max_chunks=$(DUDECT_MAX_CHUNKS_REPLAY)) ---"
	@set +e; \
	RUN=./harness_replay_contains; \
	command -v stdbuf >/dev/null 2>&1 && RUN="stdbuf -oL -eL ./harness_replay_contains"; \
	if command -v timeout >/dev/null 2>&1; then \
		timeout --signal=TERM --kill-after=10 $(DUDECT_TIMEOUT_REPLAY) $$RUN; \
		ec=$$?; \
	else \
		$$RUN; \
		ec=$$?; \
	fi; \
	case $$ec in \
		0) echo "harness_exit: harness_replay_contains=0 evidence_hint=LEAKAGE_FOUND" ;; \
		2) echo "harness_exit: harness_replay_contains=2 evidence_hint=BUDGET_EXHAUSTED" ;; \
		124) echo "harness_exit: harness_replay_contains=124 evidence_hint=TIMEOUT"; \
		     echo "AEGIS_DUDECT_SUMMARY primitive=ReplayCache::contains_ct evidence_code=TIMEOUT isolation=none platform=linux_or_wsl external_bar=isolated_ge_1e5_per_primitive" ;; \
		*) echo "harness_exit: harness_replay_contains=$$ec evidence_hint=ERROR" ;; \
	esac; \
	exit 0

run-mac: harness_verify_mac
	@echo "--- run harness_verify_mac (timeout=$(DUDECT_TIMEOUT_MAC)s meas=$(DUDECT_MEASUREMENTS_MAC) max_chunks=$(DUDECT_MAX_CHUNKS_MAC)) ---"
	@set +e; \
	RUN=./harness_verify_mac; \
	command -v stdbuf >/dev/null 2>&1 && RUN="stdbuf -oL -eL ./harness_verify_mac"; \
	if command -v timeout >/dev/null 2>&1; then \
		timeout --signal=TERM --kill-after=10 $(DUDECT_TIMEOUT_MAC) $$RUN; \
		ec=$$?; \
	else \
		$$RUN; \
		ec=$$?; \
	fi; \
	case $$ec in \
		0) echo "harness_exit: harness_verify_mac=0 evidence_hint=LEAKAGE_FOUND" ;; \
		2) echo "harness_exit: harness_verify_mac=2 evidence_hint=BUDGET_EXHAUSTED" ;; \
		124) echo "harness_exit: harness_verify_mac=124 evidence_hint=TIMEOUT"; \
		     echo "AEGIS_DUDECT_SUMMARY primitive=Sphinx::verify_mac evidence_code=TIMEOUT isolation=none platform=linux_or_wsl external_bar=isolated_ge_1e5_per_primitive" ;; \
		*) echo "harness_exit: harness_verify_mac=$$ec evidence_hint=ERROR" ;; \
	esac; \
	exit 0

lab: ffi-smoke harnesses-full run-replay run-mac
	@echo "--- dudect lab complete (WSL2/Linux best-effort; not isolated External bar) ---"

# ~12 min deepen: long replay budget + smaller MAC chunks (flush-friendly under timeout).
lab-deepen:
	$(MAKE) lab \
		DUDECT_MEASUREMENTS_REPLAY=100000 \
		DUDECT_MAX_CHUNKS_REPLAY=1200 \
		DUDECT_MEASUREMENTS_MAC=10000 \
		DUDECT_MAX_CHUNKS_MAC=200 \
		DUDECT_TIMEOUT_REPLAY=600 \
		DUDECT_TIMEOUT_MAC=180

dudect-short:
	$(MAKE) lab DUDECT_MEASUREMENTS=5000 DUDECT_MAX_CHUNKS=20 \
		DUDECT_TIMEOUT_REPLAY=60 DUDECT_TIMEOUT_MAC=60

clean:
	rm -f harness_replay_contains harness_verify_mac \
		harness_replay_contains_stub harness_verify_mac_stub
	cd $(CRATE_ROOT) && cargo clean --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --target-dir target/dudect-ffi 2>/dev/null || true

clean-all: clean
	rm -rf "$(DUDECT_DIR)"
