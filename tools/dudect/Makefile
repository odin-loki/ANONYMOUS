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
#   DUDECT_MEASUREMENTS=5000 make lab   # short statistical attempt
#
# See docs/ops/constant_time_ci.md

CC ?= gcc
CRATE_ROOT := ../../crates
FFI_MANIFEST := $(CRATE_ROOT)/aegis-crypto-dudect-ffi/Cargo.toml
TARGET_DIR := $(CRATE_ROOT)/target/dudect-ffi
STATICLIB := $(TARGET_DIR)/release/libaegis_crypto_dudect_ffi.a

DUDECT_DIR ?= $(CURDIR)/../dudect-upstream
DUDECT_REPO := https://github.com/oreparaz/dudect.git
DUDECT_MARKER := $(DUDECT_DIR)/src/dudect.h
DUDECT_INC := -I$(DUDECT_DIR)/src
DUDECT_MEASUREMENTS ?= 100000

.PHONY: all staticlib ffi-smoke clean harnesses lab dudect-upstream dudect-short

all: ffi-smoke

staticlib:
	cd $(CRATE_ROOT) && \
		CARGO_TARGET_DIR=target/dudect-ffi \
		cargo build --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --release

ffi-smoke: staticlib harnesses
	@echo "--- FFI smoke (no dudect statistical test) ---"
	./harness_replay_contains_stub
	./harness_verify_mac_stub

# Clone oreparaz/dudect when missing (External operator convenience).
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
		-DAEGIS_DUDECT_MEASUREMENTS=$(DUDECT_MEASUREMENTS) \
		harness_replay_contains.c $(STATICLIB) \
		-o harness_replay_contains \
		-I. $(DUDECT_INC) -pthread -ldl -lm

harness_verify_mac: harness_verify_mac.c aegis_dudect.h $(STATICLIB) $(DUDECT_MARKER)
	$(CC) -O2 -Wall -Wextra -std=c11 -DDUDECT_AVAILABLE \
		-DAEGIS_DUDECT_MEASUREMENTS=$(DUDECT_MEASUREMENTS) \
		harness_verify_mac.c $(STATICLIB) \
		-o harness_verify_mac \
		-I. $(DUDECT_INC) -pthread -ldl -lm

harnesses-full: staticlib dudect-upstream harness_replay_contains harness_verify_mac

# Best-effort lab: FFI smoke + optional short dudect stats (not isolated CPU proof).
lab: ffi-smoke harnesses-full
	@echo "--- dudect lab (measurements=$(DUDECT_MEASUREMENTS); WSL2 not isolated) ---"
	@command -v timeout >/dev/null 2>&1 && TO=timeout || TO=; \
	$$TO 180 ./harness_replay_contains || true; \
	$$TO 180 ./harness_verify_mac || true

dudect-short:
	$(MAKE) lab DUDECT_MEASUREMENTS=5000

clean:
	rm -f harness_replay_contains harness_verify_mac \
		harness_replay_contains_stub harness_verify_mac_stub
	cd $(CRATE_ROOT) && cargo clean --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --target-dir target/dudect-ffi 2>/dev/null || true

clean-all: clean
	rm -rf "$(DUDECT_DIR)"
