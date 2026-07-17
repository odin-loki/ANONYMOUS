# AEGIS dudect lab boundary (Linux-only build)
#
# Builds Rust FFI staticlib + optional oreparaz/dudect C harnesses.
# Default `cargo test --workspace` on Windows stays green (FFI crate is safe to compile).
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt install build-essential clang
#   rustup default stable
#
# Optional full dudect (External operator step):
#   git clone https://github.com/oreparaz/dudect.git ../dudect-upstream
#   make DUDECT_DIR=../dudect-upstream
#
# See docs/ops/constant_time_ci.md

CRATE_ROOT := ../../crates
FFI_MANIFEST := $(CRATE_ROOT)/aegis-crypto-dudect-ffi/Cargo.toml
TARGET_DIR := $(CRATE_ROOT)/target/dudect-ffi
STATICLIB := $(TARGET_DIR)/release/libaegis_crypto_dudect_ffi.a

.PHONY: all staticlib ffi-smoke clean harnesses

all: ffi-smoke

staticlib:
	cd $(CRATE_ROOT) && \
		CARGO_TARGET_DIR=target/dudect-ffi \
		cargo build --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --release

ffi-smoke: staticlib harnesses
	@echo "--- FFI smoke (no dudect statistical test) ---"
	./harness_replay_contains_stub
	./harness_verify_mac_stub

harnesses: staticlib harness_replay_contains_stub harness_verify_mac_stub

harness_replay_contains_stub: harness_replay_contains.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 harness_replay_contains.c $(STATICLIB) \
		-o harness_replay_contains_stub \
		-I. -pthread -ldl -lm

harness_verify_mac_stub: harness_verify_mac.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 harness_verify_mac.c $(STATICLIB) \
		-o harness_verify_mac_stub \
		-I. -pthread -ldl -lm

ifdef DUDECT_DIR
harnesses: harness_replay_contains harness_verify_mac

harness_replay_contains: harness_replay_contains.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 -DDUDECT_AVAILABLE \
		harness_replay_contains.c $(DUDECT_DIR)/dudect.c $(STATICLIB) \
		-o harness_replay_contains \
		-I. -I$(DUDECT_DIR) -pthread -ldl -lm

harness_verify_mac: harness_verify_mac.c aegis_dudect.h $(STATICLIB)
	$(CC) -O2 -Wall -Wextra -std=c11 -DDUDECT_AVAILABLE \
		harness_verify_mac.c $(DUDECT_DIR)/dudect.c $(STATICLIB) \
		-o harness_verify_mac \
		-I. -I$(DUDECT_DIR) -pthread -ldl -lm
endif

clean:
	rm -f harness_replay_contains harness_verify_mac \
		harness_replay_contains_stub harness_verify_mac_stub
	cd $(CRATE_ROOT) && cargo clean --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --target-dir target/dudect-ffi 2>/dev/null || true
