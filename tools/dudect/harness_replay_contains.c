/*
 * Skeleton dudect harness for ReplayCache::contains_ct (class-0 miss vs class-1 hit).
 *
 * Requires:
 *   - Built libaegis_crypto.a (--features dudect-ffi)
 *   - Clone https://github.com/oreparaz/dudect into DUDECT_DIR (see Makefile)
 *
 * This file does NOT prove constant-time behavior by itself. Run ≥10⁵ traces on an
 * isolated Linux core; WSL2 is not sufficient isolation — see docs/ops/constant_time_ci.md.
 */

#include "aegis_dudect.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DUDECT_AVAILABLE
#include "dudect.h"
#endif

static uint8_t class_bit = 0;

static void prepare_inputs(void) {
  if (aegis_dudect_replay_lab_init(AEGIS_DUDECT_REPLAY_CAPACITY) != 0) {
    fprintf(stderr, "aegis_dudect_replay_lab_init failed\n");
    exit(EXIT_FAILURE);
  }
}

#ifndef DUDECT_AVAILABLE
static uint8_t do_one(uint8_t bit) {
  class_bit = bit;
  return aegis_ct_contains(class_bit);
}

int main(void) {
  prepare_inputs();
  (void)do_one(0);
  (void)do_one(1);
  fprintf(stderr,
          "dudect sources not linked (set DUDECT_DIR and rebuild).\n"
          "FFI smoke: miss=%u hit=%u\n",
          (unsigned)aegis_ct_contains(0), (unsigned)aegis_ct_contains(1));
  return 0;
}
#else
static uint8_t do_one(uint8_t bit) {
  class_bit = bit;
  return aegis_ct_contains(class_bit);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  prepare_inputs();

  dudect_config_t config = {
      .number_measurements = 100000,
  };
  dudect_init(&config);

  dudect_state_t state = {
      .exec = do_one,
      .number_bits = 1,
      .number_classes = 2,
      .fixed_input = NULL,
      .fixed_input_length = 0,
  };

  printf("AEGIS dudect: ReplayCache::contains_ct (capacity=%u)\n",
         (unsigned)AEGIS_DUDECT_REPLAY_CAPACITY);
  dudect_test(&state);
  dudect_free();
  return 0;
}
#endif
