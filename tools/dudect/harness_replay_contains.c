/*
 * dudect harness for ReplayCache::contains_ct (class-0 miss vs class-1 hit).
 *
 * Requires built libaegis_crypto_dudect_ffi.a and oreparaz/dudect in DUDECT_DIR (see Makefile).
 * Run >=10^5 traces on an isolated Linux core; WSL2 is not sufficient — see docs/ops/constant_time_ci.md.
 */

#include "aegis_dudect.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DUDECT_AVAILABLE

int main(void) {
  if (aegis_dudect_replay_lab_init(AEGIS_DUDECT_REPLAY_CAPACITY) != 0) {
    fprintf(stderr, "aegis_dudect_replay_lab_init failed\n");
    return EXIT_FAILURE;
  }
  fprintf(stderr,
          "dudect sources not linked (run `make lab` with DUDECT_DIR set).\n"
          "FFI smoke: miss=%u hit=%u\n",
          (unsigned)aegis_ct_contains(0), (unsigned)aegis_ct_contains(1));
  return 0;
}

#else

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#define CHUNK_SIZE 1

#ifndef AEGIS_DUDECT_MEASUREMENTS
#define AEGIS_DUDECT_MEASUREMENTS 100000
#endif

uint8_t do_one_computation(uint8_t *data) {
  return aegis_ct_contains(data[0]);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();
    memset(input_data + i * c->chunk_size, 0, c->chunk_size);
    input_data[i * c->chunk_size] = classes[i];
  }
}

static int run_test(void) {
  dudect_config_t config = {
      .chunk_size = CHUNK_SIZE,
      .number_measurements = AEGIS_DUDECT_MEASUREMENTS,
  };
  dudect_ctx_t ctx;
  dudect_init(&ctx, &config);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}

int main(void) {
  if (aegis_dudect_replay_lab_init(AEGIS_DUDECT_REPLAY_CAPACITY) != 0) {
    fprintf(stderr, "aegis_dudect_replay_lab_init failed\n");
    return EXIT_FAILURE;
  }
  printf("AEGIS dudect: ReplayCache::contains_ct (capacity=%u, measurements=%d)\n",
         (unsigned)AEGIS_DUDECT_REPLAY_CAPACITY, AEGIS_DUDECT_MEASUREMENTS);
  return run_test();
}

#endif
