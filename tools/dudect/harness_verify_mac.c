/*
 * dudect harness for Sphinx verify_mac (class-0 bad MAC vs class-1 valid).
 *
 * See harness_replay_contains.c and docs/ops/constant_time_ci.md.
 */

#include "aegis_dudect.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DUDECT_AVAILABLE

int main(void) {
  aegis_dudect_mac_lab_init();
  fprintf(stderr,
          "dudect sources not linked (run `make lab` with DUDECT_DIR set).\n"
          "FFI smoke: bad=%u good=%u packet_len=%u\n",
          (unsigned)aegis_ct_verify_mac(0), (unsigned)aegis_ct_verify_mac(1),
          (unsigned)AEGIS_SPHINX_PACKET_LEN);
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
  return aegis_ct_verify_mac(data[0]);
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
  aegis_dudect_mac_lab_init();
  printf("AEGIS dudect: Sphinx verify_mac (packet_len=%u, measurements=%d)\n",
         (unsigned)AEGIS_SPHINX_PACKET_LEN, AEGIS_DUDECT_MEASUREMENTS);
  return run_test();
}

#endif
