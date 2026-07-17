/*
 * Skeleton dudect harness for Sphinx verify_mac (class-0 bad MAC vs class-1 valid).
 *
 * See harness_replay_contains.c and docs/ops/constant_time_ci.md.
 */

#include "aegis_dudect.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DUDECT_AVAILABLE
#include "dudect.h"
#endif

static void prepare_inputs(void) {
  aegis_dudect_mac_lab_init();
}

#ifndef DUDECT_AVAILABLE
int main(void) {
  prepare_inputs();
  fprintf(stderr,
          "dudect sources not linked (set DUDECT_DIR and rebuild).\n"
          "FFI smoke: bad=%u good=%u packet_len=%u\n",
          (unsigned)aegis_ct_verify_mac(0), (unsigned)aegis_ct_verify_mac(1),
          (unsigned)AEGIS_SPHINX_PACKET_LEN);
  return 0;
}
#else
static uint8_t do_one(uint8_t bit) {
  return aegis_ct_verify_mac(bit);
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

  printf("AEGIS dudect: Sphinx verify_mac (packet_len=%u)\n",
         (unsigned)AEGIS_SPHINX_PACKET_LEN);
  dudect_test(&state);
  dudect_free();
  return 0;
}
#endif
