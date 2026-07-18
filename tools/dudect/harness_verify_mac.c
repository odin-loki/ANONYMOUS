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

#ifndef AEGIS_DUDECT_MAX_CHUNKS
#define AEGIS_DUDECT_MAX_CHUNKS 0
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

static void print_summary(const char *evidence_code, size_t chunks, size_t scheduled_traces,
                          dudect_state_t state) {
  printf("AEGIS_DUDECT_SUMMARY primitive=Sphinx::verify_mac "
         "chunk_size=%d max_chunks=%d chunks_ran=%zu scheduled_traces=%zu "
         "dudect_state=%s evidence_code=%s isolation=none "
         "platform=linux_or_wsl external_bar=isolated_ge_1e5_per_primitive\n",
         AEGIS_DUDECT_MEASUREMENTS, AEGIS_DUDECT_MAX_CHUNKS, chunks, scheduled_traces,
         state == DUDECT_LEAKAGE_FOUND ? "LEAKAGE_FOUND" : "NO_LEAKAGE_EVIDENCE_YET",
         evidence_code);
  fflush(stdout);
}

static int run_test(void) {
  dudect_config_t config = {
      .chunk_size = CHUNK_SIZE,
      .number_measurements = AEGIS_DUDECT_MEASUREMENTS,
  };
  dudect_ctx_t ctx;
  dudect_init(&ctx, &config);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  size_t chunks = 0;
  size_t scheduled = 0;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
    chunks++;
    scheduled += config.number_measurements;
    if (AEGIS_DUDECT_MAX_CHUNKS > 0 && chunks >= (size_t)AEGIS_DUDECT_MAX_CHUNKS) {
      print_summary("BUDGET_EXHAUSTED", chunks, scheduled, state);
      dudect_free(&ctx);
      return 2;
    }
  }
  print_summary(state == DUDECT_LEAKAGE_FOUND ? "LEAKAGE_FOUND" : "UNEXPECTED_STATE", chunks,
                scheduled, state);
  dudect_free(&ctx);
  return (int)state;
}

int main(void) {
  /* Line-buffer stdout so `tee`/timeout capture does not drop the last meas lines. */
  setvbuf(stdout, NULL, _IOLBF, 0);
  aegis_dudect_mac_lab_init();
  printf("AEGIS dudect: Sphinx verify_mac (packet_len=%u, measurements=%d, max_chunks=%d)\n",
         (unsigned)AEGIS_SPHINX_PACKET_LEN, AEGIS_DUDECT_MEASUREMENTS, AEGIS_DUDECT_MAX_CHUNKS);
  fflush(stdout);
  return run_test();
}

#endif
