#ifndef AEGIS_DUDECT_H
#define AEGIS_DUDECT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rust staticlib exports (feature `dudect-ffi`). */
extern uint32_t AEGIS_SPHINX_PACKET_LEN;
extern uint32_t AEGIS_DUDECT_REPLAY_CAPACITY;

int32_t aegis_dudect_replay_lab_init(uint32_t capacity);
void aegis_dudect_mac_lab_init(void);

/* class_bit: 0 = miss / bad MAC, non-zero = hit / good MAC. Return is probe result only. */
uint8_t aegis_ct_contains(uint8_t class_bit);
uint8_t aegis_ct_verify_mac(uint8_t class_bit);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_DUDECT_H */
