#include "oracle.h"

/* Pinned to the base of RAM by the linker script. Must be the only thing in
 * .oracle, and must not be zeroed by startup after initialisation. */
volatile oracle_state_t g_oracle __attribute__((section(".oracle"), used)) = {
    .magic = ORACLE_STATE_MAGIC,
};
