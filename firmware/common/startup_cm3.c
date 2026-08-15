/* Minimal Cortex-M3 startup. No libc, no init_array, nothing that adds
 * instructions to the traced prefix -- every instruction before main() is
 * campaign surface you have to either fault or explicitly exclude. */
#include <stdint.h>
#include "oracle.h"

extern uint32_t _etext, _sdata, _edata, _sbss, _ebss, _stack_top;
extern int main(void);

void Reset_Handler(void)
{
    uint32_t *src = &_etext, *dst = &_sdata;
    while (dst < &_edata) { *dst++ = *src++; }
    for (dst = &_sbss; dst < &_ebss; ) { *dst++ = 0u; }

    /* .oracle is NOLOAD and outside .bss, so it survives the clear above.
     * Re-stamp the magic anyway: it is the harness's validity check, and a
     * run where it is absent means the emulator never reached this point. */
    g_oracle.magic = ORACLE_STATE_MAGIC;

    (void)main();
    oracle_halt(FW_VERDICT_ASSERT_FAIL);
}

void Default_Handler(void) { oracle_halt(FW_VERDICT_ASSERT_FAIL); }

/* HardFault is a legitimate and common fault outcome -- route it to the oracle
 * so it is classified as CRASH rather than silently spinning to budget and
 * being mislabelled HANG. Those two classes must not be confused. */
void HardFault_Handler(void) { oracle_halt(FW_VERDICT_ASSERT_FAIL); }

__attribute__((section(".vectors"), used))
void (* const g_vectors[])(void) = {
    (void (*)(void))&_stack_top,
    Reset_Handler,
    Default_Handler,   /* NMI */
    HardFault_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
};
