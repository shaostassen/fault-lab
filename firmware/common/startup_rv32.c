/* Minimal RV32I startup -- the RISC-V counterpart to startup_cm3.c.
 *
 * Same rule as the Cortex-M version: no libc, no init_array, nothing that adds
 * instructions to the traced prefix, because every instruction before main()
 * is campaign surface you have to either fault or explicitly exclude.
 *
 * THE ONE REAL DIFFERENCE FROM CORTEX-M, and it is the reason this file has
 * asm in it at all: Cortex-M loads SP from the first word of the vector table
 * as part of reset, in hardware. RISC-V does not -- the core begins executing
 * at the reset address with every register, SP included, undefined. So SP has
 * to be established in asm before any C runs, or the first function prologue
 * writes through a garbage stack pointer.
 *
 * Deliberately NOT set up here: mtvec (the trap vector CSR). Under Unicorn an
 * invalid access raises a UcError that the backend catches and classifies as
 * CPUFAULT -> CRASH, which is the outcome we want and is how the Cortex-M
 * build effectively behaves too -- its HardFault_Handler exists for QEMU and
 * silicon fidelity, not because Unicorn vectors to it. Adding a CSR write here
 * would put an instruction in every trace that buys nothing under the backend
 * that actually runs the campaigns. Revisit when the QEMU backend lands, where
 * traps really do vector.
 */
#include <stdint.h>
#include "oracle.h"

extern uint32_t _etext, _sdata, _edata, _sbss, _ebss, _stack_top;
extern int main(void);

void Reset_Handler(void);

__attribute__((naked, section(".vectors"), used))
void _start(void)
{
    __asm__ volatile(
        "la sp, _stack_top\n"
        "j  Reset_Handler\n");
}

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
