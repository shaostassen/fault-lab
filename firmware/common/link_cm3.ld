/* Cortex-M3 linker script.
 *
 * Two regions are PINNED at fixed addresses so the harness needs no ELF symbol
 * lookup in the hot path:
 *   0x20000000  .oracle  (32 B)   - post-mortem state, read after every run
 *   0x20000020  .noinit           - test vector inputs, written before reset
 * Startup must not clear either. That is what lets ONE binary serve every test
 * vector: signed, unsigned, rolled-back, fault-asserted. No rebuild per vector.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(Reset_Handler)

SECTIONS
{
  .vectors : { KEEP(*(.vectors)) } > FLASH
  .text : {
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .oracle (NOLOAD) : ALIGN(4) {
    _oracle_start = .;
    KEEP(*(.oracle))
    . = _oracle_start + 32;
  } > RAM

  .noinit (NOLOAD) : ALIGN(4) {
    _noinit_start = .;
    KEEP(*(.noinit))
    . = ALIGN(4);
    _noinit_end = .;
  } > RAM

  .data : AT (_etext) {
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  .bss (NOLOAD) : {
    _sbss = .;
    *(.bss*) *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
