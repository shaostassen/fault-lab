/* RV32I linker script.
 *
 * DELIBERATELY THE SAME MEMORY MAP AS link_cm3.ld. Flash at 0x00000000, RAM at
 * 0x20000000, .oracle pinned at 0x20000000 and .noinit immediately after it.
 * Keeping the map byte-identical across the two architectures is what makes
 * the cross-architecture comparison mean something: the harness's memory
 * constants, the oracle protocol, and the test-vector injection all stay
 * unchanged, so a difference in campaign results is a difference in ISA and
 * codegen rather than in how the two targets were set up.
 *
 * ENTRY is _start, not Reset_Handler: RISC-V needs the asm SP setup in
 * startup_rv32.c to run first (see that file for why).
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(_start)

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
