/* Freestanding <string.h>.
 *
 * The firmware implements memcpy/memset/memcmp itself, in common/minilib.c,
 * and that is a deliberate security decision rather than a portability
 * accident: memcmp is an attack target in this threat model, so it has to be
 * traced code the campaign can fault, not an opaque libc symbol. Given that,
 * pulling in a C library purely for three prototypes was a dependency the
 * project never actually needed.
 *
 * Removing it also makes the build work with a bare cross-compiler that ships
 * no C library at all -- which is the normal case for a freshly packaged
 * toolchain (Ubuntu's gcc-riscv64-unknown-elf has no libc headers), and was
 * the immediate blocker on building the RV32 target.
 *
 * <stdint.h> and <stddef.h> need no equivalent: those are freestanding
 * headers that GCC provides itself, independent of any C library.
 *
 * Declarations must stay in sync with minilib.c. They are standard signatures,
 * so a mismatch would be a compile error, not a silent divergence.
 */
#ifndef FAULTLAB_STRING_H
#define FAULTLAB_STRING_H

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

#endif /* FAULTLAB_STRING_H */
