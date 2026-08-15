/*
 * minilib.c - freestanding string primitives.
 *
 * These are deliberately OURS rather than newlib's, because memcmp is part of
 * the attack surface. The tag comparison in the verifier bottoms out here, and
 * a campaign that cannot fault the comparison loop is not testing the thing
 * that actually decides whether an image is accepted.
 *
 * Note the early exit in memcmp. That is what every real implementation does,
 * and it means the loop trip count depends on how many leading bytes match --
 * which is a timing side channel AND a much softer fault target than a
 * constant-time compare. The hardened build should be measured against a
 * constant-time variant; see memcmp_ct below.
 */
#include <stdint.h>
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    uint8_t *d = dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;   /* early exit: soft target */
        x++; y++;
    }
    return 0;
}

/* Constant-time compare. Accumulates all differences, no early exit, no
 * data-dependent branch. Returns 0 iff equal. */
int memcmp_ct(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    uint8_t acc = 0;
    while (n--) { acc |= (uint8_t)(*x++ ^ *y++); }
    return (int)acc;
}
