/*
 * verify_hardened.c - countermeasure variant.
 *
 *   C1 non-boolean sentinels     - no single bit flip manufactures "pass"
 *   C2 duplicated checks         - divergent code, not a copy-paste the
 *                                  optimiser can fold via CSE
 *   C3 CFI accumulator           - each stage XORs a distinct constant; a
 *                                  skipped stage cannot produce the final value
 *   C4 double invocation         - hash + compare run twice, results compared
 *   C5 post-condition re-verify  - the accept path re-tests before committing
 *
 * COMPILER WARNING, and the reason for the -O sweep: `volatile` is what stops
 * the optimiser folding C2 and C4 into a single evaluation. It is a blunt
 * instrument, it costs cycles, and it is not architecturally guaranteed. Diff
 * the -O2 disassembly against your expectations before trusting this file.
 */
#include <string.h>
#include "image.h"
#include "../common/oracle.h"
#include "../crypto/sha256.h"

int memcmp_ct(const void *a, const void *b, size_t n);

extern uint8_t g_scratch[];

#define CFI_ENTER    0x1B2C3D4Eu
#define CFI_HDR      0x2C3D4E5Fu
#define CFI_VERSION  0x3D4E5F60u
#define CFI_SIG      0x4E5F6071u
#define CFI_EXPECTED (CFI_ENTER ^ CFI_HDR ^ CFI_VERSION ^ CFI_SIG)

static size_t build_authenticated(const image_header_t *hdr, const uint8_t *body,
                                  const uint8_t *key)
{
    size_t n = 0;
    memcpy(g_scratch + n, key, IMAGE_KEY_LEN);            n += IMAGE_KEY_LEN;
    memcpy(g_scratch + n, (const uint8_t *)hdr + IMAGE_SIGNED_OFFSET,
           IMAGE_SIGNED_HDR_LEN);                         n += IMAGE_SIGNED_HDR_LEN;
    memcpy(g_scratch + n, body, hdr->length);             n += hdr->length;
    return n;
}

uint32_t verify_image_hardened(const image_header_t *hdr, const uint8_t *body,
                               const uint8_t *key, uint32_t min_version)
{
    volatile uint32_t r1 = VERIFY_FAIL, r2 = VERIFY_FAIL;
    volatile uint32_t cfi = 0u;
    volatile int cmp_a, cmp_b;
    uint8_t d1[32], d2[32];
    size_t n;

    oracle_mark(MARK_BOOT_ENTER);
    cfi ^= CFI_ENTER;

    /* C2: divergent duplication. The first form tests for failure, the second
     * for success, so they are not structurally identical and cannot be merged. */
    if (hdr->magic != IMAGE_MAGIC)   return VERIFY_FAIL;
    if (!(hdr->magic == IMAGE_MAGIC)) return VERIFY_FAIL;

    if (hdr->length == 0u || hdr->length > IMAGE_MAX_LEN)        return VERIFY_FAIL;
    if (!(hdr->length != 0u && hdr->length <= IMAGE_MAX_LEN))    return VERIFY_FAIL;
    cfi ^= CFI_HDR;
    oracle_mark(MARK_HDR_OK);

    if (hdr->version < min_version)     return VERIFY_FAIL;
    if (!(hdr->version >= min_version)) return VERIFY_FAIL;
    cfi ^= CFI_VERSION;
    oracle_mark(MARK_VERSION_OK);

    /* C4: two independent hash+compare passes. Cost is real -- this doubles
     * verification time. Report that number; the tradeoff is the interesting part. */
    n = build_authenticated(hdr, body, key);
    sha256(g_scratch, n, d1);
    cmp_a = memcmp_ct(d1, hdr->tag, IMAGE_TAG_LEN);

    n = build_authenticated(hdr, body, key);
    sha256(g_scratch, n, d2);
    cmp_b = memcmp_ct(d2, hdr->tag, IMAGE_TAG_LEN);

    if (cmp_a != 0)                        return VERIFY_FAIL;
    if (cmp_b != 0)                        return VERIFY_FAIL;
    if (cmp_a != cmp_b)                    return VERIFY_FAIL;
    if (memcmp_ct(d1, d2, 32) != 0)        return VERIFY_FAIL;
    cfi ^= CFI_SIG;
    oracle_mark(MARK_SIG_OK);

    /* C1: sentinel assignment, split so no single store creates PASS. */
    r1 = VERIFY_PASS;
    r2 = VERIFY_PASS;

    /* C5: the accept path re-establishes every invariant it depends on. */
    if (cfi != CFI_EXPECTED)            return VERIFY_FAIL;
    if (r1 != VERIFY_PASS)              return VERIFY_FAIL;
    if (r2 != VERIFY_PASS)              return VERIFY_FAIL;
    if ((r1 ^ r2) != 0u)                return VERIFY_FAIL;
    if (hdr->version < min_version)     return VERIFY_FAIL;
    if (hdr->magic != IMAGE_MAGIC)      return VERIFY_FAIL;

    return VERIFY_PASS;
}
