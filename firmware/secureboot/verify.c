/*
 * verify.c - BASELINE (deliberately unhardened) image verifier.
 *
 * Not strawmanned: the crypto is correct, the bounds checks are present, the
 * version check is present. This is the code that passes review everywhere
 * that has not thought about glitching.
 *
 * Known-by-construction fault targets, which the campaign must rediscover
 * independently -- that rediscovery is the harness's correctness test:
 *   1. each `return 0` is a single skippable instruction
 *   2. the final branch on the tag comparison is one flag-dependent jump
 *   3. the boolean return convention means a single bit set in r0 = accept
 */
#include <string.h>
#include "image.h"
#include "../common/oracle.h"
#include "../crypto/sha256.h"

extern uint8_t g_scratch[];

int verify_image(const image_header_t *hdr, const uint8_t *body,
                 const uint8_t *key, uint32_t min_version)
{
    uint8_t digest[32];
    size_t n = 0;

    oracle_mark(MARK_BOOT_ENTER);

    if (hdr->magic != IMAGE_MAGIC)                        return 0;
    if (hdr->length == 0u || hdr->length > IMAGE_MAX_LEN) return 0;
    oracle_mark(MARK_HDR_OK);

    if (hdr->version < min_version)                       return 0;
    oracle_mark(MARK_VERSION_OK);

    memcpy(g_scratch + n, key, IMAGE_KEY_LEN);            n += IMAGE_KEY_LEN;
    memcpy(g_scratch + n, (const uint8_t *)hdr + IMAGE_SIGNED_OFFSET,
           IMAGE_SIGNED_HDR_LEN);                         n += IMAGE_SIGNED_HDR_LEN;
    memcpy(g_scratch + n, body, hdr->length);             n += hdr->length;

    sha256(g_scratch, n, digest);

    if (memcmp(digest, hdr->tag, IMAGE_TAG_LEN) != 0)     return 0;  /* early-exit compare: soft target, by design */
    oracle_mark(MARK_SIG_OK);

    return 1;
}
