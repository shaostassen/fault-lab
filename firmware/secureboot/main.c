/*
 * main.c - secure boot target.
 *
 * The image under test, the key, and the rollback floor are placed at FIXED
 * addresses in RAM by the linker script. The harness writes them before reset,
 * which is how one binary serves every test vector. No rebuild per vector.
 *
 * CALL-SITE HARDENING (USE_HARDENED): the first campaign found that every
 * residual bypass in the hardened build landed HERE, not in the verifier.
 * Hardening a function and hardening a decision are different things -- the
 * verifier returned a protected sentinel, and then main threw that protection
 * away with a single unprotected compare-and-branch.
 *
 * The fix is a capability-token pattern. The accept path cannot be reached
 * without carrying the sentinel, and the sentinel is re-tested at the point of
 * commitment rather than only at the point of decision. Skipping any one check
 * still leaves the others; skipping the branch lands in the reject path because
 * reject is the fall-through default.
 */
#include <stdint.h>
#include "image.h"
#include "../common/oracle.h"

__attribute__((section(".noinit"), used)) uint8_t g_image[sizeof(image_header_t) + IMAGE_MAX_LEN];
__attribute__((section(".noinit"), used)) uint8_t g_key[IMAGE_KEY_LEN];
__attribute__((section(".noinit"), used)) uint32_t g_min_version;
__attribute__((section(".noinit"), used)) uint8_t g_scratch[IMAGE_MAX_LEN + 64];

#if USE_HARDENED
/* Takes the sentinel as a capability token and re-tests it before committing.
 * Reaching this function is not sufficient to boot; carrying a valid token is. */
static void jump_to_app(const image_header_t *hdr, volatile uint32_t token)
{
    if (token != VERIFY_PASS)          oracle_halt(FW_VERDICT_BOOT_REJECT);
    if (!(token == VERIFY_PASS))       oracle_halt(FW_VERDICT_BOOT_REJECT);
    if ((token ^ VERIFY_PASS) != 0u)   oracle_halt(FW_VERDICT_BOOT_REJECT);
    if (hdr->magic != IMAGE_MAGIC)     oracle_halt(FW_VERDICT_BOOT_REJECT);
    if (hdr->version < g_min_version)  oracle_halt(FW_VERDICT_BOOT_REJECT);

    g_oracle.image_version = hdr->version;
    oracle_mark(MARK_JUMP_TAKEN);
    oracle_halt(FW_VERDICT_BOOT_ACCEPT);
}
#else
static void jump_to_app(const image_header_t *hdr)
{
    g_oracle.image_version = hdr->version;
    oracle_mark(MARK_JUMP_TAKEN);
    /* Real firmware branches to hdr->entry here. Under the harness the branch
     * itself is what we care about, so record and halt: emulating an app we
     * did not write would add untraced instructions to every campaign run. */
    oracle_halt(FW_VERDICT_BOOT_ACCEPT);
}
#endif

int main(void)
{
    const image_header_t *hdr = (const image_header_t *)g_image;
    const uint8_t *body = g_image + sizeof(image_header_t);

#if USE_HARDENED
    volatile uint32_t r = VERIFY_FAIL;

    r = verify_image_hardened(hdr, body, g_key, g_min_version);

    /* Divergent duplication, same rationale as inside the verifier: the two
     * forms are not structurally identical so CSE cannot merge them. */
    if (r != VERIFY_PASS)        oracle_halt(FW_VERDICT_BOOT_REJECT);
    if (!(r == VERIFY_PASS))     oracle_halt(FW_VERDICT_BOOT_REJECT);
    if ((r ^ VERIFY_PASS) != 0u) oracle_halt(FW_VERDICT_BOOT_REJECT);

    jump_to_app(hdr, r);
#else
    if (verify_image(hdr, body, g_key, g_min_version)) {
        jump_to_app(hdr);
    }
#endif
    oracle_halt(FW_VERDICT_BOOT_REJECT);   /* fall-through default is REJECT */
    return 0;
}
