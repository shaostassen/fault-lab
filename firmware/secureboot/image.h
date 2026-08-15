#ifndef FAULTLAB_IMAGE_H
#define FAULTLAB_IMAGE_H
#include <stdint.h>
#include <stddef.h>

#define IMAGE_MAGIC     0x4C464149u   /* "IAFL" */
#define IMAGE_MAX_LEN   1024u
#define IMAGE_TAG_LEN   32u
#define IMAGE_KEY_LEN   16u

/* Tag covers key || version || length || entry || body (keyed hash).
 * `length` is inside the authenticated region on purpose: a fault that
 * inflates it must also survive tag verification. */
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  tag[IMAGE_TAG_LEN];
    uint32_t version;
    uint32_t length;
    uint32_t entry;
} image_header_t;

#define IMAGE_SIGNED_OFFSET  ((size_t)offsetof(image_header_t, version))
#define IMAGE_SIGNED_HDR_LEN (sizeof(image_header_t) - IMAGE_SIGNED_OFFSET)

#define VERIFY_PASS 0xA5A5A5A5u
#define VERIFY_FAIL 0x5A5A5A5Au

int      verify_image(const image_header_t *hdr, const uint8_t *body,
                      const uint8_t *key, uint32_t min_version);
uint32_t verify_image_hardened(const image_header_t *hdr, const uint8_t *body,
                               const uint8_t *key, uint32_t min_version);
#endif
