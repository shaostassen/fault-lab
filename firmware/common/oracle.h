/*
 * oracle.h - firmware/harness contract.
 *
 * DESIGN NOTE: the firmware reports only what it DID. It never reports
 * whether that was correct. The harness knows what input it supplied
 * (signed vs unsigned image, fault asserted vs not) and therefore owns
 * the classification. Keeping the judgement out of the firmware means
 * a fault that corrupts the firmware's self-assessment cannot launder
 * itself into a clean result.
 */
#ifndef FAULTLAB_ORACLE_H
#define FAULTLAB_ORACLE_H

#include <stdint.h>

/* MMIO window. Deliberately outside FLASH and RAM so that under Unicorn
 * it is an unmapped-write hook, and under QEMU it is a device stub.
 * A stray write here from a wild pointer is itself a signal, not noise:
 * the harness records the faulting PC. */
#define ORACLE_BASE   0x40010000u
#define ORACLE_HALT   (ORACLE_BASE + 0x00u)  /* write verdict -> stop emulation */
#define ORACLE_MARK   (ORACLE_BASE + 0x04u)  /* write checkpoint id -> set bit */

/* Raw verdicts. Values are sparse and high-Hamming-distance so that a
 * single bit flip in the verdict word cannot turn REJECT into ACCEPT. */
typedef enum {
    FW_VERDICT_NONE          = 0x00000000u,
    FW_VERDICT_BOOT_ACCEPT   = 0x0000A5C3u,
    FW_VERDICT_BOOT_REJECT   = 0x00005A3Cu,
    FW_VERDICT_SAFE_STATE    = 0x0000C33Cu,
    FW_VERDICT_RUN_COMPLETE  = 0x00003CC3u,
    FW_VERDICT_ASSERT_FAIL   = 0x0000FFF0u,
} fw_verdict_t;

/* Checkpoint ids, one bit each in oracle_state.marks. Lets the harness
 * reconstruct the control-flow path taken without an instruction trace,
 * which is what makes near-miss fitness scoring cheap in the GA search. */
enum {
    MARK_BOOT_ENTER      = 0,
    MARK_HDR_OK          = 1,
    MARK_VERSION_OK      = 2,
    MARK_SIG_OK          = 3,
    MARK_JUMP_TAKEN      = 4,
    MARK_SUP_ARMED       = 5,
    MARK_SUP_RUNNING     = 6,
    MARK_FAULT_ASSERTED  = 7,
    MARK_SAFE_ENTERED    = 8,
};

#define ORACLE_STATE_MAGIC 0x0FA17AB0u

/* Placed at a fixed address by the linker script (.oracle section) so the
 * harness can read it post-mortem without symbol lookup. Kept small: it is
 * memcpy'd on every snapshot restore. */
typedef struct {
    uint32_t magic;
    uint32_t verdict;
    uint32_t marks;         /* bitmask of MARK_* */
    uint32_t cfi_counter;   /* control-flow integrity accumulator */
    uint32_t sup_state;     /* supervisor state machine */
    uint32_t pwm_duty;      /* MUST be 0 whenever sup_state == SAFE */
    uint32_t image_version; /* version the bootloader believed it accepted */
    uint32_t reserved;
} oracle_state_t;

extern volatile oracle_state_t g_oracle;

static inline void oracle_mark(uint32_t id)
{
    g_oracle.marks |= (1u << id);
    *(volatile uint32_t *)ORACLE_MARK = id;
}

static inline void oracle_halt(uint32_t verdict)
{
    g_oracle.verdict = verdict;
    *(volatile uint32_t *)ORACLE_HALT = verdict;
    for (;;) { }  /* unreachable under emulation; guards against a skipped store */
}

#endif /* FAULTLAB_ORACLE_H */
