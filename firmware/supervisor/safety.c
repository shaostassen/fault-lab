/*
 * safety.c - motor safety supervisor.
 *
 * The safety invariant, checked post-mortem by the harness:
 *
 *     fault_asserted  =>  sup_state == SUP_SAFE  AND  pwm_duty == 0
 *
 * This target matters for a different reason than the bootloader. The bootloader
 * is a SECURITY oracle: one decision, attacker-chosen timing. This is a SAFETY
 * oracle: a continuously re-evaluated invariant. Fault models that are useless
 * against the bootloader (a bit flip in a loop counter) are effective here, and
 * the asymmetry is worth reporting.
 *
 * USE_HARDENED countermeasures:
 *   S1 complement-shadowed state - state stored alongside ~state; any single
 *      bit flip in either breaks the pairing and is detected
 *   S2 duplicated divergent guards - overcurrent and deadline each tested twice
 *   S3 idempotent safe-state entry with post-condition verify
 *   S4 fail-closed default - an unrecognised state enters safe state, it does
 *      not attempt recovery
 *   S5 per-iteration invariant re-check - safe state, once entered, is
 *      re-verified every loop rather than trusted
 */

#include <stdint.h>
#include "../common/oracle.h"

typedef enum {
    SUP_INIT    = 0x11u,
    SUP_ARMED   = 0x22u,
    SUP_RUNNING = 0x44u,
    SUP_SAFE    = 0x88u,
} sup_state_t;

#define OVERCURRENT_THRESHOLD_MA  4200u
#define DEADLINE_TICKS            50u
#define DUTY_MAX                  1000u

extern volatile uint32_t g_sensor_current_ma;
extern volatile uint32_t g_ticks_since_update;
extern volatile uint32_t g_setpoint;

#if USE_HARDENED

/* S1: state and its complement travel together. */
static volatile uint32_t s_state, s_state_inv;
static volatile uint32_t s_duty,  s_duty_inv;

static void set_state(uint32_t v) { s_state = v; s_state_inv = ~v; }
static void set_duty(uint32_t v)  { s_duty  = v; s_duty_inv  = ~v; }
static int  state_ok(void)        { return (s_state ^ ~s_state_inv) == 0u; }
static int  duty_ok(void)         { return (s_duty  ^ ~s_duty_inv)  == 0u; }

/* S3: idempotent, and verifies its own post-condition before returning. */
static void enter_safe_state(void)
{
    set_duty(0u);
    set_state(SUP_SAFE);
    g_oracle.pwm_duty = 0u;
    g_oracle.sup_state = SUP_SAFE;
    oracle_mark(MARK_SAFE_ENTERED);

    if (s_duty != 0u)              { g_oracle.pwm_duty = 0u; oracle_halt(FW_VERDICT_ASSERT_FAIL); }
    if (s_state != SUP_SAFE)       { g_oracle.pwm_duty = 0u; oracle_halt(FW_VERDICT_ASSERT_FAIL); }
    if (g_oracle.pwm_duty != 0u)   { g_oracle.pwm_duty = 0u; oracle_halt(FW_VERDICT_ASSERT_FAIL); }
}

void supervisor_run(uint32_t iterations)
{
    set_state(SUP_INIT);
    set_duty(0u);
    g_oracle.sup_state = SUP_INIT;
    g_oracle.pwm_duty = 0u;

    for (uint32_t i = 0u; i < iterations; i++) {

        /* S1: shadow integrity before anything trusts the state. */
        if (!state_ok()) { enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE); }
        if (!duty_ok())  { enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE); }

        /* S2: divergent duplication of each guard. */
        if (g_sensor_current_ma > OVERCURRENT_THRESHOLD_MA) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE);
        }
        if (!(g_sensor_current_ma <= OVERCURRENT_THRESHOLD_MA)) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE);
        }
        if (g_ticks_since_update > DEADLINE_TICKS) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE);
        }
        if (!(g_ticks_since_update <= DEADLINE_TICKS)) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state(); oracle_halt(FW_VERDICT_SAFE_STATE);
        }

        switch (s_state) {
        case SUP_INIT:    set_state(SUP_ARMED);   oracle_mark(MARK_SUP_ARMED);   break;
        case SUP_ARMED:   set_state(SUP_RUNNING); oracle_mark(MARK_SUP_RUNNING); break;
        case SUP_RUNNING: {
            uint32_t d = s_duty;
            if (d < g_setpoint)      d += 10u;
            else if (d > g_setpoint) d -= 10u;
            if (d > DUTY_MAX)        d = DUTY_MAX;
            set_duty(d);
            break;
        }
        case SUP_SAFE:    set_duty(0u); break;
        default:
            /* S4: an impossible state IS a detected fault. Do not recover. */
            enter_safe_state(); oracle_halt(FW_VERDICT_ASSERT_FAIL);
        }

        /* S5: safe state is re-verified, never trusted. */
        if (s_state == SUP_SAFE && s_duty != 0u) {
            set_duty(0u); g_oracle.pwm_duty = 0u;
            oracle_halt(FW_VERDICT_ASSERT_FAIL);
        }

        g_oracle.sup_state = s_state;
        g_oracle.pwm_duty  = s_duty;
    }
    oracle_halt(FW_VERDICT_RUN_COMPLETE);
}

#else  /* ---------------- baseline ---------------- */

static void enter_safe_state(void)
{
    g_oracle.pwm_duty = 0u;
    g_oracle.sup_state = SUP_SAFE;
    oracle_mark(MARK_SAFE_ENTERED);
}

void supervisor_run(uint32_t iterations)
{
    sup_state_t state = SUP_INIT;
    uint32_t duty = 0u;

    g_oracle.sup_state = state;
    g_oracle.pwm_duty = 0u;

    for (uint32_t i = 0u; i < iterations; i++) {

        if (g_sensor_current_ma > OVERCURRENT_THRESHOLD_MA) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state();
            oracle_halt(FW_VERDICT_SAFE_STATE);
        }
        if (g_ticks_since_update > DEADLINE_TICKS) {
            oracle_mark(MARK_FAULT_ASSERTED);
            enter_safe_state();
            oracle_halt(FW_VERDICT_SAFE_STATE);
        }

        switch (state) {
        case SUP_INIT:    state = SUP_ARMED;   oracle_mark(MARK_SUP_ARMED);   break;
        case SUP_ARMED:   state = SUP_RUNNING; oracle_mark(MARK_SUP_RUNNING); break;
        case SUP_RUNNING:
            if (duty < g_setpoint)      duty += 10u;
            else if (duty > g_setpoint) duty -= 10u;
            if (duty > DUTY_MAX)        duty = DUTY_MAX;
            break;
        case SUP_SAFE:    duty = 0u; break;
        default:
            enter_safe_state();
            oracle_halt(FW_VERDICT_ASSERT_FAIL);
        }

        g_oracle.sup_state = (uint32_t)state;
        g_oracle.pwm_duty = duty;
    }
    oracle_halt(FW_VERDICT_RUN_COMPLETE);
}
#endif
