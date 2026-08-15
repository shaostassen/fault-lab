#include <stdint.h>
#include "../common/oracle.h"

void supervisor_run(uint32_t iterations);

/* Scenario inputs, written by the harness pre-reset. */
__attribute__((section(".noinit"), used)) volatile uint32_t g_sensor_current_ma;
__attribute__((section(".noinit"), used)) volatile uint32_t g_ticks_since_update;
__attribute__((section(".noinit"), used)) volatile uint32_t g_setpoint;
__attribute__((section(".noinit"), used)) volatile uint32_t g_iterations;

int main(void)
{
    supervisor_run(g_iterations ? g_iterations : 24u);
    return 0;
}
