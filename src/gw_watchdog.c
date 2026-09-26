/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>

#include <nn_osal/osal.h>

#include "gw_watchdog.h"

NN_OSAL_LOG_MODULE(gw_watchdog);

#define KICK_PERIOD_MS  10000
#define WDT_TIMEOUT_MS  60000
#define WORKER_STACK    1024
#define WORKER_PRIO     10

static nn_osal_wdt_channel_t s_chan = -1;

static void on_watchdog_fault(nn_osal_wdt_channel_t channel, void *user)
{
	(void)channel; (void)user;
	/* If we get here at all, the heartbeat thread isn't feeding us —
	 * log via printk (LOG might also be wedged) and let the underlying
	 * HW WDT carry through with a reset. */
	nn_osal_printk("\n*** TASK WATCHDOG TIMEOUT - forcing reset ***\n");
}

static void heartbeat_thread(void *a, void *b, void *c)
{
	(void)a; (void)b; (void)c;
	while (1) {
		if (s_chan >= 0) {
			(void)nn_osal_task_wdt_feed(s_chan);
		}
		nn_osal_sleep_ms(KICK_PERIOD_MS);
	}
}

NN_OSAL_THREAD_STACK_DEFINE(s_hb_stack, WORKER_STACK);
static nn_osal_thread_t s_hb_thread;

int gw_watchdog_init(void)
{
	int rv = nn_osal_task_wdt_init(WDT_TIMEOUT_MS, on_watchdog_fault, NULL);
	if (rv == -ENOSYS) {
		NN_LOG_DBG("task watchdog not available; gw_watchdog is a no-op");
		return 0;
	}
	if (rv && rv != -EALREADY) {
		NN_LOG_WRN("nn_osal_task_wdt_init: %d (continuing without WDT)", rv);
		return rv;
	}
	s_chan = nn_osal_task_wdt_add(WDT_TIMEOUT_MS);
	if (s_chan < 0) {
		NN_LOG_WRN("nn_osal_task_wdt_add: %d (continuing without WDT)",
			   s_chan);
		return s_chan;
	}
	rv = nn_osal_thread_create(&s_hb_thread,
				   s_hb_stack, sizeof(s_hb_stack),
				   heartbeat_thread, NULL, NULL, NULL,
				   WORKER_PRIO, "gw_wdt_hb");
	if (rv) {
		NN_LOG_WRN("nn_osal_thread_create(gw_wdt_hb): %d", rv);
		return rv;
	}
	NN_LOG_INF("task watchdog armed (%d ms timeout, %d ms heartbeat)",
		WDT_TIMEOUT_MS, KICK_PERIOD_MS);
	return 0;
}
