/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdlib.h>

#include <nn_osal/osal.h>

#include "gw_peer_reset.h"

NN_OSAL_LOG_MODULE(gw_peer_reset);

/* Board-specific pin assignments — kept inline (instead of in a
 * separate nn_board.c) because there's only one board for this app
 * today.  When a 2nd board target arrives, move these defines plus
 * the gw_peer_reset_init() registration to apps/<app>/boards/<b>.c. */
#define RESET_GPIO_PIN  19
#define BOOT_GPIO_PIN   18  /* host GPIO18 → NCP GPIO9 (BOOT, open-drain) */

static nn_osal_gpio_pin_t s_reset_pin;
static nn_osal_gpio_pin_t s_boot_pin;

int gw_peer_reset_init(void)
{
	nn_osal_gpio_port_t *gpio_port = NN_OSAL_GPIO_DT_PORT_BY_NODELABEL(gpio0);
	if (!nn_osal_gpio_port_ready(gpio_port)) {
		NN_LOG_ERR("gpio0 not ready");
		return -ENODEV;
	}

	nn_osal_gpio_from_raw(&s_reset_pin, gpio_port,
			      RESET_GPIO_PIN, 0);
	nn_osal_gpio_from_raw(&s_boot_pin,  gpio_port,
			      BOOT_GPIO_PIN,  0);
	nn_osal_gpio_register("ncp_reset", &s_reset_pin);
	nn_osal_gpio_register("ncp_boot",  &s_boot_pin);

	/* Idle HIGH — NCP EN sees high → chip running normally. */
	int rv = nn_osal_gpio_configure(&s_reset_pin,
					NN_OSAL_GPIO_OUTPUT |
					NN_OSAL_GPIO_INIT_HIGH);
	if (rv) {
		NN_LOG_ERR("nn_osal_gpio_configure(reset, GPIO%d): %d",
			RESET_GPIO_PIN, rv);
		return rv;
	}
	/* BOOT line: open-drain so we never fight the NCP's GPIO9 internal
	 * pull-up.  Idle deasserted (logical 1 → high-Z, NCP pull-up keeps
	 * the line HIGH → SPI flash boot at next reset). */
	rv = nn_osal_gpio_configure(&s_boot_pin,
				    NN_OSAL_GPIO_OUTPUT |
				    NN_OSAL_GPIO_INIT_HIGH |
				    NN_OSAL_GPIO_OPEN_DRAIN);
	if (rv) {
		NN_LOG_WRN("nn_osal_gpio_configure(boot, GPIO%d, OD): %d — "
			"download_ncp will not work", BOOT_GPIO_PIN, rv);
	} else {
		NN_LOG_INF("peer-boot GPIO%d configured (open-drain idle high "
			"→ NCP BOOT)", BOOT_GPIO_PIN);
	}
	NN_LOG_INF("peer-reset GPIO%d configured (idle high → NCP EN)",
		RESET_GPIO_PIN);
	return 0;
}

void gw_peer_reset_pulse(int hold_ms)
{
	nn_osal_gpio_pin_t *reset = nn_osal_gpio_get("ncp_reset");
	if (!reset) {
		NN_LOG_WRN("gw_peer_reset not initialized");
		return;
	}
	if (hold_ms < 1) hold_ms = 1;
	NN_LOG_INF("pulsing NCP reset (LOW for %d ms)", hold_ms);
	nn_osal_gpio_set_logical(reset, 0);
	nn_osal_sleep_ms(hold_ms);
	nn_osal_gpio_set_logical(reset, 1);
}

void gw_peer_reset_download(int en_pulse_ms, int boot_hold_ms)
{
	nn_osal_gpio_pin_t *reset = nn_osal_gpio_get("ncp_reset");
	nn_osal_gpio_pin_t *boot  = nn_osal_gpio_get("ncp_boot");
	if (!reset || !boot) {
		NN_LOG_WRN("gw_peer_reset not initialized");
		return;
	}
	if (en_pulse_ms  < 1) en_pulse_ms  = 50;
	if (boot_hold_ms < 1) boot_hold_ms = 200;

	NN_LOG_INF("download_ncp: BOOT=LOW + EN pulse %d ms + BOOT hold %d ms",
		en_pulse_ms, boot_hold_ms);
	/* Assert BOOT first so the NCP samples it low at the EN rising edge. */
	nn_osal_gpio_set_logical(boot,  0);
	nn_osal_sleep_ms(2);
	nn_osal_gpio_set_logical(reset, 0);
	nn_osal_sleep_ms(en_pulse_ms);
	nn_osal_gpio_set_logical(reset, 1);
	/* Hold BOOT a bit longer to cover the ROM strapping read window. */
	nn_osal_sleep_ms(boot_hold_ms);
	nn_osal_gpio_set_logical(boot, 1);  /* high-Z (open-drain) */
}

/* ── shell ─────────────────────────────────────────────────────── */

static int cmd_reset_ncp(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	int hold_ms = 100;
	if (argc == 2) hold_ms = atoi(argv[1]);
	nn_osal_shell_print(sh, "pulsing NCP EN low for %d ms", hold_ms);
	gw_peer_reset_pulse(hold_ms);
	nn_osal_shell_print(sh, "done");
	return 0;
}

static int cmd_download_ncp(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	int en_ms   = 50;
	int boot_ms = 200;
	if (argc >= 2) en_ms   = atoi(argv[1]);
	if (argc >= 3) boot_ms = atoi(argv[2]);
	nn_osal_shell_print(sh, "putting NCP into ROM download mode "
		    "(EN low %d ms, BOOT hold %d ms)", en_ms, boot_ms);
	gw_peer_reset_download(en_ms, boot_ms);
	nn_osal_shell_print(sh, "done — NCP is now in ROM bootloader; esptool the "
		    "NCP UART0 port now");
	return 0;
}

NN_OSAL_SHELL_CMD_REGISTER(reset_ncp, cmd_reset_ncp,
		   "reset_ncp [hold_ms] — hardware-reset paired NCP via "
		   "GPIO 19 (default 100 ms low pulse)");

NN_OSAL_SHELL_CMD_REGISTER(download_ncp, cmd_download_ncp,
		   "download_ncp [en_ms] [boot_ms] — drive paired NCP into "
		   "ROM download mode (BOOT low across EN reset). "
		   "Defaults: en=50 ms, boot_hold=200 ms");
