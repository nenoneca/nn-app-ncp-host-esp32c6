/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gw_peer_reset — drive the gateway's GPIO 19 to hardware-reset the
 * paired NCP via its EN pin.
 *
 * Software-triggered resets (sys_reboot, esp_restart) on the OT-NCP
 * leave SPI1 in a state that hangs MCUboot mid-flash-init, so OTA's
 * post-FINALIZE swap never completes.  Pulsing EN low is equivalent
 * to a power-on reset from the chip's perspective — full peripheral
 * reset, MCUboot boots cleanly, swap completes.
 *
 * Wiring: gateway GPIO 19 → NCP EN.  Both chips' GPIO 19 default to
 * input/high-Z at boot, so neither resets the other accidentally
 * during enumeration.  No series resistor needed (push-pull HIGH only
 * fights the EN pull-up briefly during the LOW pulse).
 */

#ifndef GW_PEER_RESET_H_
#define GW_PEER_RESET_H_

#ifdef __cplusplus
extern "C" {
#endif

int  gw_peer_reset_init(void);
void gw_peer_reset_pulse(int hold_ms);

/*
 * Drive the paired NCP into ROM download mode by holding its BOOT pin
 * (NCP GPIO 9) low across an EN reset pulse, then releasing.  Wiring:
 * host GPIO 18 (open-drain) → NCP GPIO 9 (BOOT, internal pull-up).
 *
 *   en_pulse_ms      — how long EN is held LOW (default 50 ms is plenty)
 *   boot_hold_ms     — how long BOOT stays LOW after EN goes HIGH
 *                      (default 200 ms covers ROM strapping read window)
 *
 * After this returns, esptool over UART0 can connect to the NCP at the
 * usual 460800 baud — no manual buttons.
 */
void gw_peer_reset_download(int en_pulse_ms, int boot_hold_ms);

#ifdef __cplusplus
}
#endif

#endif /* GW_PEER_RESET_H_ */
