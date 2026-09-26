# Implementation Plan

Concrete step-by-step for the NCP host firmware. Each milestone is a
build-and-test gate.

## Source tree (proposed)

```
apps/ncp_host_esp32c6/
├── CMakeLists.txt
├── prj.conf
├── boards/esp32c6_devkitc_hpcore.overlay
├── src/
│   ├── main.c              — init order, shell commands
│   ├── hdlc.c / .h         — HDLC framer (port of OT's hdlc.cpp)
│   ├── spinel.c / .h       — Spinel encode/decode (port of OT's spinel.c)
│   ├── ncp_link.c / .h     — UART driver + link-layer state machine
│   ├── ncp_netif.c / .h    — Zephyr net_if for Thread over Spinel
│   ├── platform_infra.c    — otPlatInfraIf* stubs forwarding over Spinel
│   ├── platform_mdns.c     — otPlatMdns* → mDNS publish on WiFi
│   ├── platform_dns.c      — otPlatDnsStartUpstreamQuery forwarding
│   ├── nat64.c / .h        — NAT64 translator (IPv6↔IPv4, stateful)
│   └── border_agent.c      — BA UDP forwarding (port 49191 → Spinel)
├── docs/
│   ├── architecture.md     — High-level design
│   ├── spinel-protocol.md  — Spinel property reference
│   └── implementation-plan.md  — This file
└── README.md
```

## Milestone A: Spinel link bring-up

**Scope**: host ↔ NCP handshake, shell commands to query NCP state.

**Files**:
- `src/hdlc.c` — HDLC byte-stuff/unstuff, CRC16
- `src/spinel.c` — pack/unpack variable-length integers, property IDs
- `src/ncp_link.c` — UART RX thread reads bytes, frames them, dispatches
- `src/main.c` — k_thread for link, shell commands

**Build targets**:
- Compile without OpenThread (CONFIG_NET_L2_OPENTHREAD=n)
- Still enable CONFIG_WIFI=y for later (test it boots)

**Tests**:
- `ncp version` → returns `NCP_VERSION` string from the NCP
- `ncp capability` → lists CAPS property
- `ncp raw-get 1` → hex dump of PROPTOCOL_VERSION reply
- Spinel frame errors logged but don't crash

**Acceptance**:
- Host shell shows `ncp:~$ ncp version` returning real data from the paired NCP
- No HDLC framing errors over a 10-second `stress-get` test (continuous GETs)

**Estimated effort**: 2-3 days. ~500 LOC.

---

## Milestone B: IP packet forwarding

**Scope**: Thread IPv6 packets tunnel through the host transparently.

**Files**:
- `src/ncp_netif.c` — register a `net_if` of type dummy/generic that
  encodes/decodes via Spinel `STREAM_NET`
- Update `src/main.c` to subscribe to the NCP's IPv6 address notifications

**Config changes**:
- `CONFIG_NET_IPV6=y` (already)
- `CONFIG_NET_ROUTING=y` — host becomes a router between netifs
- Custom L2 layer that sends via Spinel instead of to a physical link

**Tests**:
- NCP forms a Thread network (NCP is leader)
- Sensor-01 joins; NCP reports its OMR address via `IPV6_ADDRESS_TABLE`
  notification
- Host registers that address on thread_net_if
- Ping6 from host WiFi interface → sensor OMR → reply received

**Acceptance**:
- `ping6 <sensor OMR>` from the host shell works
- `net iface` shows two interfaces: `wlan0` + `thread_spinel`
- Routing table entry points `fd**::/64` (OMR prefix) to `thread_spinel`

**Estimated effort**: 3-5 days. ~600 LOC.

---

## Milestone C: NAT64 + Infrastructure services

**Scope**: Thread sensors can reach IPv4 internet (through host WiFi).

**Files**:
- `src/platform_infra.c` — otPlatInfraIf* platform hook implementations
- `src/nat64.c` — stateful NAT64 (port-overloaded, PMP-style mapping)

**How it works**:
1. Host sends WiFi router advertisements with NAT64 prefix
2. NCP learns prefix from RA, configures its OMR
3. Sensor sends to `64:ff9b::1.2.3.4` → NCP forwards to host via Spinel
4. Host's NAT64 translates IPv6 → IPv4, opens IPv4 socket, sends
5. Reply arrives on IPv4 socket → translate → Spinel → NCP → sensor

**Config changes**:
- `CONFIG_NET_IPV4=y`, `CONFIG_NET_DHCPV4=y`, `CONFIG_DNS_RESOLVER=y`
- Large NAT64 table (`CONFIG_NAT64_MAX_MAPPINGS=128`)

**Tests**:
- From sensor: `ping6 64:ff9b::1.1.1.1` works
- `ping6 64:ff9b::<hub-ipv4>` — hub receives + replies
- Sustained: 100 pings, <1% loss
- Concurrent: 3 sensors simultaneously pinging, no cross-contamination

**Acceptance**:
- Hub reachable from all three sensors via NAT64
- OTA download (947KB test) completes without stall —
  **this is the final acceptance gate vs ESP-IDF TBR**

**Estimated effort**: 5-7 days. ~800 LOC.

---

## Milestone D: mDNS proxy + Border Agent

**Scope**: Service discovery and external commissioning.

**Files**:
- `src/platform_mdns.c` — implement otPlatMdns* via Zephyr mDNS responder
- `src/border_agent.c` — UDP listener on port 49191 → Spinel UDP_FORWARD_STREAM

**Tests**:
- Sensor registers `_hub._tcp.local` via SRP
- `avahi-browse _hub._tcp` on host laptop (same WiFi) sees the service
- OpenThread commissioner app can commission a new sensor through the
  host's WiFi

**Estimated effort**: 3-4 days. ~300 LOC.

---

## Dependencies and gotchas

### Zephyr module integration

We need to avoid enabling `CONFIG_NET_L2_OPENTHREAD` on the host — that
tries to bring up its own OT stack. Instead we build OpenThread's
**spinel + hdlc libraries** independently:

```
CONFIG_NET_L2_OPENTHREAD=n
# But we need to manually pull in openthread-spinel lib for encoding:
# (might need custom CMakeLists changes or just copy the relevant files)
```

If that doesn't work out, we can:
- Copy `spinel.h`, `spinel.c`, `hdlc.hpp`, `hdlc.cpp` directly into
  our `src/` tree (they're standalone)
- Use `add_subdirectory` for `third_party/openthread/src/lib/{spinel,hdlc}`
  as a standalone module

### PSA/mbedtls

Border Agent on NCP handles all DTLS. Host doesn't need mbedtls.
Leave existing PSA knobs alone; they stay off by default.

### WiFi blob stubs

Same issue as `apps/tbr_esp32c6/`: weak stubs for
`esp_wifi_sta_get_reset_nvs_pmk_internal` etc. Copy from there.

### Log levels

Keep OT/Spinel log levels low during normal operation (INF or WRN).
UART0 console can get flooded by every Spinel frame logged at DBG.

## When to ship each milestone

- **Milestone A**: can be standalone commit; the Spinel library is
  generically useful and we can demo the link with `ncp version`.
- **Milestone B**: minimum for "proof the architecture works" — host
  can act as a Thread-to-anywhere router at the IPv6 level.
- **Milestone C**: minimum for "replaces the ESP-IDF TBR" — NAT64 + OTA
  test passes.
- **Milestone D**: "production ready" — service discovery + commissioning
  work from external apps.

If any milestone exceeds its estimate by 2x, reconsider switching to
Linux `otbr-agent` for the host role.

## Implementation order within a milestone

1. Read/study the reference code first (POSIX platform/*.cpp)
2. Design the Zephyr-native API (what k_thread, k_work_q, k_mutex do we
   need?)
3. Write header first (`*.h`) — defines the contract
4. Write empty functions that return errors
5. Compile — validates linkage
6. Fill in functionality top-down
7. Unit test with a Python `pyspinel` fixture if possible

## Code style

Match the existing project style (see `apps/tbr_esp32c6/src/main.c`):
- SPDX license headers
- LOG_MODULE_REGISTER per file
- `k_thread`/`k_work`/`k_mutex` for concurrency
- No global state except `static` in each .c file
- Public API in the `.h` file only
