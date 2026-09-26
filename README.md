# ESP32-C6 NCP Host (Phase N2)

Zephyr firmware for the host chip in our NCP architecture. Pairs with the
`ncp_esp32c6` firmware running on a separate ESP32-C6 (the NCP chip). The
host provides WiFi connectivity and bridges infrastructure services
(mDNS, NAT64, router advertisements) to the Thread network via Spinel.

**Status**: design + scaffolding. No source yet — the implementation
requires writing a custom Zephyr NCP client (~1500 LOC) because Zephyr
does not ship one.

## Hardware layout

```
┌─────────────────────┐   UART1 HDLC/Spinel   ┌─────────────────────┐
│   NCP ESP32-C6      │   460800 + RTS/CTS    │  Host ESP32-C6      │
│   nn-app-ncp-esp32c6│ ◄───────────────────► │  nn-app-ncp-host    │
│                     │                       │                     │
│   OT FTD + BR core  │                       │   WiFi STA          │
│   SRP server        │                       │   NCP client        │
│   Border Agent      │                       │   mDNS proxy        │
│   802.15.4 radio    │                       │   NAT64 translator  │
│                     │                       │   Infra RA sender   │
└─────────────────────┘                       └─────────────────────┘
```

## Wiring (cross-connect, identical to RCP layout)

| NCP (C6) | ↔ | Host (C6) |
|----------|---|-----------|
| GPIO5 (UART1 TX) | → | GPIO4 (UART1 RX) |
| GPIO4 (UART1 RX) | ← | GPIO5 (UART1 TX) |
| GPIO6 (UART1 RTS) | → | GPIO7 (UART1 CTS) |
| GPIO7 (UART1 CTS) | ← | GPIO6 (UART1 RTS) |
| GND | — | GND |

The Host chip's UART0 (USB-JTAG) is reserved for the shell/debug console.

## Architectural responsibilities

### What the NCP does (already built)

- Full OpenThread FTD stack
- 802.15.4 MAC + radio
- Thread mesh routing
- SRP server (Thread-side service registration)
- Border Agent (commissioning DTLS on Thread side)
- DNSSD server
- Spinel/HDLC NCP server

### What the Host must do (this app)

- **WiFi STA** — join infrastructure network, get IPv4 + IPv6
- **Spinel client** — HDLC framing, Spinel encode/decode, connection state
- **IP packet forwarding** — bidirectional between WiFi net_if and the virtual
  "thread_net_if" that represents the NCP's Thread interface over Spinel
- **OT platform hook implementations** (over Spinel):
  - `otPlatInfraIfSendIcmp6Nd` — host sends ND/RA packets on WiFi
  - `otPlatMdnsSendMulticast` / `otPlatMdnsSendUnicast` — host publishes
    mDNS on WiFi (receives events from NCP's SRP server)
  - `otPlatDnsStartUpstreamQuery` — host resolves DNS for Thread devices
    via WiFi DNS resolver
- **NAT64 translator** — implement IPv6-to-IPv4 translation on host side,
  since host is where WiFi/IPv4 egress lives. Use `inet_ntoa`/socket API
  to translate.

## Implementation plan

### Milestone A: Minimal NCP client

Goal: host boots, establishes Spinel link with NCP, reports OT state.

- `src/spinel_host.c` — HDLC framing + Spinel encode/decode
  - Reuse `third_party/openthread/src/lib/hdlc/hdlc.cpp`
  - Reuse `third_party/openthread/src/lib/spinel/spinel.c` (encoder/decoder)
- `src/ncp_link.c` — UART driver, manages inbound/outbound queues
- Shell commands: `ncp version`, `ncp state`, `ncp send <hex>`

Lines of code: ~500.

### Milestone B: Packet forwarding (IP6 tunneling)

Goal: Thread device can ping an IPv6 address on the WiFi infrastructure.

- `src/ncp_netif.c` — register a Zephyr `net_if` for the Thread interface
  - L2 send: encode as Spinel `NET_SEND_STREAM` frame, send over UART
  - L2 recv: decode Spinel `NET_RECV_STREAM`, hand to `net_recv_data`
- Handle Thread address assignment: NCP publishes its addresses via Spinel;
  host registers them on the virtual net_if
- `src/main.c` — set up routing so WiFi ↔ thread_net_if forwarding works

Lines of code: ~600.

### Milestone C: Border routing services

Goal: NAT64 works, sensors can reach the IPv4 hub.

- `src/platform_infra_if.c` — implement `otPlatInfraIfSendIcmp6Nd` over
  Spinel (host sends ICMPv6 ND/RA on WiFi netif; received packets from
  WiFi get forwarded to NCP via Spinel as infra-if receive)
- `src/nat64.c` — NAT64 table + translation (IPv6 with 64:ff9b::/96 prefix
  → IPv4 on WiFi; reply IPv4 → synthesized IPv6)
- `src/platform_mdns.c` — implement `otPlatMdnsSendMulticast` (receives
  mDNS publish requests from NCP's SRP server, sends on WiFi IPv6 mcast)

Lines of code: ~800.

### Milestone D: DNS upstream + Border Agent UDP forward

Goal: full DNS-SD discovery and external commissioning.

- `src/platform_dns_upstream.c` — forward DNS queries from NCP (for Thread
  devices that want to resolve external hostnames) to WiFi DNS resolver
- UDP forwarder: handle `SPINEL_PROP_THREAD_UDP_FORWARD_STREAM` for BA

Lines of code: ~300.

**Total estimated implementation: ~2200 LOC.**

## Existing code we can reuse

| Source | Purpose |
|--------|---------|
| `third_party/openthread/src/lib/hdlc/hdlc.cpp` | HDLC framing |
| `third_party/openthread/src/lib/spinel/spinel.c` | Spinel encoder/decoder |
| `third_party/openthread/src/posix/platform/radio_spinel.cpp` | Reference for Spinel property patterns |
| `third_party/openthread/src/posix/platform/infra_if.cpp` | Reference for infra_if platform impl |
| `third_party/openthread/src/posix/platform/mdns_socket.cpp` | Reference for mDNS platform impl |
| `apps/tbr_esp32c6/` | WiFi + stub patterns |

None of the POSIX platform code runs as-is on Zephyr — it uses POSIX
sockets, select(), threads. Porting each file is mostly mechanical but
not automatic.

## Zephyr config highlights

```
# Shell + console on USB-JTAG
CONFIG_SHELL=y
CONFIG_SERIAL=y
CONFIG_UART_INTERRUPT_DRIVEN=y

# WiFi STA (standard)
CONFIG_WIFI=y
CONFIG_NET_L2_WIFI_SHELL=y
CONFIG_ESP32_WIFI_STA_AUTO_DHCPV4=y
CONFIG_NET_IPV4=y
CONFIG_NET_IPV6=y
CONFIG_NET_DHCPV4=y

# We do NOT enable CONFIG_NET_L2_OPENTHREAD or OPENTHREAD_FTD
# — all OT logic lives on the NCP.

# UART1 for Spinel link to NCP
# (no Kconfig for this — we write the driver from scratch)

# Memory (host doesn't need huge OT state, should fit easily)
CONFIG_MAIN_STACK_SIZE=5200
CONFIG_NET_BUF_RX_COUNT=32
CONFIG_NET_BUF_TX_COUNT=32
```

Estimated RAM usage: ~120KB / 400KB SRAM (plenty of room).

## Testing (when implemented)

1. **Unit**: Spinel encode/decode round-trips (host talks to a loopback NCP)
2. **Integration**: Host C6 speaks to NCP C6 over UART1. Run `ncp state` —
   should return OT state from the NCP.
3. **Thread join**: Sensor-01 joins the Thread network formed by the NCP
   (NCP acts as leader; host doesn't participate in Thread).
4. **IPv6 ping**: Thread device pings a Link-Local address on the Host's
   WiFi interface — verifies packet forwarding.
5. **NAT64**: Thread device pings `64:ff9b::1.1.1.1` — verifies NAT64
   translation on the host.
6. **SRP + mDNS**: Sensor registers a service via SRP; host publishes it
   as mDNS on WiFi; a laptop on the same WiFi sees it in `dns-sd -B`.
7. **OTA stress**: Sensor OTA downloads 947KB firmware over NAT64.
   Target: >100KB without stall (beats ESP-IDF TBR we replaced).

## Limitations / open questions

- **Spinel property extensions for mDNS**: stock Spinel doesn't define
  mDNS proxy commands. We'd need custom Spinel vendor properties OR
  restructure so SRP events flow via a different channel.
- **Commissioner external access**: Border Agent commissioning expects
  DTLS handshakes to originate from WiFi and terminate in OT. Host must
  decrypt/forward these as opaque UDP (via `UDP_FORWARD_STREAM`).
- **Test tooling**: We'll need a Spinel-fluent test fixture. Simplest
  is a Python `pyspinel` script driving the host's Spinel link.

## Next concrete step

Decide whether to implement Milestones A–D or switch to Linux
`otbr-agent` path (which already implements all of the above). See
parent plan file `functional-prancing-anchor.md`.
