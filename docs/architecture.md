# Architecture: C6 NCP + C6 Host

## Why two chips

A Thread Border Router needs two radios active at once:
- **802.15.4** to talk to Thread sensors
- **WiFi** to talk to infrastructure (and the hub)

ESP32-C6 has both radios on one die, but Zephyr's implementation:
- **Cannot run WiFi + 802.15.4 simultaneously** with acceptable reliability
- **Zephyr Border Router glue is 131KB static** — doesn't fit with WiFi on the same chip

Solution: split the roles across two C6s.

## Where each service lives

| Service | Chip | Reason |
|---------|------|--------|
| 802.15.4 MAC + radio | NCP | Physically needs the 802.15.4 radio |
| OT stack (MLE, 6LoWPAN) | NCP | Wants exclusive radio control |
| Thread routing | NCP | Uses OT internal state |
| SRP server | NCP | Receives registrations from Thread side |
| Border Agent (DTLS termination) | NCP | Owns MeshCoP keys in OT Instance |
| Commissioner | NCP | OT Commissioner API |
| WiFi STA | Host | Physically needs the WiFi radio |
| IPv4 connectivity | Host | Comes from WiFi DHCP |
| NAT64 translator | Host | Needs IPv4 socket API |
| mDNS advertising proxy | Host | Publishes on WiFi link-local |
| Infrastructure RA | Host | Sends on WiFi link |
| External DNS resolver | Host | Uses WiFi DHCP-learned DNS |
| Upstream DNS forwarder | Host | Queries external on behalf of Thread |

## Packet flows

### Thread device → IPv4 hub (happy path, NAT64)

```
Sensor (Thread) ─┐
  IPv6 packet to │
  64:ff9b::<hub> │
                 ▼
              [NCP receives on 802.15.4]
              OT stack routes internally
                 │
                 ▼
              NCP recognizes 64:ff9b::/96 prefix
              (advertised by Host via INFRA_IF_STATE)
              Wraps IPv6 packet in Spinel STREAM_NET
                 │
                 ▼ UART1 + HDLC + Spinel
              [Host receives Spinel frame]
              Decodes → raw IPv6 packet
                 │
                 ▼
              NAT64 translator (host-side code)
              - 64:ff9b::<hub-ipv4> → <hub-ipv4>
              - src: NAT64 pool mapping
              Synthesizes IPv4 packet
                 │
                 ▼
              net_send_data on WiFi netif
                 │
                 ▼
              Hub receives IPv4 packet ✓
```

### Reply: IPv4 hub → Thread device

```
Hub (IPv4) ─────┐
  reply IPv4    │
                ▼
             [Host WiFi receives]
             net_recv_data IPv4 pkt
                │
                ▼
             NAT64 translator
             - <pool-ipv4> → 64:ff9b::<sensor-v6>
             - looks up mapping by src port
                │
                ▼
             Synthesizes IPv6 packet
             Wraps in Spinel STREAM_NET frame
                │
                ▼ UART1 + HDLC + Spinel
             [NCP receives]
             OT stack routes to sensor on 802.15.4
                │
                ▼
             Sensor receives IPv6 reply ✓
```

### SRP registration → mDNS advertisement

```
Sensor ──── SRP DNS-SD update ────►  [NCP SRP server accepts]
                                           │
                                           ▼
                                     NCP sends Spinel vendor prop:
                                     MDNS_REGISTER_SERVICE
                                     { name, type, port, txt, ipv6 }
                                           │
                                           ▼ UART1
                                     [Host decodes Spinel]
                                     Calls mdns_publish_service()
                                     on WiFi net_if
                                           │
                                           ▼
                                     Neighbors on WiFi LAN see mDNS PTR/SRV
                                     `dns-sd -B _foo._tcp` finds it ✓
```

### External commissioner → NCP Border Agent

```
Commissioner (laptop on WiFi) ──► UDP to Host:49191 (DTLS handshake)
                                     │
                                     ▼
                                  [Host WiFi receives UDP]
                                  Port 49191 is border-agent
                                     │
                                     ▼
                                  Wrap payload in Spinel
                                  THREAD_UDP_FORWARD_STREAM
                                     │
                                     ▼ UART1
                                  [NCP decodes]
                                  Delivers to Border Agent
                                     │
                                     ▼
                                  DTLS handshake completes
                                  (Border Agent has MeshCoP PSKc)
                                     │
                                     ▼
                                  Reply UDP flows back through
                                  same STREAM_NET tunnel
```

## Shared configuration

Both NCP and Host must agree on:

- **Spinel IID** (usually 0 for single-interface)
- **Spinel TID counter** (host drives it; NCP matches)
- **NAT64 prefix** (`64:ff9b::/96` or custom)
- **Border Agent UDP port** (49191 IANA; configurable)
- **HDLC baud rate + flow control** (460800 + RTS/CTS)

## Failure modes

- **UART link lost**: host detects Spinel timeout → reset attempt with
  `SPINEL_CMD_RESET` → if NCP doesn't respond, toggle reset line GPIO.
- **NCP crash**: NCP's reboot triggers unsolicited `LAST_STATUS=RESET`.
  Host must flush pending state and re-initialize.
- **WiFi drops**: host continues to serve Spinel (NCP unaware).
  Re-advertise NAT64 prefix when WiFi comes back.
- **Thread partition**: NCP detects via OT, reports via IPV6_ADDRESS_TABLE
  changes (OMR prefix changes).

## Comparison to alternatives

| Approach | Host RAM | Dev effort | Maintenance |
|----------|----------|------------|-------------|
| This: C6 NCP + C6 host | ~120KB | Weeks (custom code) | We maintain |
| Linux `otbr-agent` host | N/A | Hours | Upstream |
| ESP-IDF TBR (abandoned) | - | - | Unreliable NAT64 |
| Zephyr BR on S3 N16R8 | Doesn't fit | - | - |
| 2× ESP32-S3 | Fits | Weeks (same code) | We maintain |

The C6+C6 design is the smallest-footprint Zephyr-only path at the cost
of writing our own Spinel client.
