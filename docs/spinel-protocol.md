# Spinel Protocol Reference for NCP Host

Key Spinel properties and commands we need to handle on the host side. Full
spec: `third_party/openthread/src/lib/spinel/spinel.h`.

## Frame format

Spinel runs over HDLC framing:

```
[7E] [header] [command] [property] [payload ...] [CRC16] [7E]
```

- `7E` — HDLC flag byte (frame delimiter)
- Escaping: `7E`/`7D` in payload become `7D 5E` / `7D 5D`
- `header` byte: `[FLG:2][IID:2][TID:4]`
  - FLG: always `10b` (protocol version)
  - IID: interface ID (0 for single-interface)
  - TID: transaction ID (0 for async notifications, 1-15 for request/reply)
- `command`: one byte, see table below
- `property`: packed integer (variable-length), identifies the property
- `payload`: property-specific, packed types
- `CRC16`: HDLC CRC-16/X25 over header+command+property+payload

## Essential commands

| Cmd | Value | Direction | Purpose |
|-----|-------|-----------|---------|
| `PROP_VALUE_GET` | 2 | H→N | Read property value |
| `PROP_VALUE_SET` | 3 | H→N | Write property value |
| `PROP_VALUE_INSERT` | 4 | H→N | Append to list property |
| `PROP_VALUE_REMOVE` | 5 | H→N | Remove from list property |
| `PROP_VALUE_IS` | 6 | N→H | Response or async notification |
| `PROP_VALUE_INSERTED` | 7 | N→H | Async: item added to list |
| `PROP_VALUE_REMOVED` | 8 | N→H | Async: item removed |

## Properties we need (host-side handling)

### Framework

| Property | ID | Direction | Notes |
|----------|-----|-----------|-------|
| `LAST_STATUS` | 0 | N→H | Error/status code on any operation |
| `PROTOCOL_VERSION` | 1 | GET | Returns `(4, 3)` for Spinel 4.3 |
| `NCP_VERSION` | 2 | GET | Human-readable NCP info string |
| `INTERFACE_TYPE` | 3 | GET | `3` = Thread |
| `CAPS` | 5 | GET | List of capability IDs the NCP supports |
| `HWADDR` | 8 | GET | 64-bit factory MAC |

### Thread / IPv6 data plane

| Property | ID | Direction | Purpose |
|----------|-----|-----------|---------|
| `STREAM_NET` | 0x70 | Both | IPv6 packets (Thread traffic) |
| `STREAM_NET_INSECURE` | 0x71 | Both | IPv6 packets, skip MAC security |
| `IPV6_ADDRESS_TABLE` | 0x60 | INSERT/REMOVE async | Thread interface addresses (for host to mirror on its net_if) |
| `THREAD_ON_MESH_NETS` | 0x51 | INSERT async | On-mesh prefixes (for routing) |
| `THREAD_OFF_MESH_ROUTES` | 0x52 | INSERT async | External routes |

### Border routing (Thread 1.2+) — vendor extensions

Stock Spinel doesn't define these; OpenThread adds vendor properties:

| Property | Direction | Purpose |
|----------|-----------|---------|
| `INFRA_IF_STATE` | H→N | Host tells NCP about infra link state (up/down, prefix) |
| `INFRA_IF_RECV_ICMP6` | H→N | Host forwards received ND/RA from WiFi to NCP |
| `INFRA_IF_SEND_ICMP6` | N→H | NCP wants to send ND/RA on WiFi |
| `MDNS_REGISTER_SERVICE` | N→H | NCP's SRP server tells host to publish mDNS |
| `MDNS_SENT_PACKET` | H→N | Host notifies NCP of mDNS TX completion |
| `NAT64_CIDR` | H→N | Tell NCP the NAT64 prefix (64:ff9b::/96) |

Implementation detail: these vendor extensions are numbered in the
Spinel "extensions" range (`SPINEL_PROP_EXT__BEGIN` and up). Check
`third_party/openthread/src/lib/spinel/spinel.h` for exact IDs.

### Border Agent UDP forwarding

| Property | ID | Direction | Purpose |
|----------|-----|-----------|---------|
| `THREAD_UDP_FORWARD_STREAM` | 0x189 | Both | Tunnel arbitrary UDP to/from OT Border Agent |

When a Thread commissioner sends commissioning DTLS to Host's WiFi IP at
port 49191, host extracts UDP payload and sends via this stream to NCP.
NCP's Border Agent processes it; reply comes back via the same stream.

## Host-side state machine

```
[Boot]
  │
  ▼
[Wait for NCP reset]
  NCP sends PROP_VALUE_IS(LAST_STATUS, RESET) on boot
  │
  ▼
[Query capabilities]
  GET(PROTOCOL_VERSION, NCP_VERSION, CAPS)
  │
  ▼
[Register our infra interface]
  SET(INFRA_IF_STATE, {index=0, up=1, prefix=<WiFi prefix>})
  │
  ▼
[Activate data plane]
  SET(MAC_RAW_STREAM_ENABLED, 0)  -- we don't want raw MAC
  SET(NET_SAVED, 1)               -- let NCP keep dataset
  SET(NET_IF_UP, 1)
  SET(NET_STACK_UP, 1)
  │
  ▼
[Event loop]
  - Read Spinel frames from UART
  - Dispatch to handlers:
    * STREAM_NET → forward IPv6 pkt to net_recv_data on Zephyr stack
    * INFRA_IF_SEND_ICMP6 → send on WiFi net_if
    * MDNS_REGISTER_SERVICE → publish mDNS
    * THREAD_UDP_FORWARD_STREAM → forward to BA commissioner
  - Encode outbound:
    * Packets from net_send_data → STREAM_NET frame
    * WiFi ND/RA → INFRA_IF_RECV_ICMP6 frame
    * BA UDP from WiFi → THREAD_UDP_FORWARD_STREAM frame
```

## Minimum viable host

For Milestone A (just get Spinel link up), we only need:

- HDLC frame RX/TX over UART
- Encode `PROP_VALUE_GET` / decode `PROP_VALUE_IS`
- Handle `LAST_STATUS`, `NCP_VERSION`
- A shell command to query the NCP

That's maybe 400 LOC. Everything else builds on this foundation.

## References

- `third_party/openthread/src/lib/spinel/spinel.h` — Spinel constants, packed type format
- `third_party/openthread/src/lib/spinel/spinel.c` — pack/unpack helpers
- `third_party/openthread/src/lib/hdlc/hdlc.cpp` — HDLC encoder/decoder
- `third_party/openthread/src/posix/platform/*.cpp` — POSIX NCP host reference (what we're porting)
