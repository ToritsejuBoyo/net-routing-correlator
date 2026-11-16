---
name: net-routing-correlator
description: >-
  Correlates IPsec VPN (IKEv1/IKEv2) and BGP/OSPF syslog from both ends of a site-to-site tunnel
  across Cisco IOS-XE/ASA, FortiGate, Palo Alto, Juniper, strongSwan and MikroTik RouterOS.
  Estimates clock skew between the two peers, merges them into one timeline, chains causality from
  IPsec teardown to routing adjacency loss, measures flap periodicity to separate a timer fault from
  a path fault, and emits ranked hypotheses with per-vendor remediation and rollback. Use when a
  site-to-site VPN drops intermittently, when BGP or OSPF adjacencies flap over a tunnel, when an
  OSPF neighbour sticks in ExStart or Exchange, when a tunnel comes up and then fails under load, or
  when two vendors' logs have to be reconciled to work out which end is at fault.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only; never contacts a router, firewall or syslog collector
---

# IPsec VPN and BGP/OSPF Flap Log Correlator (`net-routing-correlator`)

## Purpose and target roles

For **network engineers, NOC analysts and network security engineers** holding a site-to-site tunnel
that drops intermittently, where the two ends are different vendors and often different
organisations.

The hard part of this incident is not reading the log. It is that the symptom and the cause are
logged by different devices, at different layers, with clocks that disagree, and the symptom is
louder. `BGP-5-ADJCHANGE: neighbor Down Hold Timer Expired` appears four times an hour and says
nothing about the phase 2 rekey three seconds earlier that caused it.

## Operating rules and safety guardrails

1. **Read-only, offline, no egress.** The engine reads one or two log files and writes a report. It
   never contacts a device, never resolves a name, never opens a socket.
2. **Credentials are removed on ingest, not on output.** Pre-shared keys, BGP MD5 passwords, SNMP
   communities, Cisco type-5/7/8/9 hashes and API tokens are redacted before a line is stored, so
   no output format can leak one. There is no flag to turn this off: a routing log forwarded to a
   partner with a PSK in it cannot be unsent.
3. **Peer addresses, interface names and MACs are preserved.** They are the evidence an engineer
   greps for. A report that redacts them is unusable.
4. **Align the clocks before reading the timeline.** Correlating two logs whose clocks disagree
   produces confident, specific and wrong conclusions. The engine measures the offset from events
   both peers logged and states its confidence; when it cannot, it says so and declines to reorder.
5. **Rank hypotheses; never assert a single root cause.** Several of these failure modes are
   genuinely ambiguous from logs alone. Every hypothesis therefore carries its evidence and the one
   test that would settle it.
6. **Every remediation ships with its rollback.** Several of the changes proposed - tunnel MTU, OSPF
   timers, BGP router-id - reset the adjacency as they are applied. If the engineer is reaching the
   far end through that tunnel, they will lose it. Say so before they type it.
7. **Never recommend `ip ospf mtu-ignore` as a fix.** It suppresses the check, not the drops. The
   oversized packets are still being discarded; the failure has only been made quieter.

## Running the correlator

```bash
# Both ends - always prefer this
python scripts/correlate-routing-logs.py \
  --peer-a-log ./hq-asr1001.log \
  --peer-b-log ./branch-fortigate.log \
  --peer-a-label hq-asr1001 --peer-b-label branch-fgt

# One end only, with its timezone declared and the syslog year supplied
python scripts/correlate-routing-logs.py -a ./branch.log --peer-a-tz +02:00 --year 2026

# Structured output for a ticket system
python scripts/correlate-routing-logs.py -a ./hq.log -b ./branch.log -f json -o ./rca.json
```

`--window` sets how many seconds of quiet separate one incident from the next; raise it on
high-latency links. `--max-events` caps how many events are rendered per incident.

### Read-only commands for collecting fresh state

* **Cisco IOS-XE:** `show crypto ikev2 sa detailed`, `show crypto ipsec sa`, `show ip bgp summary`,
  `show ip ospf neighbor`, `show logging | include IKEV2|CRYPTO|BGP|OSPF|TUN`
* **Cisco ASA:** `show crypto ikev2 sa detail`, `show vpn-sessiondb l2l`, `show logging | include IKEV2|VPN`
* **FortiGate:** `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`,
  `get router info bgp summary`, `get router info ospf neighbor`
* **Juniper:** `show security ike security-associations detail`, `show bgp neighbor`, `show ospf neighbor`
* **strongSwan:** `swanctl --list-sas`, `journalctl -u strongswan --since "-6h"`
* **MikroTik RouterOS v7:** `/ip ipsec active-peers print detail`, `/routing bgp session print`,
  `/routing ospf neighbor print`, `/log print where topics~"ipsec|bgp|ospf"`

## How to read the report

### 1. Clock alignment, first and always

The report opens with the measured offset between the two peers and the confidence in it. If
confidence is `none` or `low`, stop: the cross-peer ordering below it is not evidence. Fix NTP, or
treat each peer's log separately.

A leading `*` on a Cisco timestamp means the clock has never synchronised. Those timestamps are
uptime wearing a wall clock's clothes and correlate with nothing.

### 2. Ranked hypotheses, each with its test

Confidence is this tool's opinion. The **test that settles it** is what resolves the incident, and
it is usually faster than the change it would justify. A DF-bit ping sweep takes thirty seconds and
removes all doubt about MTU; changing tunnel MTU on both peers takes a maintenance window.

### 3. Periodicity: the single most useful discriminator

Drops whose spacing clusters tightly around one interval are a **timer**. Drops at scattered
intervals are a **path**. The two have no fix in common, and treating one as the other burns a
window. The report measures this and refuses to claim it from fewer than three drops.

### 4. Direction, restated relative to the tunnel

A BGP `NOTIFICATION sent` with code 4 means this router stopped *receiving*. The same code
`received` means the peer stopped receiving from *us*. The engine restates every such line relative
to the tunnel rather than to the device that wrote it, so that one failure logged at both ends is
counted once, in one direction - not twice, in two.

### 5. OSPF: dead timer and ExStart are never the same fault

| Symptom | Packet size that failed | Meaning | Fix family |
| :--- | :--- | :--- | :--- |
| Dead timer expired | Hellos, small, multicast | The path stopped carrying traffic | Restore the path, check the SA, check multicast |
| Stuck in ExStart/Exchange | DBD packets at full interface MTU | Small packets pass, large ones do not | Match `ip mtu` on both ends, clamp TCP MSS |

Merging these loses the only information that distinguishes them.

## Diagnostic workflow

1. **Read section 1.** If clock confidence is not `high` or `medium`, fix that before anything else.
2. **Read section 4 (periodicity).** Timer or path. This decides which half of section 3 matters.
3. **Take the top hypothesis and run its test**, not its remediation.
4. **Check the causal chain** in section 5 for the incident. If an interface went down first,
   nothing above it in the stack is a root cause.
5. **Only then apply a change**, in a window, with the rollback to hand and out-of-band access
   confirmed.
6. Consult [`references/ike-bgp-ospf-state-matrix.md`](references/ike-bgp-ospf-state-matrix.md) to
   decode a notify code, an FSM subcode or an MTU overhead calculation the report did not cover.
7. Write the finding up with
   [`assets/routing-rca-report-template.md`](assets/routing-rca-report-template.md).

## What this skill cannot tell you

- **A log records what a device chose to write.** Packets dropped by a carrier in between appear in
  neither peer's log - only as silence.
- **Correlation inside a window is not causation.** Two events a second apart may share a cause
  rather than be one.
- **Absence of an event is not absence of a fault** when the two peers log at different levels,
  which they almost always do.
- **A lifetime mismatch is a correlation to test, not a proven cause.** RFC 7296 lets each peer
  rekey on its own schedule, and most modern stacks tolerate unequal lifetimes. Disabling
  kilobyte-based rekeying is the far less contested change; prefer it first.

## Bundled files

* [`scripts/correlate-routing-logs.py`](scripts/correlate-routing-logs.py) - the correlation engine.
  Run this first.
* [`scripts/sanitizer.py`](scripts/sanitizer.py) - the shared credential and PII redaction floor
  used across this skill library.
* [`references/ike-bgp-ospf-state-matrix.md`](references/ike-bgp-ospf-state-matrix.md) - IKEv2
  notify codes, OSPF neighbour state machine, BGP FSM error codes and subcodes, IPsec overhead and
  MTU/MSS tables, and per-vendor CLI equivalents.
* [`assets/routing-rca-report-template.md`](assets/routing-rca-report-template.md) - RCA and change
  execution template with the side-by-side peer parameter matrix.
* [`tests/validate-skill.py`](tests/validate-skill.py) - known-answer validation against synthetic
  fixtures whose correct conclusions are known by construction.
