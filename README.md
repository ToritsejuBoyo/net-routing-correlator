# IPsec VPN & BGP/OSPF Flap Log Correlator (`net-routing-correlator`)

[![tests](https://github.com/ToritsejuBoyo/net-routing-correlator/actions/workflows/tests.yml/badge.svg)](https://github.com/ToritsejuBoyo/net-routing-correlator/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)](CONTRIBUTING.md)
[![Security](https://img.shields.io/badge/security-read--only%20%7C%20no%20egress-informational.svg)](SECURITY.md)
[![Standard](https://img.shields.io/badge/standard-agentskills.io-blueviolet.svg)](https://agentskills.io)

> Takes the syslog from both ends of a site-to-site tunnel, aligns their clocks, merges them into
> one timeline, and answers the question you actually have at 02:00: **which side broke, at which
> layer, and what do I change on each box.** Ranked hypotheses with their evidence, the test that
> settles each one, and the rollback for every command it suggests.

---

## Who this is for

Network engineers, NOC analysts and network security engineers holding an intermittent site-to-site
VPN where the two ends are different vendors, and frequently different organisations.

## Why reading the log by hand fails

The symptom and the cause are logged by different devices, at different layers, with clocks that
disagree, and the symptom is louder:

```text
Feb 11 02:00:00  HQ      %IKEV2-5-OSAL_REKEY: SA rekey initiated for peer 203.0.113.42
Feb 11 02:00:02  HQ      %CRYPTO-4-RECVD_PKT_INV_SPI: invalid spi ... CHILD_SA_NOT_FOUND
Feb 11 02:00:03  HQ      %CRYPTO-5-SESSION_STATUS: Crypto tunnel is DOWN
Feb 11 02:00:04  HQ      %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.2 4/0 (hold time expired)
Feb 11 02:00:04  HQ      %BGP-5-ADJCHANGE: neighbor 10.255.0.2 Down     <-- the ticket says this
```

The ticket is raised on the last line. The cause is on the first, three seconds earlier, on a
different protocol. And the branch FortiGate's copy of the same four seconds carries a timestamp
three seconds out, because its NTP drifted.

## What it does

| Step | What it establishes |
| :--- | :--- |
| **Clock skew** | Measures the offset between the two peers from events both logged, with a confidence and a spread. If the anchors disagree, it says so and refuses to reorder the timeline. |
| **Merged timeline** | One ordered stream from six timestamp conventions and seven vendor dialects. |
| **Incidents** | Events grouped by quiet gaps, so four flaps are four incidents, not one wall of text. |
| **Causal chains** | Ordered strictly downward through the stack. IPsec teardown can cause a BGP drop; a BGP drop can never cause an IPsec teardown, so the reverse is never asserted. |
| **Periodicity** | Drops whose spacing clusters on one interval are a **timer**; scattered drops are a **path**. The two have no fix in common. |
| **Direction** | A BGP hold-timer expiry restated relative to the tunnel, so one failure logged at both ends counts once, in one direction. |
| **Ranked hypotheses** | With evidence, confidence, the test that settles it, per-vendor CLI, and the rollback. |

## The distinctions it refuses to blur

**BGP code 4, sent vs received.** `NOTIFICATION sent` means this router stopped *receiving* -
inbound path broken. `received` means the peer stopped receiving from us - outbound path broken.
Those are faults on different equipment. A report that says only "BGP flapped" has discarded the
single most useful bit in the log.

**OSPF dead timer vs ExStart hang.** Hellos are small and multicast; Database Description packets
go out at full interface MTU. Small packets failing means the path is down. Small packets passing
while large ones fail means MTU. These are never merged, and `ip ospf mtu-ignore` is never
recommended - it suppresses the check, not the drops.

**Timer faults vs path faults.** Measured, not guessed, and never claimed from fewer than three
drops.

## Install

```bash
git clone https://github.com/ToritsejuBoyo/net-routing-correlator.git
cd net-routing-correlator
python tests/validate-skill.py      # 89 known-answer checks
```

No dependencies. Python 3.10+ and the standard library only.

## Usage

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

## Example

```text
## 2. Clock alignment

- Estimated offset: +2.99 s (peer B relative to peer A)
- Confidence: high from 12 matched event(s), spread 0.07 s
- Correction applied to the timeline below: yes

## 3. Ranked hypotheses

| # | Confidence   | Layer   | Hypothesis                                                  |
| 1 | high (0.85)  | ipsec   | Drops align with the SA lifetime: rekey is failing or the   |
|   |              |         | two lifetimes differ                                        |
| 2 | medium (0.72)| routing | BGP hold timer expired - and the log says which direction   |
|   |              |         | broke                                                       |

## 4. Flap periodicity

- Drops counted: 4        (not 8 - the same drop seen by both peers is counted once)
- Repeat interval: ~3600 s
- Matches: 1 hour (common phase-2 lifetime)
```

## Supported log dialects

Cisco IOS / IOS-XE, Cisco ASA, Fortinet FortiGate, Palo Alto PAN-OS, Juniper Junos,
strongSwan / Linux, MikroTik RouterOS. Timestamps: ISO 8601 with or without offset, RFC 3164 BSD
syslog, FortiGate `date=`/`time=` headers, RouterOS `mmm/dd/yyyy`, epoch seconds, and Cisco's
leading `*` for an unsynchronised clock - which the report flags, because those timestamps are
uptime wearing a wall clock's clothes.

## Safety posture

- **Read-only and offline.** Never contacts a router, firewall or syslog collector. No sockets, no
  name resolution.
- **Credentials die on ingest.** Pre-shared keys, BGP MD5 passwords, SNMP communities, Cisco
  type-5/7/8/9 hashes and API tokens are removed before a line is stored, so no output format can
  leak one. There is no flag to disable this.
- **Indicators survive.** Peer addresses, interface names and MACs are the evidence an engineer
  greps for.
- **Proposes, never applies.** Every remediation ships with its rollback and a warning where the
  change itself will reset the adjacency you are reaching the far end through.

## Limits

- **A log records what a device chose to write.** Packets dropped by a carrier in between appear in
  neither peer's log - only as silence.
- **Correlation inside a window is not causation.** Two events a second apart may share a cause
  rather than be one.
- **A lifetime mismatch is a correlation to test, not a proven cause.** RFC 7296 makes rekeying
  unilateral and most modern stacks tolerate unequal lifetimes. The report says this where it
  matters and prefers the far less contested fix - disabling kilobyte-based rekeying - first.
- **One peer's log cannot establish direction.** The report says so rather than guessing.

## Test coverage

| Suite | Checks | Covers |
| :--- | :--- | :--- |
| `tests/validate-skill.py` | 89 | Known-answer conclusions per fixture scenario, timestamp dialects, redaction contract, direction attribution, causal-chain ordering, restraint under thin evidence, CLI behaviour, pattern safety, skill packaging |
| `tests/sanitizer_conformance_test.py` | 17 | Library-wide credential/PII redaction contract |
| `tests/extreme_stress_matrix.py` | 16 | ~47 hostile payloads: malformed input, encodings, NUL bytes, ReDoS, injection, 50k-event scale, determinism, leak contract |

Status is published by CI on every push across Python 3.10-3.13 on Linux, macOS and Windows.

## Repository structure

```text
net-routing-correlator/
├── SKILL.md
├── scripts/
│   ├── correlate-routing-logs.py            # Correlation engine (run this first)
│   └── sanitizer.py                         # Shared credential/PII redaction floor
├── references/
│   └── ike-bgp-ospf-state-matrix.md         # Notify codes, FSM subcodes, MTU tables, timers
├── assets/
│   └── routing-rca-report-template.md       # RCA and change-execution template
└── tests/
    ├── validate-skill.py
    ├── sanitizer_conformance_test.py
    ├── extreme_stress_matrix.py
    └── fixtures/                            # Synthetic logs (no real network data)
```

All fixtures are synthetic and use RFC 5737 documentation address space. No real network, customer
or device data is included.

## License

MIT. See [LICENSE](LICENSE).
