# Changelog

All notable changes to `net-routing-correlator` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-16

First release. S16 / OP-14 of the it-ops-skills library.

### Added
- Offline two-peer correlation engine (`scripts/correlate-routing-logs.py`): six
  timestamp conventions and seven vendor dialects (Cisco IOS/IOS-XE, Cisco ASA,
  FortiGate, Palo Alto PAN-OS, Juniper Junos, strongSwan, MikroTik RouterOS)
  normalised into one UTC event stream.
- Clock-skew estimation between the two peers from events both of them logged,
  reported with a sample count, a spread and a confidence. A low-confidence
  estimate is stated and NOT applied, because reordering a timeline from a bad
  offset inverts cause and effect.
- Incident grouping by quiet gap, and causal chaining ordered strictly downward
  through the stack: IPsec teardown may explain a routing drop, never the reverse.
- Flap periodicity analysis separating a timer fault from a path fault, matched
  against common IKE and IPsec lifetimes, and declining to claim a period from
  fewer than three drops.
- Tunnel-relative direction attribution: a BGP hold-timer expiry logged as "sent"
  at one end and "received" at the other is one failure in one direction, counted
  once.
- Thirty-three detection rules across transport, IKE, IPsec, routing and forwarding
  layers, each carrying a plain-English meaning used in the report.
- Ranked hypotheses carrying evidence, a confidence score, the one discriminating
  test that settles them, per-vendor remediation CLI and the matching rollback.
- Reference material covering IKEv2 notify codes, OSPF neighbour state machine
  failures, BGP FSM error codes, RFC 4486 Cease subcodes, IPsec overhead and
  MTU/MSS tables, liveness timer coordination, and the evidence for and against
  the widely repeated "lifetime mismatch causes drops" claim.
- Test suites: 89 known-answer validation, 17 sanitization conformance, 16 extreme
  stress matrix.

### Security
- Read-only and offline: never contacts a router, firewall or syslog collector.
- Credentials are redacted on ingest rather than at render time, so no output
  format can leak one. Covers pre-shared keys, BGP MD5 passwords, SNMP
  communities, Cisco type-5/7/8/9 hashes, FortiGate `psksecret`, strongSwan
  `ipsec.secrets` lines and API tokens. There is no flag to disable it.
- Peer addresses, interface names and MACs are preserved because they are the
  evidence the report exists to carry.
- Every detection pattern is bounded; a ReDoS suite exercises each rule against
  pathological input.

### Notes
- Python floor is 3.10. Python 3.9 reached end of life in October 2025 and the
  test harness uses `sys.stdlib_module_names`.
