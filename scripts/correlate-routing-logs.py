#!/usr/bin/env python3
"""
correlate-routing-logs.py - Offline IPsec VPN and BGP/OSPF flap log correlator.

READS ONLY. Never contacts a router, firewall, TACACS server or syslog collector.
It reads one or two log files from disk and writes a report. Nothing is applied.

What it does
------------
Takes the syslog of one or both ends of a site-to-site tunnel and answers the
question an engineer actually has at 02:00: *which side broke, at which layer,
and what do I change on each box.*

  1. Parses six timestamp conventions and five vendor log dialects into one
     normalised event stream (Cisco IOS/IOS-XE/ASA, FortiGate, Palo Alto,
     Juniper, strongSwan/charon, MikroTik RouterOS).
  2. Estimates the CLOCK SKEW between the two peers from events both of them
     logged, and states its confidence. Two routers whose NTP has drifted
     produce a timeline where the effect precedes the cause, so every
     correlation below is wrong until this is done.
  3. Merges both peers into one timeline and groups events into incidents
     using a time window.
  4. Chains causality inside an incident: IPsec SA teardown -> routing
     adjacency loss -> traffic loss, in that order and only in that order.
  5. Measures flap PERIODICITY. Drops whose spacing clusters tightly around a
     single interval are a timer, not a fault; drops at random spacing are a
     path problem. The two have opposite fixes.
  6. Emits RANKED HYPOTHESES WITH CONFIDENCE, each carrying the evidence that
     produced it, per-vendor remediation CLI, and the rollback for that CLI.

What it deliberately does not do
--------------------------------
It does not assert a single root cause. Several of the failure modes here are
genuinely ambiguous from logs alone - a rekey-aligned flap is consistent with a
lifetime mismatch, with a kilobyte-based lifesize rekey, and with an MTU
blackhole that only large post-rekey packets hit - so the output is a ranked
list with the discriminating test for each, not a verdict.

Direction matters and is reported
---------------------------------
For BGP, `NOTIFICATION sent` (hold timer expired, code 4) means THIS router
stopped hearing the peer: the inbound path is broken. `NOTIFICATION received`
with the same code means the peer stopped hearing this router: the outbound
path is broken. Those are different faults on different equipment, and a report
that says only "BGP flapped" has thrown away the single most useful bit in the
log.

For OSPF, a dead-timer expiry (hellos, 60-ish bytes, multicast) and an
ExStart/Exchange hang (DBD packets at full interface MTU) are never merged:
small packets failing means the path is down, large packets failing while small
ones pass means MTU, and the fixes do not overlap.

Exit codes: 0 report produced, 1 input unusable, 2 bad invocation.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from sanitizer import residual_scrub as _residual_scrub
    except ImportError:
        def _residual_scrub(text, skip=None):
            return text if isinstance(text, str) else ""

# IP addresses, peer identities and interface names are the evidence an engineer
# greps for; stripping them makes the report useless. Credentials - PSKs, BGP MD5
# passwords, SNMP communities, API tokens - are removed unconditionally.
_INDICATOR_CLASSES = frozenset({"ipv4", "ipv6", "mac-address", "guid", "email"})

MAX_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 1 * 1024 * 1024
DEFAULT_WINDOW = 5.0
DEFAULT_MAX_EVENTS = 400

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Credential redaction, applied before a line is stored anywhere
# ---------------------------------------------------------------------------

# Every quantifier below is bounded. An unbounded quantifier next to an
# alternation in a pattern that runs over attacker- or partner-supplied log text
# is a denial of service waiting for a long line.
_SECRET_PATTERNS = (
    # Cisco type-5 / 7 / 8 / 9 password hashes. This MUST be tried before the
    # generic key=value rule below, which would otherwise treat the lone type
    # digit as the secret and leave the hash itself in the clear - a redaction
    # that looks like it worked is worse than none, because nobody re-checks it.
    re.compile(r"(?i)\b(password|key)\s+(5|7|8|9)\s+(?!\[REDACTED)(\S{1,256})"),
    # key = value forms used by every vendor's config dump and debug output
    re.compile(
        r"(?i)\b(pre-?shared-?key|preshared|psk-?secret|ppk-?secret|psk|"
        r"passphrase|secret|password|passwd|pwd|"
        r"md5-?key|authentication-?key|auth-?key|community|snmp-community|"
        r"shared-?secret|key-?string|token|api-?key)"
        r"(\s*[:=]\s*|\s+)"
        r"(?!\[REDACTED)(?![5789]\s)(\"[^\"\n]{1,256}\"|'[^'\n]{1,256}'|\S{1,256})"
    ),
    # strongSwan ipsec.secrets style:  a.b.c.d : PSK "value"
    re.compile(r"(?i)\bPSK\s+(?!\[REDACTED)(\"[^\"\n]{1,256}\"|\S{1,256})"),
)


def redact_secrets(text):
    """
    Remove credentials from a log line.

    This runs on ingest, not on output, so a secret never reaches the event
    store, the JSON file or an exception message. A redaction applied only at
    render time is one `--format json` away from being skipped.
    """
    if not text:
        return ""
    out = text
    out = _SECRET_PATTERNS[0].sub(
        lambda m: "%s %s [REDACTED-SECRET]" % (m.group(1), m.group(2)), out)
    out = _SECRET_PATTERNS[1].sub(
        lambda m: "%s%s[REDACTED-SECRET]" % (m.group(1), m.group(2)), out)
    out = _SECRET_PATTERNS[2].sub("PSK [REDACTED-SECRET]", out)
    return out


def _scrub(text):
    return _residual_scrub(text or "", skip=_INDICATOR_CLASSES)


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

VENDOR_SIGNATURES = (
    ("cisco-asa", re.compile(r"%ASA-\d-\d{6}|%PIX-\d-\d{6}")),
    ("cisco-ios", re.compile(r"%(?:IKEV2|CRYPTO|BGP|OSPF|TUN|LINK|LINEPROTO|SYS|IPSEC)-\d+-[A-Z0-9_]{2,40}")),
    ("fortigate", re.compile(r"(?:devname=|devid=FG|logid=\d{10}|subtype=\"?(?:vpn|router|system)\"?)")),
    ("paloalto", re.compile(r"(?i)\b(?:PAN-OS|,(?:TRAFFIC|SYSTEM|GLOBALPROTECT),)|\bike-nego-p[12]\b")),
    ("juniper", re.compile(r"\b(?:kmd|rpd)\[\d{1,8}\]|\bRPD_(?:BGP|OSPF)_[A-Z_]{2,40}\b")),
    ("strongswan", re.compile(r"\bcharon\b|\bipsec\[\d{1,8}\]|\b(?:IKE_SA|CHILD_SA)\b")),
    ("mikrotik", re.compile(r"(?i)\b(?:ipsec|route,bgp|route,ospf|system,info)\s*,|\bRouterOS\b")),
)


def detect_vendor(line):
    for name, pattern in VENDOR_SIGNATURES:
        if pattern.search(line):
            return name
    return "generic"


VENDOR_LABELS = {
    "cisco-ios": "Cisco IOS / IOS-XE",
    "cisco-asa": "Cisco ASA",
    "fortigate": "Fortinet FortiGate",
    "paloalto": "Palo Alto PAN-OS",
    "juniper": "Juniper Junos",
    "strongswan": "strongSwan / Linux",
    "mikrotik": "MikroTik RouterOS",
    "generic": "Unrecognised syslog",
}


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# ISO 8601 / RFC 5424, with optional fractional seconds and optional offset.
_RE_ISO = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?"
)
# FortiGate key=value header: date=2026-02-11 time=14:03:11
_RE_FORTI = re.compile(
    r"date=(\d{4})-(\d{2})-(\d{2})\s+time=(\d{2}):(\d{2}):(\d{2})"
)
# RFC 3164 BSD syslog: Feb 11 14:03:11  (no year - the single worst design
# decision in operational logging, and the reason --year exists)
_RE_BSD = re.compile(
    r"\b([A-Za-z]{3})\s{1,2}(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
)
# MikroTik: feb/11/2026 14:03:11
_RE_MIKROTIK = re.compile(
    r"\b([A-Za-z]{3})/(\d{1,2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})"
)
# Cisco uptime-relative marker, e.g. *Feb 11 14:03:11.233: - handled by _RE_BSD,
# but a leading '*' means the clock is NOT authoritative (no NTP sync).
_RE_CISCO_UNSYNCED = re.compile(r"^\s*\*(?=[A-Za-z]{3}\s)")
# Bare epoch seconds, sometimes with milliseconds
_RE_EPOCH = re.compile(r"\beventtime=(\d{10,19})\b|\b(?:^|\s)(1[0-9]{9})(?:\.(\d{1,6}))?(?=\s)")


def _mk(year, month, day, hour, minute, second, frac=None, offset=None):
    micro = 0
    if frac:
        micro = int((frac + "000000")[:6])
    try:
        stamp = datetime(year, month, day, hour, minute, second, micro,
                         tzinfo=timezone.utc)
    except ValueError:
        return None
    if offset:
        stamp = stamp - offset
    return stamp


def _parse_offset(raw):
    if not raw or raw == "Z":
        return None
    sign = 1 if raw[0] == "+" else -1
    body = raw[1:].replace(":", "")
    if len(body) != 4 or not body.isdigit():
        return None
    return timedelta(minutes=sign * (int(body[:2]) * 60 + int(body[2:])))


def parse_timestamp(line, default_year, tz_offset_minutes=0):
    """
    Return (datetime_utc, precision_note) or (None, reason).

    Everything is normalised to UTC. A log whose timestamps carry no offset is
    assumed to be in the timezone given by --peer-a-tz / --peer-b-tz, defaulting
    to UTC - and the report says so, because a silent assumption here shifts the
    entire timeline by whole hours and quietly inverts cause and effect.
    """
    local = timedelta(minutes=tz_offset_minutes)

    match = _RE_FORTI.search(line)
    if match:
        stamp = _mk(int(match.group(1)), int(match.group(2)), int(match.group(3)),
                    int(match.group(4)), int(match.group(5)), int(match.group(6)),
                    None, local)
        if stamp:
            return stamp, "vendor-header"

    match = _RE_ISO.search(line)
    if match:
        explicit = _parse_offset(match.group(8))
        stamp = _mk(int(match.group(1)), int(match.group(2)), int(match.group(3)),
                    int(match.group(4)), int(match.group(5)), int(match.group(6)),
                    match.group(7), explicit if explicit is not None else
                    (None if match.group(8) == "Z" else local))
        if stamp:
            return stamp, "iso8601" if match.group(8) else "iso8601-no-offset"

    match = _RE_MIKROTIK.search(line)
    if match:
        month = _MONTHS.get(match.group(1).lower())
        if month:
            stamp = _mk(int(match.group(3)), month, int(match.group(2)),
                        int(match.group(4)), int(match.group(5)), int(match.group(6)),
                        None, local)
            if stamp:
                return stamp, "routeros"

    match = _RE_BSD.search(line)
    if match:
        month = _MONTHS.get(match.group(1).lower())
        if month:
            stamp = _mk(default_year, month, int(match.group(2)),
                        int(match.group(3)), int(match.group(4)), int(match.group(5)),
                        match.group(6), local)
            if stamp:
                note = "bsd-syslog-year-assumed"
                if _RE_CISCO_UNSYNCED.search(line):
                    note = "bsd-syslog-clock-unsynced"
                return stamp, note

    match = _RE_EPOCH.search(line)
    if match:
        raw = match.group(1) or match.group(2)
        if raw:
            value = int(raw)
            while value > 99999999999:  # nanoseconds / microseconds
                value //= 1000
            try:
                return datetime.fromtimestamp(value, tz=timezone.utc), "epoch"
            except (OverflowError, OSError, ValueError):
                pass

    return None, "no-timestamp"


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------

# Layers, ordered from the bottom of the stack upward. Causality may only flow
# from a lower layer to a higher one within an incident.
LAYERS = ("transport", "ike", "ipsec", "routing", "forwarding")
_LAYER_RANK = {name: index for index, name in enumerate(LAYERS)}


class Rule(object):
    __slots__ = ("event_id", "layer", "severity", "pattern", "meaning", "direction")

    def __init__(self, event_id, layer, severity, pattern, meaning, direction=None):
        self.event_id = event_id
        self.layer = layer
        self.severity = severity
        self.pattern = re.compile(pattern)
        self.meaning = meaning
        self.direction = direction


# direction: "inbound-broken"  - this router stopped receiving from the peer
#            "outbound-broken" - the peer stopped receiving from this router
#            None              - the log does not say
RULES = (
    # ---- transport / underlay --------------------------------------------
    Rule("IKE_NO_RESPONSE", "transport", "high",
         r"(?i)retransmit(?:ting)?\s+(?:IKE_SA_INIT|request|message)|"
         r"no\s+response\s+from\s+peer|"
         r"peer\s+not\s+responding\s+to\s+IKE|"
         r"giving\s+up\s+after\s+\d{1,3}\s+retransmit",
         "IKE packets left this router and nothing came back. UDP/500 or UDP/4500 "
         "is being dropped somewhere in the underlay, or the peer is down.",
         "outbound-broken"),
    Rule("NAT_T_DETECTED", "transport", "info",
         r"(?i)NAT[-_ ]?T\b|NAT[-_ ]detected|floating\s+to\s+(?:port\s+)?4500|"
         r"NAT_DETECTION_(?:SOURCE|DESTINATION)_IP",
         "NAT traversal is in use, so the tunnel is encapsulated in UDP/4500 and "
         "carries 8 bytes more overhead than raw ESP."),
    Rule("IFACE_DOWN", "transport", "high",
         r"(?i)%LINEPROTO-5-UPDOWN.{0,120}?changed\s+state\s+to\s+down|"
         r"%LINK-3-UPDOWN.{0,120}?changed\s+state\s+to\s+down|"
         r"\binterface\s+\S{1,40}\s+(?:is\s+)?down\b|link\s+down\b",
         "A physical or logical interface went down. If this precedes every other "
         "event in the incident, nothing above it is a root cause."),
    Rule("IFACE_ERRORS", "transport", "medium",
         r"(?i)\b(?:CRC|input\s+errors|output\s+drops|frame\s+errors|"
         r"carrier\s+transitions)\b.{0,40}?\d{1,12}|%LINK-4-ERROR",
         "Layer-1/2 errors on the WAN interface. These corrupt large frames far "
         "more often than small ones, which mimics an MTU problem."),
    Rule("PMTU_ICMP", "transport", "medium",
         r"(?i)fragmentation\s+needed|frag(?:mentation)?\s+required|"
         r"ICMP\s+type\s*3\s*code\s*4|packet\s+too\s+big|DF\s+bit\s+set",
         "Path MTU discovery signalling. Useful when present - but PMTUD failing "
         "silently is the common case, and silence does not appear in logs."),

    # ---- IKE phase 1 / phase 2 -------------------------------------------
    Rule("IKE_NO_PROPOSAL_CHOSEN", "ike", "high",
         r"(?i)NO_PROPOSAL_CHOSEN|no\s+proposal\s+chosen|"
         r"(?:IKE|phase\s*[12])\s+proposal\s+mismatch|"
         r"no\s+matching\s+(?:proposal|transform|policy)|"
         r"received\s+notify\s+(?:type\s+)?14\b",
         "RFC 7296 notify 14. The two peers share no common set of encryption, "
         "integrity, PRF and DH group - or PFS is on at one end and off at the other."),
    Rule("IKE_INVALID_KE", "ike", "medium",
         r"(?i)INVALID_KE_PAYLOAD|invalid\s+KE\s+payload|"
         r"received\s+notify\s+(?:type\s+)?17\b",
         "RFC 7296 notify 17. The initiator guessed a DH group the responder did "
         "not want. Harmless once - a loop of these means the group lists are "
         "ordered differently on each side."),
    Rule("IKE_AUTH_FAILED", "ike", "high",
         r"(?i)AUTHENTICATION_FAILED|authentication\s+fail(?:ed|ure)|"
         r"pre-?shared\s+key\s+mismatch|PSK\s+mismatch|"
         r"peer\s+ID\s+mismatch|received\s+notify\s+(?:type\s+)?24\b|"
         r"certificate\s+(?:verification\s+failed|expired)",
         "RFC 7296 notify 24. A wrong pre-shared key, a mismatched local/peer ID "
         "(common behind NAT, where one side sends an RFC 1918 address as its ID), "
         "or an expired certificate chain."),
    Rule("IKE_TS_UNACCEPTABLE", "ike", "high",
         r"(?i)TS_UNACCEPTABLE|traffic\s+selector(?:s)?\s+unacceptable|"
         r"proxy[- ]?ID\s+(?:mismatch|not\s+match)|"
         r"received\s+notify\s+(?:type\s+)?38\b|"
         r"failed\s+to\s+narrow\s+(?:traffic\s+selectors|TS)",
         "RFC 7296 notify 38. One peer is route-based (0.0.0.0/0 selectors), the "
         "other policy-based with narrow subnet pairs, or the subnet masks differ."),
    Rule("IKE_CHILD_SA_NOT_FOUND", "ike", "medium",
         r"(?i)CHILD_SA_NOT_FOUND|no\s+(?:child\s+)?SA\s+found|"
         r"invalid\s+SPI|received\s+notify\s+(?:type\s+)?34\b|"
         r"%CRYPTO-4-RECVD_PKT_INV_SPI",
         "The peer referenced an SA this router has already discarded. Classic "
         "symptom of simultaneous rekeying, or of one side tearing down early."),
    Rule("IKE_SA_UP", "ike", "info",
         r"(?i)IKE(?:v2)?\s+SA\s+(?:established|up)|"
         r"%IKEV2-5-(?:SA_UP|OSAL_INITIAL_UP)|"
         r"established\s+IKE_SA|phase\s*1\s+(?:complete|established)|"
         r"negotiate\s+IKE\s+SA\s+done",
         "Phase 1 came up. On its own this is good news; immediately after a "
         "teardown it is a flap, and the interval between the two is what "
         "distinguishes a timer from a path fault."),
    Rule("IKE_SA_DOWN", "ike", "high",
         r"(?i)IKE(?:v2)?\s+SA\s+(?:down|deleted|torn\s+down)|"
         r"%IKEV2-5-SA_DOWN|deleting\s+IKE_SA|"
         r"phase\s*1\s+(?:down|deleted)",
         "Phase 1 went down, which takes every child SA with it."),
    Rule("IKE_REKEY", "ike", "info",
         r"(?i)\brekey(?:ing|ed)?\b|CREATE_CHILD_SA|"
         r"%IKEV2-5-(?:CHILD_SA_UP|OSAL_REKEY)|"
         r"initiating\s+(?:IKE_SA|CHILD_SA)\s+rekey",
         "A scheduled rekey. On its own this is normal; aligned with a drop it is "
         "the single most informative event in the log."),
    Rule("DPD_TIMEOUT", "ike", "high",
         r"(?i)\bDPD\b.{0,40}?(?:timeout|fail|expire|retransmit)|"
         r"dead\s+peer\s+detection|peer\s+(?:is\s+)?(?:dead|unreachable)|"
         r"%IKEV2-5-(?:PEER_DOWN|OSAL_DPD)|liveness\s+check\s+fail",
         "Dead peer detection gave up. DPD probes are small, so a DPD timeout with "
         "no interface error means packets of ALL sizes stopped - not an MTU fault.",
         "inbound-broken"),
    Rule("IPSEC_SA_DOWN", "ipsec", "high",
         r"(?i)(?:IPsec|CHILD)[_ ]?SA\s+(?:deleted|down|expired|torn)|"
         r"%CRYPTO-5-(?:SESSION_STATUS|IPSEC_SETUP_FAILURE).{0,80}?(?:DOWN|FAIL)|"
         r"tunnel\s+(?:is\s+)?down|closing\s+CHILD_SA|"
         r"ipsec[- ]sa\s+(?:removed|deleted)",
         "The data-plane security association went away. Everything riding the "
         "tunnel loses its path at this instant."),
    Rule("IPSEC_SA_UP", "ipsec", "info",
         r"(?i)(?:IPsec|CHILD)[_ ]?SA\s+(?:established|installed|up)|"
         r"%CRYPTO-5-SESSION_STATUS.{0,80}?UP|"
         r"tunnel\s+(?:is\s+)?up|installed\s+CHILD_SA",
         "The data-plane security association was installed."),
    Rule("IPSEC_LIFESIZE", "ipsec", "medium",
         r"(?i)life(?:size|bytes)|kilobyte\s+(?:lifetime|rekey)|"
         r"volume[- ]based\s+rekey|\blifebytes\b",
         "Volume-based (kilobyte) rekeying is configured. Two peers almost never "
         "count the same number of bytes, so this rekeys at unpredictable times "
         "and is the usual cause of a flap that correlates with traffic, not clock."),

    # ---- BGP --------------------------------------------------------------
    Rule("BGP_HOLD_EXPIRED_LOCAL", "routing", "high",
         r"(?i)(?:notification\s+sent|sent\s+notification).{0,80}?"
         r"(?:hold\s+(?:time|timer)\s+expired|code\s*4\b|4/0)|"
         r"%BGP-3-NOTIFICATION:\s*sent.{0,80}?(?:4/0|hold\s+time)",
         "THIS router declared the hold timer expired and tore the session down. "
         "It stopped RECEIVING keepalives, so the broken direction is peer -> here.",
         "inbound-broken"),
    Rule("BGP_HOLD_EXPIRED_REMOTE", "routing", "high",
         r"(?i)(?:notification\s+received|received\s+notification).{0,80}?"
         r"(?:hold\s+(?:time|timer)\s+expired|code\s*4\b|4/0)|"
         r"%BGP-3-NOTIFICATION:\s*received.{0,80}?(?:4/0|hold\s+time)",
         "The PEER declared the hold timer expired. It stopped receiving our "
         "keepalives, so the broken direction is here -> peer.",
         "outbound-broken"),
    Rule("BGP_CEASE", "routing", "medium",
         r"(?i)(?:cease|code\s*6\b|6/\d)\b.{0,60}?"
         r"(?:administrativ|max(?:imum)?[- ]prefix|connection\s+(?:reject|collision)|"
         r"peer\s+de-?configured|out\s+of\s+resources|reset)|"
         r"%BGP-3-NOTIFICATION.{0,80}?\b6/\d\b",
         "RFC 4271 code 6 with an RFC 4486 subcode: an administrative or policy "
         "teardown, not a transport failure. Someone or something chose this."),
    Rule("BGP_MAX_PREFIX", "routing", "high",
         r"(?i)max(?:imum)?[- ]prefix.{0,60}?(?:exceed|limit|reach)|"
         r"%BGP-4-MAXPFX|prefix\s+limit\s+exceeded",
         "The peer advertised more prefixes than the configured limit. This is a "
         "policy decision firing, not a network fault - and it will repeat."),
    Rule("BGP_OPEN_STUCK", "routing", "high",
         r"(?i)\b(?:OpenSent|OpenConfirm)\b|"
         r"(?:bad\s+peer\s+AS|bad\s+BGP\s+identifier|unsupported\s+capability)|"
         r"%BGP-3-NOTIFICATION.{0,80}?\b2/\d\b",
         "The session never finished OPEN. A code-2 subcode names the exact "
         "disagreement: wrong remote-as, duplicate router-id, or a capability "
         "one side will not accept."),
    Rule("BGP_ADJ_DOWN", "routing", "high",
         r"(?i)%BGP-5-(?:ADJCHANGE|NBR_RESET).{0,120}?\bDown\b|"
         r"BGP\s+(?:neighbor|peer)\s+\S{1,60}\s+(?:went\s+)?[Dd]own|"
         r"bgp\s+session\s+(?:closed|down|torn)|"
         r"RPD_BGP_NEIGHBOR_STATE_CHANGED.{0,80}?\bIdle\b",
         "A BGP session dropped. This line records the fact, not the reason - "
         "the reason is in the NOTIFICATION logged beside it, and which side "
         "sent that notification is what names the failing direction."),
    Rule("BGP_ADJ_UP", "routing", "info",
         r"(?i)%BGP-5-ADJCHANGE.{0,120}?\bUp\b|"
         r"BGP\s+(?:neighbor|peer)\s+\S{1,60}\s+(?:is\s+)?[Uu]p\b|"
         r"bgp\s+session\s+established|"
         r"BGP[^\n]{0,60}?\bEstablished\b",
         "A BGP session came up. Paired with a drop, the gap between them is the "
         "outage the customer actually experienced, which is usually shorter "
         "than the ticket claims and longer than the router implies."),

    # ---- OSPF -------------------------------------------------------------
    Rule("OSPF_DEAD_EXPIRED", "routing", "high",
         r"(?i)%OSPF-5-ADJCHG.{0,160}?Dead\s+timer\s+expired|"
         r"dead\s+(?:timer|interval)\s+expired|"
         r"OSPF\s+neighbor\s+\S{1,60}\s+(?:is\s+)?down.{0,60}?dead",
         "Hellos stopped arriving for the whole dead interval. Hellos are small "
         "multicast packets, so this is a path or adjacency fault - NOT MTU.",
         "inbound-broken"),
    Rule("OSPF_EXSTART_STUCK", "routing", "high",
         r"(?i)\bEXSTART\b|\bEXCHANGE\b.{0,60}?(?:retransmi|stuck|loop)|"
         r"too\s+many\s+retransmissions|"
         r"%OSPF-5-ADJCHG.{0,160}?(?:ExStart|Exchange)",
         "The adjacency reached ExStart/Exchange and stopped. Hellos pass but "
         "Database Description packets, sent at full interface MTU, do not. This "
         "is an MTU problem until proven otherwise."),
    Rule("OSPF_MTU_MISMATCH", "routing", "high",
         r"(?i)%OSPF-4-(?:EXTER_MTU|ERRRCV).{0,120}?MTU|"
         r"MTU\s+mismatch|mismatched?\s+MTU|"
         r"received\s+(?:DBD|database\s+description).{0,60}?MTU\s+\d{3,5}",
         "OSPF carries the sender's interface MTU in the DBD header and refuses "
         "the adjacency when it exceeds the receiver's. The number in the log is "
         "the peer's MTU - set both ends to the smaller value."),
    Rule("OSPF_HELLO_PARAM_MISMATCH", "routing", "high",
         r"(?i)(?:hello|dead)\s+(?:interval|timer)\s+mismatch|"
         r"mismatch(?:ed)?\s+(?:hello|dead|area|netmask|option)|"
         r"%OSPF-4-(?:BADLSATYPE|ERRRCV).{0,120}?mismatch|"
         r"area\s+mismatch|authentication\s+(?:type\s+)?mismatch",
         "The two interfaces disagree on hello/dead intervals, area id, netmask "
         "or authentication. The adjacency can never form; it is not flapping, it "
         "has never worked."),
    Rule("OSPF_ADJ_UP", "routing", "info",
         r"(?i)%OSPF-5-ADJCHG.{0,160}?\bFULL\b|"
         r"OSPF\s+neighbor\s+\S{1,60}.{0,40}?\bFull\b|"
         r"RPD_OSPF_NBRUP",
         "An OSPF adjacency reached FULL, so hellos, DBD packets and LSAs all "
         "completed at least once. Any MTU limit in the path is above the size "
         "of the database that was exchanged, not below it."),
    Rule("OSPF_ADJ_DOWN", "routing", "high",
         r"(?i)%OSPF-5-ADJCHG.{0,160}?\bDown\b|"
         r"RPD_OSPF_NBRDOWN|OSPF\s+neighbor\s+\S{1,60}\s+down",
         "An OSPF adjacency dropped. The state it fell FROM matters: from FULL "
         "means an established neighbour was lost, from ExStart means it never "
         "got that far and the cause is a different one entirely."),

    # ---- forwarding -------------------------------------------------------
    Rule("TUNNEL_RECURSIVE", "forwarding", "critical",
         r"(?i)%TUN-5-RECURDOWN|recursive\s+rout|"
         r"tunnel\s+\S{1,40}\s+temporarily\s+disabled",
         "The route to the tunnel's own destination now points through the tunnel. "
         "The interface shuts itself down to break the loop, the route withdraws, "
         "the interface comes back, and the cycle repeats forever."),
    Rule("BFD_DOWN", "forwarding", "high",
         r"(?i)BFD.{0,60}?(?:session\s+)?(?:down|failed|DETECT_TIMEOUT)|"
         r"%BFD-5-(?:SESSION|NBRSTATE).{0,60}?DOWN",
         "BFD declared the path down. BFD fires in milliseconds, so it leads every "
         "protocol timer and is the earliest honest signal of a path loss."),
    Rule("ROUTE_WITHDRAWN", "forwarding", "medium",
         r"(?i)withdraw(?:n|ing)?\s+(?:route|prefix)|route\s+removed|"
         r"%ROUTING-4-(?:ROUTE|PREFIX)",
         "Prefixes left the table. Traffic loss starts here, not at the protocol "
         "event that caused it."),
)


# Events that both peers of a healthy tunnel log at roughly the same instant.
# These anchor the clock-skew estimate.
SKEW_ANCHORS = frozenset({
    "IKE_SA_UP", "IKE_SA_DOWN", "IPSEC_SA_UP", "IPSEC_SA_DOWN",
    "BGP_ADJ_UP", "BGP_ADJ_DOWN", "OSPF_ADJ_UP", "OSPF_ADJ_DOWN",
    "IKE_NO_PROPOSAL_CHOSEN", "IKE_TS_UNACCEPTABLE",
})

# Rekey intervals that appear in vendor defaults and in most templates.
KNOWN_LIFETIMES = (
    (600, "10 minutes"),
    (1800, "30 minutes (FortiGate phase-2 default)"),
    (3600, "1 hour (common phase-2 lifetime)"),
    (7200, "2 hours"),
    (14400, "4 hours"),
    (28800, "8 hours (common phase-1 lifetime)"),
    (86400, "24 hours"),
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _peer_subject(line):
    """Pull a peer address or neighbour id out of the line, if one is there."""
    match = re.search(r"(?i)\b(?:peer|neighbor|neighbour|remote-?ip|dst|gateway)"
                      r"[\s:=]+((?:\d{1,3}\.){3}\d{1,3})", line)
    if match:
        return match.group(1)
    match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", line)
    return match.group(1) if match else ""


def _mtu_values(line):
    """
    Collect EVERY MTU number on the line, not just the first.

    The OSPF message that matters names two of them - "Received DBD packet with
    MTU 1400 larger than interface MTU 1380" - and the disagreement between the
    two is the entire finding. Taking only the first throws away the half of the
    evidence that makes it a mismatch rather than a number.
    """
    found = []
    for raw in re.findall(r"(?i)\bMTU\s*(?:of|=|:)?\s*(\d{3,5})\b", line):
        value = int(raw)
        if 68 <= value <= 65535 and value not in found:
            found.append(value)
    return found


def parse_log(path, peer_label, default_year, tz_offset_minutes):
    """
    Read one peer's log into a list of classified events.

    Unmatched lines are counted but discarded. A 2 GB syslog is mostly interface
    counters and DHCP; carrying those in memory to print a summary of twelve
    events is how a triage tool becomes the thing you cannot run during an
    incident.
    """
    try:
        size = os.path.getsize(path)
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        # These three already have precise, actionable messages at the call
        # site. Flattening them into a generic ValueError would replace "no
        # such file" with "unusable", which tells the operator nothing.
        raise
    except OSError as exc:
        raise ValueError("cannot stat %s: %s" % (path, exc))
    if size > MAX_BYTES:
        raise ValueError("%s is %d bytes, above the %d byte safety limit"
                         % (path, size, MAX_BYTES))

    events = []
    stats = {
        "lines_read": 0,
        "lines_matched": 0,
        "lines_without_timestamp": 0,
        "lines_truncated": 0,
        "bytes": size,
    }
    vendors = {}
    unsynced = 0

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        for line_number, raw in enumerate(handle, start=1):
            stats["lines_read"] += 1
            if len(raw) > MAX_LINE_BYTES:
                raw = raw[:MAX_LINE_BYTES]
                stats["lines_truncated"] += 1
            line = raw.replace("\x00", "").strip()
            if not line:
                continue

            matched = [rule for rule in RULES if rule.pattern.search(line)]
            if not matched:
                continue
            stats["lines_matched"] += 1

            safe = redact_secrets(line)
            vendor = detect_vendor(line)
            vendors[vendor] = vendors.get(vendor, 0) + 1

            stamp, precision = parse_timestamp(line, default_year, tz_offset_minutes)
            if stamp is None:
                stats["lines_without_timestamp"] += 1
            if precision == "bsd-syslog-clock-unsynced":
                unsynced += 1

            # One line can satisfy several rules. Keep the most specific signal
            # by preferring the deepest layer and the highest severity, but
            # record every id so a hypothesis can match on any of them.
            primary = sorted(
                matched,
                key=lambda r: (_SEVERITY_RANK.get(r.severity, 0),
                               _LAYER_RANK.get(r.layer, 0)),
                reverse=True,
            )[0]

            events.append({
                "peer": peer_label,
                "line": line_number,
                "timestamp": stamp,
                "precision": precision,
                "vendor": vendor,
                "event_id": primary.event_id,
                "all_event_ids": sorted({rule.event_id for rule in matched}),
                "layer": primary.layer,
                "severity": primary.severity,
                "direction": primary.direction,
                "subject": _peer_subject(line),
                "mtu": _mtu_values(line),
                "text": safe,
            })

    stats["vendors"] = vendors
    stats["clock_unsynced_lines"] = unsynced
    return events, stats


_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


# ---------------------------------------------------------------------------
# Clock skew
# ---------------------------------------------------------------------------

def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def estimate_clock_skew(events_a, events_b, max_pair_gap=900.0):
    """
    Estimate how far peer B's clock is ahead of peer A's, in seconds.

    Method: for every anchor event in A, find the nearest-in-time anchor event in
    B carrying the same event id, and record the signed difference. Take the
    median of those differences, and measure the spread.

    Why the median and not the mean: a single pair matched across two unrelated
    incidents produces an outlier of minutes, and the mean follows it. Why the
    spread matters: if the differences do not agree with each other, the pairing
    itself is wrong and the estimate must be reported as unreliable rather than
    used to reorder the timeline.
    """
    anchors_b = {}
    for event in events_b:
        if event["event_id"] in SKEW_ANCHORS and event["timestamp"]:
            anchors_b.setdefault(event["event_id"], []).append(event["timestamp"])
    for key in anchors_b:
        anchors_b[key].sort()

    deltas = []
    pairs = []
    for event in events_a:
        if event["event_id"] not in SKEW_ANCHORS or not event["timestamp"]:
            continue
        candidates = anchors_b.get(event["event_id"])
        if not candidates:
            continue
        best = min(candidates, key=lambda t: abs((t - event["timestamp"]).total_seconds()))
        delta = (best - event["timestamp"]).total_seconds()
        if abs(delta) <= max_pair_gap:
            deltas.append(delta)
            pairs.append((event["event_id"], event["timestamp"], best, delta))

    if len(deltas) < 2:
        return {
            "offset_seconds": 0.0,
            "confidence": "none",
            "sample_count": len(deltas),
            "spread_seconds": None,
            "applied": False,
            "note": ("Not enough events appear in both logs to measure clock skew. "
                     "The timeline below is shown with each peer's own timestamps, "
                     "so ordering ACROSS peers may be wrong. Confirm NTP on both "
                     "ends before drawing conclusions from relative ordering."),
        }

    offset = _median(deltas)
    spread = max(deltas) - min(deltas)
    if spread <= 1.0:
        confidence = "high"
    elif spread <= 5.0:
        confidence = "medium"
    else:
        confidence = "low"

    applied = confidence in ("high", "medium") and abs(offset) >= 0.5
    if confidence == "low":
        note = ("Anchor events disagree by up to %.1f s, so the offset is an "
                "estimate only and has NOT been applied. Either the two logs cover "
                "different incidents or one clock is drifting, not merely offset."
                % spread)
    elif not applied:
        note = ("Clocks agree to within %.2f s. No correction applied." % abs(offset))
    else:
        direction = "ahead of" if offset > 0 else "behind"
        note = ("Peer B's clock is %.2f s %s peer A's, measured from %d event(s) "
                "logged by both. Peer B timestamps are shifted by -%.2f s to build "
                "the merged timeline." % (abs(offset), direction, len(deltas), offset))

    return {
        "offset_seconds": round(offset, 3),
        "confidence": confidence,
        "sample_count": len(deltas),
        "spread_seconds": round(spread, 3),
        "applied": applied,
        "note": note,
        "anchors": [
            {"event_id": eid, "peer_a": a.isoformat(), "peer_b": b.isoformat(),
             "delta_seconds": round(d, 3)}
            for eid, a, b, d in pairs[:10]
        ],
    }


# ---------------------------------------------------------------------------
# Timeline and incidents
# ---------------------------------------------------------------------------

def build_timeline(events_a, events_b, skew):
    """Merge both peers into one list ordered by corrected time."""
    merged = []
    shift = timedelta(seconds=skew["offset_seconds"]) if skew["applied"] else timedelta(0)

    for event in events_a:
        item = dict(event)
        item["aligned"] = event["timestamp"]
        merged.append(item)
    for event in events_b:
        item = dict(event)
        item["aligned"] = (event["timestamp"] - shift) if event["timestamp"] else None
        merged.append(item)

    dated = [e for e in merged if e["aligned"] is not None]
    undated = [e for e in merged if e["aligned"] is None]
    # Line number is the tie-break so that two events in the same second keep the
    # order the device wrote them in. Without it the output is non-deterministic
    # across runs, and a report you cannot diff is a report you cannot trust.
    dated.sort(key=lambda e: (e["aligned"], e["peer"], e["line"]))
    undated.sort(key=lambda e: (e["peer"], e["line"]))
    return dated, undated


def group_incidents(timeline, window_seconds):
    """
    Cut the timeline into incidents wherever there is a quiet gap.

    An incident is a run of events with no gap longer than the window. The window
    is deliberately an argument: a lab tunnel settles in under a second, a
    satellite link with a 600 ms RTT and a 40 s dead interval does not.
    """
    if not timeline:
        return []
    window = timedelta(seconds=window_seconds)
    incidents = []
    current = [timeline[0]]
    for event in timeline[1:]:
        if event["aligned"] - current[-1]["aligned"] <= window:
            current.append(event)
        else:
            incidents.append(current)
            current = [event]
    incidents.append(current)
    return incidents


def chain_causality(incident):
    """
    Order one incident's events into a cause -> effect chain.

    The rule is one-directional and deliberately crude: within an incident,
    a lower layer that fails before a higher layer is a candidate cause of it.
    The reverse is never asserted. OSPF dropping cannot cause an IPsec SA to be
    deleted, so a chain that claims it is wrong no matter how good the timing
    looks.
    """
    failures = [e for e in incident
                if e["severity"] in ("high", "critical") and e["layer"] != "forwarding"]
    failures += [e for e in incident
                 if e["severity"] in ("high", "critical") and e["layer"] == "forwarding"]
    chain = []
    seen_layers = set()
    for event in sorted(failures, key=lambda e: (e["aligned"], _LAYER_RANK.get(e["layer"], 0))):
        rank = _LAYER_RANK.get(event["layer"], 0)
        if chain:
            previous_rank = _LAYER_RANK.get(chain[-1]["layer"], 0)
            if rank < previous_rank:
                # A lower layer failing after a higher one is a consequence
                # being logged late, not a new cause. Keep it in the incident,
                # out of the chain.
                continue
        if event["layer"] in seen_layers and event["event_id"] == chain[-1]["event_id"]:
            continue
        seen_layers.add(event["layer"])
        chain.append(event)
    return chain


# ---------------------------------------------------------------------------
# Flap periodicity
# ---------------------------------------------------------------------------

FLAP_EVENTS = frozenset({
    "IPSEC_SA_DOWN", "IKE_SA_DOWN", "BGP_ADJ_DOWN", "OSPF_ADJ_DOWN",
    "BGP_HOLD_EXPIRED_LOCAL", "BGP_HOLD_EXPIRED_REMOTE", "OSPF_DEAD_EXPIRED",
    "DPD_TIMEOUT", "TUNNEL_RECURSIVE",
})


def analyse_periodicity(timeline, tolerance=0.10):
    """
    Decide whether the drops are on a timer or at random.

    Take the gaps between consecutive drop events and ask whether they cluster.
    A tight cluster means something fires on a schedule - a rekey, a lifetime, a
    cron job, a scheduled route refresh. Scattered gaps mean the path itself is
    unreliable.

    This distinction drives the whole report: a timer fault is fixed by changing
    a number in a config, a path fault is not, and treating one as the other
    wastes a maintenance window.
    """
    stamps = sorted(e["aligned"] for e in timeline
                    if e["event_id"] in FLAP_EVENTS and e["aligned"])
    # Collapse the same drop reported by both peers within two seconds.
    collapsed = []
    for stamp in stamps:
        if not collapsed or (stamp - collapsed[-1]).total_seconds() > 2.0:
            collapsed.append(stamp)

    result = {
        "drop_count": len(collapsed),
        "intervals_seconds": [],
        "periodic": False,
        "period_seconds": None,
        "matched_lifetime": None,
        "note": "",
    }
    if len(collapsed) < 3:
        result["note"] = ("Fewer than three drops in this capture, so periodicity "
                          "cannot be assessed. Collect a longer window before "
                          "ruling a timer in or out.")
        return result

    gaps = [round((b - a).total_seconds(), 2)
            for a, b in zip(collapsed, collapsed[1:]) if (b - a).total_seconds() > 0]
    result["intervals_seconds"] = gaps[:50]
    if len(gaps) < 2:
        result["note"] = "Too few intervals to assess periodicity."
        return result

    centre = _median(gaps)
    if not centre or centre <= 0:
        result["note"] = "Drops are simultaneous; no interval to measure."
        return result

    within = [g for g in gaps if abs(g - centre) <= centre * tolerance]
    ratio = len(within) / float(len(gaps))

    if ratio >= 0.7:
        result["periodic"] = True
        result["period_seconds"] = round(centre, 2)
        for seconds, label in KNOWN_LIFETIMES:
            if abs(centre - seconds) <= seconds * 0.15:
                result["matched_lifetime"] = {"seconds": seconds, "label": label}
                break
        if result["matched_lifetime"]:
            result["note"] = (
                "Drops repeat every ~%.0f s (%d of %d intervals within %d%%), which "
                "sits on %s. A drop that lands on a rekey boundary this reliably is "
                "a negotiation or lifetime problem, not a path problem. Note the "
                "limit of this evidence: the spacing alone cannot separate a "
                "lifetime mismatch from a rekey that fails for another reason, so "
                "the hypotheses below list both and give the test that separates them."
                % (centre, len(within), len(gaps), int(tolerance * 100),
                   result["matched_lifetime"]["label"]))
        else:
            result["note"] = (
                "Drops repeat every ~%.0f s (%d of %d intervals within %d%%). That "
                "is a timer somewhere, but it does not match a common IPsec "
                "lifetime. Check scheduled jobs, DHCP lease renewal on the WAN, and "
                "any carrier-side session timer before changing crypto settings."
                % (centre, len(within), len(gaps), int(tolerance * 100)))
    else:
        result["note"] = (
            "Intervals between drops are scattered (median %.0f s, only %d of %d "
            "within %d%%). Irregular drops point at the path - loss, interface "
            "errors, a flapping carrier circuit - rather than at a timer. Changing "
            "lifetimes will not help here."
            % (centre, len(within), len(gaps), int(tolerance * 100)))
    return result


# ---------------------------------------------------------------------------
# Hypotheses
# ---------------------------------------------------------------------------

def _fix(cisco=None, fortigate=None, mikrotik=None, strongswan=None, juniper=None):
    out = {}
    for key, value in (("Cisco IOS-XE", cisco), ("FortiGate", fortigate),
                       ("MikroTik RouterOS v7", mikrotik),
                       ("strongSwan", strongswan), ("Juniper Junos", juniper)):
        if value:
            out[key] = value
    return out


def _confidence_label(score):
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def canonical_direction(is_peer_a, direction):
    """
    Translate a log-relative direction into a tunnel-relative one.

    A router that logs "I stopped receiving" and its peer logging "the far end
    stopped receiving from me" are the SAME failure described from two desks. If
    both are counted naively, a one-way loss reads as a two-way loss and the
    report sends an engineer to the wrong box. Everything is therefore restated
    as the direction traffic was failing IN, relative to the tunnel itself.
    """
    if direction == "inbound-broken":
        return "toward_peer_a" if is_peer_a else "toward_peer_b"
    if direction == "outbound-broken":
        return "toward_peer_b" if is_peer_a else "toward_peer_a"
    return None


DIRECTION_LABELS = {
    "toward_peer_a": "peer B -> peer A",
    "toward_peer_b": "peer A -> peer B",
}


def build_hypotheses(counts, directions, periodicity, mtu_values, incidents, skew):
    """
    Produce ranked hypotheses.

    Each hypothesis carries:
      * a score, built from how many independent signals support it
      * the evidence that produced the score, so a reader can disagree
      * the ONE test that would confirm or kill it
      * remediation CLI per vendor, and the rollback for that CLI

    The discriminating test matters more than the ranking. Ranking is this
    tool's opinion; the test is what settles it.
    """
    found = []

    def add(key, title, layer, score, evidence, test, fixes, rollback, caveat=""):
        found.append({
            "id": key,
            "title": title,
            "layer": layer,
            "score": round(min(score, 0.98), 2),
            "confidence": _confidence_label(min(score, 0.98)),
            "evidence": evidence,
            "discriminating_test": test,
            "remediation": fixes,
            "rollback": rollback,
            "caveat": caveat,
        })

    def c(*ids):
        return sum(counts.get(i, 0) for i in ids)

    # --- recursive routing: unmistakable, so it outranks everything ---------
    if c("TUNNEL_RECURSIVE"):
        add("recursive-routing",
            "Recursive routing: the tunnel destination is being learned through the tunnel",
            "forwarding", 0.95,
            ["%d recursive-routing event(s) logged" % c("TUNNEL_RECURSIVE"),
             "This message is emitted only when the route to the tunnel destination "
             "resolves out of the tunnel interface itself"],
            "Check the routing table for the remote peer's public address while the "
            "tunnel is up. If its next hop is the tunnel interface, this is confirmed; "
            "no other evidence is needed.",
            _fix(
                cisco="ip route <PEER_PUBLIC_IP> 255.255.255.255 <WAN_NEXT_HOP>\n"
                      "router bgp <ASN>\n neighbor <PEER> route-map NO-PEER-PFX in",
                fortigate="config router static\n edit 0\n  set dst <PEER_PUBLIC_IP>/32\n"
                          "  set gateway <WAN_NEXT_HOP>\n  set device <WAN_IF>\n next\nend",
                mikrotik="/ip route add dst-address=<PEER_PUBLIC_IP>/32 "
                         "gateway=<WAN_NEXT_HOP> distance=1",
                juniper="set routing-options static route <PEER_PUBLIC_IP>/32 "
                        "next-hop <WAN_NEXT_HOP>",
            ),
            "Remove the static /32 host route you added:\n"
            "  Cisco:     no ip route <PEER_PUBLIC_IP> 255.255.255.255 <WAN_NEXT_HOP>\n"
            "  FortiGate: config router static / delete <id> / end\n"
            "  MikroTik:  /ip route remove [find dst-address=<PEER_PUBLIC_IP>/32]\n"
            "The tunnel returns to its previous flapping state; nothing else changes.",
            "The /32 must point at the physical WAN next hop. If the WAN next hop is "
            "itself learned dynamically, pin it or the loop returns on the next "
            "failover.")

    # --- phase 1 / phase 2 proposal mismatch -------------------------------
    if c("IKE_NO_PROPOSAL_CHOSEN"):
        score = 0.70 + min(0.2, 0.02 * c("IKE_NO_PROPOSAL_CHOSEN"))
        evidence = ["%d NO_PROPOSAL_CHOSEN notification(s)" % c("IKE_NO_PROPOSAL_CHOSEN")]
        if c("IKE_SA_UP") == 0:
            score += 0.05
            evidence.append("Phase 1 never came up in this capture, so the mismatch "
                            "is in phase 1 rather than in a child SA")
        else:
            evidence.append("Phase 1 did come up at least once, so the mismatch is "
                            "most likely in the phase 2 proposal or in PFS")
        add("proposal-mismatch",
            "IKE proposal mismatch (encryption, integrity, PRF, DH group or PFS)",
            "ike", score, evidence,
            "Put both peers' proposals side by side and compare all five fields. If "
            "phase 1 establishes and phase 2 does not, the difference is in the phase 2 "
            "transform set or in PFS being enabled on exactly one side.",
            _fix(
                cisco="crypto ikev2 proposal PROP-AES256\n encryption aes-cbc-256\n"
                      " integrity sha256\n group 14\n!\n"
                      "crypto ipsec transform-set TS-AES256 esp-aes 256 esp-sha256-hmac\n"
                      " mode tunnel\n!\n"
                      "show crypto ikev2 proposal     ! verify on BOTH peers",
                fortigate="config vpn ipsec phase1-interface\n edit <NAME>\n"
                          "  set proposal aes256-sha256\n  set dhgrp 14\n next\nend\n"
                          "config vpn ipsec phase2-interface\n edit <NAME>\n"
                          "  set proposal aes256-sha256\n  set pfs enable\n"
                          "  set dhgrp 14\n next\nend",
                mikrotik="/ip ipsec proposal set [find name=default] "
                         "enc-algorithms=aes-256-cbc auth-algorithms=sha256 pfs-group=modp2048\n"
                         "/ip ipsec profile set [find name=default] "
                         "enc-algorithm=aes256 hash-algorithm=sha256 dh-group=modp2048",
                strongswan="conn peer\n  ike=aes256-sha256-modp2048!\n"
                           "  esp=aes256-sha256-modp2048!",
            ),
            "Restore the previous proposal on the peer you changed, then clear the "
            "SA so it renegotiates with the old settings:\n"
            "  Cisco:     clear crypto ikev2 sa\n"
            "  FortiGate: diagnose vpn ike gateway clear name <NAME>\n"
            "  MikroTik:  /ip ipsec active-peers kill [find]\n"
            "Keep the old proposal text to hand BEFORE you change it; the tunnel will "
            "not come back on its own if you cannot reproduce it exactly.",
            "With AES-GCM do not also configure a separate integrity algorithm - GCM "
            "is an AEAD cipher and carries its own. Several vendors accept the "
            "configuration and then fail to negotiate.")

    # --- traffic selector mismatch -----------------------------------------
    if c("IKE_TS_UNACCEPTABLE"):
        add("traffic-selectors",
            "Traffic selector / proxy-ID mismatch between a route-based and a policy-based peer",
            "ike", 0.80,
            ["%d TS_UNACCEPTABLE notification(s)" % c("IKE_TS_UNACCEPTABLE"),
             "Phase 1 reached authentication, so credentials and proposals are "
             "already agreed - only the selectors are not"],
            "Compare the selectors each side offers. One peer offering 0.0.0.0/0 to "
            "0.0.0.0/0 while the other offers named subnets is conclusive.",
            _fix(
                cisco="interface Tunnel0\n ip address <TUN_IP> 255.255.255.252\n"
                      " tunnel mode ipsec ipv4\n tunnel protection ipsec profile <PROF>\n"
                      "! route-based VTI offers 0.0.0.0/0 selectors",
                fortigate="config vpn ipsec phase2-interface\n edit <NAME>\n"
                          "  set src-subnet 0.0.0.0 0.0.0.0\n"
                          "  set dst-subnet 0.0.0.0 0.0.0.0\n next\nend",
                mikrotik="/ip ipsec policy set [find peer=<PEER>] "
                         "src-address=0.0.0.0/0 dst-address=0.0.0.0/0 "
                         "tunnel=yes level=unique",
                strongswan="conn peer\n  leftsubnet=0.0.0.0/0\n  rightsubnet=0.0.0.0/0\n"
                           "  type=tunnel",
            ),
            "Put the original subnet pairs back on the peer you changed and clear the "
            "child SA. Moving a policy-based peer to 0.0.0.0/0 also changes which "
            "traffic is encrypted, so roll back promptly if the tunnel comes up but "
            "traffic goes the wrong way.",
            "Moving to 0.0.0.0/0 selectors changes the security policy, not just the "
            "negotiation. On a policy-based firewall it can send unintended traffic "
            "into the tunnel. Review the policy, not only the tunnel state.")

    # --- authentication -----------------------------------------------------
    if c("IKE_AUTH_FAILED"):
        add("authentication",
            "IKE authentication failure: pre-shared key, peer ID, or certificate",
            "ike", 0.82,
            ["%d authentication failure(s)" % c("IKE_AUTH_FAILED"),
             "Authentication failures repeat identically until a human changes "
             "something; they do not resolve on their own"],
            "Re-enter the pre-shared key on BOTH peers by typing it rather than "
            "pasting. If it still fails, compare the local and peer ID values - a "
            "peer behind NAT often sends an RFC 1918 address as its ID while the "
            "responder expects the public one.",
            _fix(
                cisco="crypto ikev2 keyring KR\n peer PEER\n  address <PEER_IP>\n"
                      "  pre-shared-key <NEW_KEY>\n!\n"
                      "crypto ikev2 profile PROF\n match identity remote address <PEER_IP>\n"
                      " identity local address <LOCAL_PUBLIC_IP>",
                fortigate="config vpn ipsec phase1-interface\n edit <NAME>\n"
                          "  set psksecret <NEW_KEY>\n  set localid <LOCAL_ID>\n"
                          "  set peerid <PEER_ID>\n next\nend",
                mikrotik="/ip ipsec identity set [find peer=<PEER>] "
                         "secret=<NEW_KEY> my-id=address:<LOCAL_PUBLIC_IP> "
                         "remote-id=address:<PEER_PUBLIC_IP>",
                strongswan="# /etc/ipsec.secrets\n"
                           "<LOCAL_PUBLIC_IP> <PEER_PUBLIC_IP> : PSK \"<NEW_KEY>\"",
            ),
            "Restore the previous key or ID settings from your configuration backup "
            "and clear the IKE SA. Take the backup BEFORE changing the key: on most "
            "platforms the stored secret cannot be read back once replaced.",
            "A trailing space or a smart quote introduced by copying a key out of a "
            "document produces exactly this error and is invisible in the config. "
            "Type the key rather than pasting it.")

    # --- rekey-aligned flap -------------------------------------------------
    if periodicity.get("periodic") and periodicity.get("matched_lifetime"):
        score = 0.60
        evidence = [periodicity["note"]]
        if c("IKE_REKEY"):
            score += 0.10
            evidence.append("%d explicit rekey event(s) in the same capture"
                            % c("IKE_REKEY"))
        if c("IKE_CHILD_SA_NOT_FOUND"):
            score += 0.15
            evidence.append("%d CHILD_SA_NOT_FOUND / invalid-SPI event(s): the two "
                            "peers disagree about which SA is current, which is what "
                            "a lifetime mismatch looks like from the inside"
                            % c("IKE_CHILD_SA_NOT_FOUND"))
        if c("IPSEC_LIFESIZE"):
            score += 0.10
            evidence.append("Volume-based (kilobyte) rekeying is referenced in the log")
        add("rekey-aligned-flap",
            "Drops align with the SA lifetime: rekey is failing or the two lifetimes differ",
            "ipsec", score, evidence,
            "Set the phase 2 lifetime on one peer to a clearly different value (for "
            "example 1800 s against 3600 s) and watch where the next drop lands. If "
            "the drop moves to the new interval, the rekey is the cause. If it stays "
            "where it was, something else fires on that schedule and the lifetime is "
            "innocent.",
            _fix(
                cisco="crypto ipsec security-association lifetime seconds 3600\n"
                      "no crypto ipsec security-association lifetime kilobytes\n"
                      "crypto ikev2 profile PROF\n lifetime 28800",
                fortigate="config vpn ipsec phase2-interface\n edit <NAME>\n"
                          "  set keylifeseconds 3600\n  set keylife-type seconds\n"
                          " next\nend",
                mikrotik="/ip ipsec proposal set [find name=default] lifetime=1h\n"
                         "/ip ipsec profile set [find name=default] lifetime=8h",
                strongswan="conn peer\n  ikelifetime=8h\n  lifetime=1h\n"
                           "  margintime=9m\n  rekeyfuzz=100%",
            ),
            "Return both peers to their original lifetime values. Lifetime changes "
            "take effect at the next rekey, not immediately, so verify at the next "
            "interval rather than assuming the rollback worked.",
            "Whether a lifetime MISMATCH by itself causes drops is genuinely "
            "contested: RFC 7296 lets each peer rekey on its own schedule, and most "
            "modern stacks handle unequal lifetimes without dropping traffic. Treat "
            "the mismatch as a strong correlation to test, not as a proven cause - "
            "and prefer disabling kilobyte-based rekeying first, which is far less "
            "disputed.")
    elif periodicity.get("periodic"):
        add("periodic-non-crypto",
            "Drops are on a timer that is not an IPsec lifetime",
            "transport", 0.50,
            [periodicity["note"]],
            "Compare the drop interval against the WAN DHCP lease time, any PPPoE "
            "session timer, scheduled backups, and the carrier's own session limits. "
            "The matching interval names the owner.",
            _fix(cisco="show dhcp lease\nshow pppoe session\nshow archive config",
                 fortigate="get system interface physical\ndiagnose debug application "
                           "dhcpc -1\nshow system auto-script",
                 mikrotik="/ip dhcp-client print detail\n/system scheduler print"),
            "No configuration change is proposed here, so there is nothing to roll "
            "back. These are read-only commands.",
            "")

    # --- MTU / ExStart ------------------------------------------------------
    mtu_signal = c("OSPF_EXSTART_STUCK", "OSPF_MTU_MISMATCH")
    if mtu_signal:
        score = 0.72
        evidence = []
        if c("OSPF_MTU_MISMATCH"):
            score += 0.15
            evidence.append("%d explicit MTU mismatch message(s) from OSPF"
                            % c("OSPF_MTU_MISMATCH"))
        if c("OSPF_EXSTART_STUCK"):
            evidence.append("%d adjacency stall(s) in ExStart/Exchange: hellos are "
                            "being exchanged but Database Description packets are not"
                            % c("OSPF_EXSTART_STUCK"))
        if c("OSPF_DEAD_EXPIRED") == 0:
            score += 0.05
            evidence.append("No dead-timer expiry in the same capture, so small "
                            "packets are getting through while large ones are not - "
                            "the signature of an MTU limit rather than a path loss")
        if len(set(mtu_values)) > 1:
            score += 0.08
            evidence.append("Conflicting MTU values seen in the logs: %s"
                            % ", ".join(str(v) for v in sorted(set(mtu_values))))
        if c("NAT_T_DETECTED"):
            evidence.append("NAT-T is active, adding 8 bytes of UDP overhead on top "
                            "of ESP")
        add("mtu-exstart",
            "OSPF stuck in ExStart/Exchange: interface MTU mismatch or large-packet blackhole",
            "routing", score, evidence,
            "Ping across the tunnel with the DF bit set, sweeping the size: if 1300 "
            "bytes succeeds and 1450 fails, the path MTU is between them and this is "
            "confirmed. Do this before changing anything - it takes thirty seconds "
            "and removes all doubt.",
            _fix(
                cisco="interface Tunnel0\n ip mtu 1400\n ip tcp adjust-mss 1360\n"
                      " ip ospf network point-to-point\n"
                      "! apply identically on BOTH peers",
                fortigate="config system interface\n edit <TUNNEL_IF>\n"
                          "  set mtu-override enable\n  set mtu 1400\n next\nend\n"
                          "config firewall policy\n edit <ID>\n"
                          "  set tcp-mss-sender 1360\n  set tcp-mss-receiver 1360\n"
                          " next\nend",
                mikrotik="/interface ipip set [find name=<TUNNEL_IF>] mtu=1400\n"
                         "/ip firewall mangle add chain=forward protocol=tcp "
                         "tcp-flags=syn action=change-mss new-mss=1360 "
                         "out-interface=<TUNNEL_IF>",
                juniper="set interfaces st0.0 family inet mtu 1400\n"
                        "set security flow tcp-mss ipsec-vpn mss 1360",
            ),
            "Restore the previous MTU and MSS values on both peers:\n"
            "  Cisco:     interface Tunnel0 / no ip mtu 1400 / no ip tcp adjust-mss 1360\n"
            "  FortiGate: set mtu-override disable\n"
            "  MikroTik:  /interface set [find name=<TUNNEL_IF>] mtu=1500\n"
            "Changing MTU resets the adjacency, so expect one controlled flap in each "
            "direction - apply it in a window, not during the incident.",
            "Do NOT reach for 'ip ospf mtu-ignore'. It makes the adjacency form by "
            "suppressing the check, and the oversized packets that were being dropped "
            "are still being dropped - you have hidden the fault, not fixed it, and "
            "the next symptom will be a partial LSDB rather than a clean failure.")

    # --- OSPF dead timer ----------------------------------------------------
    if c("OSPF_DEAD_EXPIRED"):
        score = 0.65
        evidence = ["%d dead-timer expiry event(s): hellos stopped for a full dead "
                    "interval" % c("OSPF_DEAD_EXPIRED")]
        if c("IPSEC_SA_DOWN") or c("IKE_SA_DOWN"):
            score += 0.18
            evidence.append("An IPsec SA went down in the same incident, which "
                            "removes the path the hellos were using - the OSPF event "
                            "is downstream of it")
        if c("OSPF_EXSTART_STUCK") == 0:
            evidence.append("No ExStart stall in this capture, so this is a loss of "
                            "the path rather than an MTU limit")
        add("ospf-dead-timer",
            "OSPF dead timer expired: hellos stopped arriving",
            "routing", score, evidence,
            "Hellos are small and multicast. Confirm whether multicast 224.0.0.5 "
            "survives the tunnel by watching the OSPF packet counters on both ends, "
            "and check whether the IPsec SA was present for the whole interval.",
            _fix(
                cisco="interface Tunnel0\n ip ospf network point-to-point\n"
                      " ip ospf hello-interval 10\n ip ospf dead-interval 40\n"
                      "! match BOTH values on both peers",
                fortigate="config router ospf\n config ospf-interface\n edit <NAME>\n"
                          "  set network-type point-to-point\n"
                          "  set hello-interval 10\n  set dead-interval 40\n"
                          " next\n end\nend",
                mikrotik="/routing ospf interface-template set [find interfaces=<IF>] "
                         "type=ptp hello-interval=10s dead-interval=40s",
            ),
            "Restore the original hello and dead intervals on both peers. Timer "
            "changes drop the adjacency the moment they are applied, in both "
            "directions.",
            "If the IPsec SA was also down, fix that first and re-check. Changing "
            "OSPF timers to mask a tunnel that is not passing traffic produces an "
            "adjacency that stays up while forwarding nothing, which is harder to "
            "diagnose than the original fault.")

    # --- OSPF parameter mismatch -------------------------------------------
    if c("OSPF_HELLO_PARAM_MISMATCH"):
        add("ospf-parameters",
            "OSPF interface parameters disagree: the adjacency cannot form at all",
            "routing", 0.85,
            ["%d parameter mismatch message(s)" % c("OSPF_HELLO_PARAM_MISMATCH"),
             "A parameter mismatch is not intermittent. If this is present, the "
             "adjacency has never worked, and anything you were treating as a flap "
             "is a separate problem"],
            "Compare hello interval, dead interval, area id, network mask, network "
            "type and authentication on both interfaces. Exactly one will differ.",
            _fix(
                cisco="show ip ospf interface Tunnel0\n"
                      "! compare hello/dead/area/mask/type against the peer",
                fortigate="get router info ospf interface <IF>",
                mikrotik="/routing ospf interface-template print detail",
            ),
            "These are read-only commands; nothing to roll back. Any change you then "
            "make to align the parameters should be reverted by restoring the prior "
            "value on the interface you changed.",
            "")

    # --- BGP directionality -------------------------------------------------
    inbound = directions.get("toward_peer_a", 0)
    outbound = directions.get("toward_peer_b", 0)
    if c("BGP_HOLD_EXPIRED_LOCAL", "BGP_HOLD_EXPIRED_REMOTE"):
        if inbound and not outbound:
            direction_text = ("Every liveness failure points the same way: traffic "
                              "failing in the direction %s. Investigate peer B's "
                              "transmit path and peer A's receive path; peer A's "
                              "transmit path is not implicated by this evidence."
                              % DIRECTION_LABELS["toward_peer_a"])
            score = 0.72
        elif outbound and not inbound:
            direction_text = ("Every liveness failure points the same way: traffic "
                              "failing in the direction %s. Investigate peer A's "
                              "transmit path and peer B's receive path."
                              % DIRECTION_LABELS["toward_peer_b"])
            score = 0.72
        elif inbound and outbound:
            direction_text = ("Liveness failures point BOTH ways (%d toward peer A, "
                              "%d toward peer B) after restating each log line "
                              "relative to the tunnel rather than to the device that "
                              "wrote it. A genuinely bidirectional loss is consistent "
                              "with the tunnel going away, not with one-way loss on a "
                              "single transit path." % (inbound, outbound))
            score = 0.68
        else:
            direction_text = ("The log does not say which side sent the notification, "
                              "so the failing direction is unknown. Capture "
                              "'show ip bgp neighbor' from both ends next time.")
            score = 0.45
        evidence = [direction_text]
        if c("IPSEC_SA_DOWN"):
            evidence.append("An IPsec SA teardown is present in the same incident; "
                            "BGP losing a session that rides that SA is the expected "
                            "consequence, not an independent fault")
        add("bgp-hold-timer",
            "BGP hold timer expired - and the log says which direction broke",
            "routing", score, evidence,
            "If keepalives (small) fail while the tunnel is up, the path is down. If "
            "keepalives survive and the session drops only during a full table "
            "exchange, the large UPDATE packets are hitting a path MTU limit - test "
            "with a DF-bit ping sweep before touching timers.",
            _fix(
                cisco="router bgp <ASN>\n neighbor <PEER> timers 10 30\n"
                      " neighbor <PEER> fall-over bfd\n"
                      "interface Tunnel0\n ip tcp adjust-mss 1360",
                fortigate="config router bgp\n config neighbor\n edit <PEER>\n"
                          "  set keep-alive-timer 10\n  set holdtime-timer 30\n"
                          "  set bfd enable\n next\n end\nend",
                mikrotik="/routing bgp connection set [find remote.address=<PEER>] "
                         "keepalive-time=10s hold-time=30s",
                juniper="set protocols bgp group <G> neighbor <PEER> hold-time 30",
            ),
            "Restore the original timers on both ends. Hold-time is negotiated to the "
            "lower of the two values at session setup, so a change takes effect only "
            "after the session resets - the rollback will itself bounce the session.",
            "Shortening timers makes a flap detectable sooner; it does not make the "
            "path work. If you shorten them without fixing the path you will simply "
            "flap faster.")

    # --- BGP cease / max prefix --------------------------------------------
    if c("BGP_MAX_PREFIX"):
        add("bgp-max-prefix",
            "BGP maximum-prefix limit exceeded: the session was torn down by policy",
            "routing", 0.88,
            ["%d maximum-prefix event(s)" % c("BGP_MAX_PREFIX"),
             "This is a configured limit firing, not a network fault. It will "
             "re-fire on every reconnect until either the limit or the advertisement "
             "changes"],
            "Read the peer's advertised prefix count against the configured limit. "
            "The two numbers settle it with no further testing.",
            _fix(
                cisco="router bgp <ASN>\n neighbor <PEER> maximum-prefix <N> 80 restart 15",
                fortigate="config router bgp\n config neighbor\n edit <PEER>\n"
                          "  set maximum-prefix <N>\n  set maximum-prefix-threshold 80\n"
                          " next\n end\nend",
                mikrotik="/routing bgp connection set [find remote.address=<PEER>] "
                         "input.limit-process-routes-ipv4=<N>",
            ),
            "Restore the previous limit. Raising a maximum-prefix limit to stop an "
            "alarm removes the protection it was there to provide, so change it only "
            "once you know WHY the peer's advertisement grew.",
            "A sudden jump in prefix count is sometimes a misconfiguration or a leak "
            "at the far end. Raising the limit without asking makes you carry it.")

    if c("BGP_CEASE") and not c("BGP_MAX_PREFIX"):
        add("bgp-cease",
            "BGP Cease notification: an administrative teardown, not a transport failure",
            "routing", 0.60,
            ["%d Cease notification(s) (RFC 4271 code 6)" % c("BGP_CEASE"),
             "A Cease is sent deliberately. Something or someone chose to reset this "
             "session; the network did not drop it"],
            "Read the RFC 4486 subcode in the message and correlate the timestamp "
            "against change records and scheduled jobs on both ends.",
            _fix(cisco="show logging | include BGP-3-NOTIFICATION\nshow archive log config all",
                 fortigate="execute log filter category 1\nexecute log display",
                 mikrotik="/log print where topics~\"bgp\"\n/system history print"),
            "Read-only commands; nothing to roll back.",
            "")

    if c("BGP_OPEN_STUCK"):
        add("bgp-open",
            "BGP session never left OPEN: a parameter disagreement, not a flap",
            "routing", 0.80,
            ["%d OPEN-stage event(s)" % c("BGP_OPEN_STUCK"),
             "The TCP session is forming, so the path works. The two routers "
             "disagree about remote-as, router-id or a capability"],
            "Compare the local-as and remote-as on both ends, then the router-id. A "
            "duplicate or unset router-id produces this immediately.",
            _fix(
                cisco="router bgp <ASN>\n bgp router-id <UNIQUE_IP>\n"
                      " neighbor <PEER> remote-as <CORRECT_ASN>",
                fortigate="config router bgp\n set router-id <UNIQUE_IP>\n"
                          " config neighbor\n edit <PEER>\n  set remote-as <CORRECT_ASN>\n"
                          " next\n end\nend",
                mikrotik="/routing bgp connection set [find remote.address=<PEER>] "
                         "remote.as=<CORRECT_ASN> router-id=<UNIQUE_IP>",
            ),
            "Restore the previous ASN or router-id. Changing a router-id resets every "
            "BGP session on the device, not just this one - do it in a window.",
            "")

    # --- DPD / transport ----------------------------------------------------
    if c("DPD_TIMEOUT", "IKE_NO_RESPONSE"):
        score = 0.55
        evidence = []
        if c("DPD_TIMEOUT"):
            evidence.append("%d DPD timeout(s): liveness probes, which are small, "
                            "stopped being answered" % c("DPD_TIMEOUT"))
        if c("IKE_NO_RESPONSE"):
            score += 0.15
            evidence.append("%d IKE retransmission(s) with no reply: UDP/500 or "
                            "UDP/4500 is not reaching the peer, or its replies are "
                            "not reaching here" % c("IKE_NO_RESPONSE"))
        if c("IFACE_DOWN"):
            score += 0.12
            evidence.append("An interface went down in the same window, which "
                            "explains the loss without any crypto fault")
        if c("IFACE_ERRORS"):
            evidence.append("Interface errors are present; layer 1/2 loss corrupts "
                            "large frames preferentially and can mimic an MTU fault")
        add("dpd-transport",
            "Peer liveness lost: the underlay stopped carrying IKE/ESP",
            "transport", score, evidence,
            "From each peer, source a ping from the WAN interface to the other peer's "
            "public address, and check whether UDP/500 and UDP/4500 are permitted "
            "end to end. Small packets failing rules MTU out entirely.",
            _fix(
                cisco="show crypto ikev2 sa detailed\nshow interface <WAN> | include error\n"
                      "ping <PEER_PUBLIC_IP> source <WAN>\n"
                      "! permit udp any host <LOCAL_PUBLIC_IP> eq 500 4500 on the WAN ACL",
                fortigate="diagnose vpn ike gateway list\n"
                          "execute ping-options source <WAN_IP>\nexecute ping <PEER_PUBLIC_IP>\n"
                          "diagnose sniffer packet <WAN_IF> 'udp port 500 or udp port 4500' 4",
                mikrotik="/ip ipsec active-peers print detail\n"
                         "/ping <PEER_PUBLIC_IP> src-address=<WAN_IP>\n"
                         "/ip firewall filter print where dst-port=500,4500",
                strongswan="swanctl --list-sas\nip -s link show <WAN_IF>",
            ),
            "These are read-only commands. If you add a firewall rule to permit "
            "UDP/500 and UDP/4500, remove that rule to roll back - and note that "
            "removing it will drop the tunnel again.",
            "A stateful NAT device in front of either peer can expire the UDP/4500 "
            "mapping during idle periods. If drops follow quiet periods rather than "
            "a clock, raise DPD frequency or enable NAT keepalives before changing "
            "anything in the crypto configuration.")

    # --- clock integrity ----------------------------------------------------
    if skew.get("confidence") in ("none", "low") or skew.get("unsynced_lines"):
        found.append({
            "id": "clock-integrity",
            "title": "Clock alignment between the two peers is unverified",
            "layer": "transport",
            "score": 0.40,
            "confidence": "medium",
            "evidence": [skew.get("note", "")],
            "discriminating_test": "Run 'show ntp status' (Cisco), 'diagnose sys ntp "
                                   "status' (FortiGate) or '/system ntp client print' "
                                   "(MikroTik) on both peers and confirm both are "
                                   "synchronised to the same stratum source.",
            "remediation": _fix(
                cisco="ntp server <NTP_IP>\nclock timezone UTC 0\nservice timestamps "
                      "log datetime msec year localtime show-timezone",
                fortigate="config system ntp\n set ntpsync enable\n"
                          " set server-mode disable\nend\n"
                          "config system global\n set timezone 00\nend",
                mikrotik="/system ntp client set enabled=yes servers=<NTP_IP>\n"
                         "/system clock set time-zone-name=UTC",
            ),
            "rollback": "Revert the NTP server and timezone to their previous values. "
                        "Note that correcting a clock will make future logs "
                        "discontinuous with past ones.",
            "caveat": "Correlating two logs whose clocks disagree produces confident, "
                      "specific and wrong conclusions. Fix this before trusting any "
                      "cross-peer ordering above.",
        })

    found.sort(key=lambda h: (-h["score"], h["id"]))
    return found


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _ts(value):
    if value is None:
        return "unknown"
    return value.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def correlate(events_a, events_b, stats_a, stats_b, window, max_events,
              label_a, label_b):
    skew = estimate_clock_skew(events_a, events_b)
    skew["unsynced_lines"] = (stats_a.get("clock_unsynced_lines", 0)
                              + stats_b.get("clock_unsynced_lines", 0))

    timeline, undated = build_timeline(events_a, events_b, skew)
    incidents = group_incidents(timeline, window)
    periodicity = analyse_periodicity(timeline)

    counts = {}
    directions = {}
    mtu_values = []
    for event in timeline + undated:
        for event_id in event["all_event_ids"]:
            counts[event_id] = counts.get(event_id, 0) + 1
        if event["direction"]:
            canon = canonical_direction(event["peer"] == label_a, event["direction"])
            if canon:
                directions[canon] = directions.get(canon, 0) + 1
        if event["mtu"]:
            mtu_values.extend(event["mtu"])

    hypotheses = build_hypotheses(counts, directions, periodicity, mtu_values,
                                  incidents, skew)

    incident_summaries = []
    for index, incident in enumerate(incidents, start=1):
        chain = chain_causality(incident)
        peers = sorted({e["peer"] for e in incident})
        incident_summaries.append({
            "index": index,
            "start": incident[0]["aligned"],
            "end": incident[-1]["aligned"],
            "duration_seconds": round(
                (incident[-1]["aligned"] - incident[0]["aligned"]).total_seconds(), 2),
            "event_count": len(incident),
            "peers": peers,
            "both_peers": len(peers) > 1,
            "chain": chain,
            "events": incident,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "peer_labels": {"a": label_a, "b": label_b},
        "window_seconds": window,
        "max_events": max_events,
        "ingest": {"a": stats_a, "b": stats_b},
        "clock_skew": skew,
        "periodicity": periodicity,
        "event_counts": counts,
        "direction_counts": directions,
        "incidents": incident_summaries,
        "undated_events": undated,
        "hypotheses": hypotheses,
        "timeline": timeline,
    }


_RULE_BY_ID = {rule.event_id: rule for rule in RULES}


def render_markdown(report, max_events):
    out = []
    add = out.append
    label_a = report["peer_labels"]["a"]
    label_b = report["peer_labels"]["b"]

    add("# IPsec VPN and BGP/OSPF Flap Correlation Report")
    add("")
    add("Generated %s. Read-only analysis of log files; no device was contacted."
        % report["generated_utc"])
    add("")

    # --- ingest -------------------------------------------------------------
    add("## 1. What was read")
    add("")
    add("| Peer | Lines read | Lines classified | Without timestamp | Vendors seen |")
    add("| :--- | ---: | ---: | ---: | :--- |")
    for key, label in (("a", label_a), ("b", label_b)):
        stats = report["ingest"][key]
        if not stats:
            continue
        vendors = ", ".join(
            "%s (%d)" % (VENDOR_LABELS.get(name, name), count)
            for name, count in sorted(stats.get("vendors", {}).items(),
                                      key=lambda kv: -kv[1])) or "none"
        add("| %s | %d | %d | %d | %s |"
            % (label, stats.get("lines_read", 0), stats.get("lines_matched", 0),
               stats.get("lines_without_timestamp", 0), vendors))
    add("")
    if not report["ingest"]["b"]:
        add("> Only one peer's log was supplied. Clock skew cannot be measured, "
            "direction of failure cannot be established from a single side, and any "
            "conclusion about which end is at fault is a guess. Supply the other "
            "peer's log when you can get it.")
        add("")

    # --- clock --------------------------------------------------------------
    skew = report["clock_skew"]
    add("## 2. Clock alignment")
    add("")
    add("- Estimated offset: **%+.2f s** (peer B relative to peer A)"
        % skew["offset_seconds"])
    add("- Confidence: **%s** from %d matched event(s)%s"
        % (skew["confidence"], skew["sample_count"],
           ", spread %.2f s" % skew["spread_seconds"]
           if skew["spread_seconds"] is not None else ""))
    add("- Correction applied to the timeline below: **%s**"
        % ("yes" if skew["applied"] else "no"))
    add("")
    add(skew["note"])
    add("")
    if skew.get("unsynced_lines"):
        add("> %d log line(s) carry a leading `*`, which on Cisco platforms means the "
            "clock has never synchronised to NTP. Those timestamps are device uptime "
            "dressed up as wall clock and cannot be correlated with anything."
            % skew["unsynced_lines"])
        add("")

    # --- hypotheses ---------------------------------------------------------
    add("## 3. Ranked hypotheses")
    add("")
    substantive = [h for h in report["hypotheses"] if h["id"] != "clock-integrity"]
    if not substantive:
        # Saying nothing here would leave the clock-integrity note looking like a
        # finding about the incident. It is not: there is no finding.
        add("No classified failure events were found in these logs. Either the "
            "incident is outside the captured window, or the logging level is too "
            "low to record negotiation detail. Raise the level and re-capture.")
        add("")
    if report["hypotheses"]:
        add("These are ranked by weight of evidence, not asserted as fact. Each one "
            "names the test that would confirm or kill it; run the test before "
            "changing a production device.")
        add("")
        add("| # | Confidence | Layer | Hypothesis |")
        add("| ---: | :--- | :--- | :--- |")
        for index, item in enumerate(report["hypotheses"], start=1):
            add("| %d | %s (%.2f) | %s | %s |"
                % (index, item["confidence"], item["score"], item["layer"],
                   item["title"]))
        add("")
        for index, item in enumerate(report["hypotheses"], start=1):
            add("### %d. %s" % (index, item["title"]))
            add("")
            add("**Confidence:** %s (%.2f)  **Layer:** %s"
                % (item["confidence"], item["score"], item["layer"]))
            add("")
            add("**Evidence**")
            add("")
            for line in item["evidence"]:
                if line:
                    add("- %s" % line)
            add("")
            add("**Test that settles it**")
            add("")
            add(item["discriminating_test"])
            add("")
            if item["remediation"]:
                add("**Remediation by vendor**")
                add("")
                for vendor, block in item["remediation"].items():
                    add("*%s*" % vendor)
                    add("")
                    add("```")
                    add(block)
                    add("```")
                    add("")
            add("**Rollback**")
            add("")
            add(item["rollback"])
            add("")
            if item["caveat"]:
                add("**Caveat**")
                add("")
                add(item["caveat"])
                add("")

    # --- periodicity --------------------------------------------------------
    period = report["periodicity"]
    add("## 4. Flap periodicity")
    add("")
    add("- Drops counted: **%d**" % period["drop_count"])
    if period["period_seconds"]:
        add("- Repeat interval: **~%.0f s**" % period["period_seconds"])
    if period["matched_lifetime"]:
        add("- Matches: **%s**" % period["matched_lifetime"]["label"])
    add("")
    add(period["note"])
    add("")
    if period["intervals_seconds"]:
        add("Intervals between drops, in seconds: `%s`"
            % ", ".join("%.0f" % g for g in period["intervals_seconds"][:20]))
        add("")

    # --- incidents ----------------------------------------------------------
    add("## 5. Incidents and causal chains")
    add("")
    if not report["incidents"]:
        add("No timestamped events to group.")
        add("")
    for incident in report["incidents"][:20]:
        add("### Incident %d - %s, %d event(s) over %.1f s"
            % (incident["index"], _ts(incident["start"]), incident["event_count"],
               incident["duration_seconds"]))
        add("")
        if incident["both_peers"]:
            add("Both peers logged events in this incident.")
        else:
            add("Only %s logged events in this incident. A fault seen at one end and "
                "not the other is itself evidence: it points at the receive path of "
                "the silent peer, or at its logging level."
                % incident["peers"][0])
        add("")
        if incident["chain"]:
            add("**Causal chain** (lower layers first; this ordering is asserted only "
                "downward through the stack):")
            add("")
            for step, event in enumerate(incident["chain"], start=1):
                rule = _RULE_BY_ID.get(event["event_id"])
                add("%d. `%s` **%s** on %s - %s"
                    % (step, _ts(event["aligned"]), event["event_id"], event["peer"],
                       rule.meaning if rule else ""))
            add("")
        add("| Time (UTC) | Peer | Layer | Event | Log line |")
        add("| :--- | :--- | :--- | :--- | :--- |")
        for event in incident["events"][:max_events]:
            add("| %s | %s | %s | `%s` | `%s` |"
                % (_ts(event["aligned"]), event["peer"], event["layer"],
                   event["event_id"], _md_cell(event["text"])))
        if len(incident["events"]) > max_events:
            add("| ... | | | | %d more event(s) suppressed; raise --max-events |"
                % (len(incident["events"]) - max_events))
        add("")

    if len(report["incidents"]) > 20:
        add("> %d further incident(s) were found and are present in the JSON output."
            % (len(report["incidents"]) - 20))
        add("")

    # --- undated ------------------------------------------------------------
    section = 6
    if report["undated_events"]:
        add("## %d. Events with no usable timestamp" % section)
        section += 1
        add("")
        add("%d classified event(s) carried no parseable timestamp and were left out "
            "of the timeline. They are real events; they simply cannot be ordered."
            % len(report["undated_events"]))
        add("")
        add("| Peer | Line | Event | Log line |")
        add("| :--- | ---: | :--- | :--- |")
        for event in report["undated_events"][:50]:
            add("| %s | %d | `%s` | `%s` |"
                % (event["peer"], event["line"], event["event_id"],
                   _md_cell(event["text"])))
        add("")

    # --- limits -------------------------------------------------------------
    add("## %d. What this report cannot tell you" % section)
    add("")
    add("- **A log records what a device decided to write, not what happened on the "
        "wire.** Packets dropped by an intermediate carrier appear in neither peer's "
        "log; they appear only as silence.")
    add("- **Correlation inside a time window is not causation.** Two events a second "
        "apart in a five-second window may share a cause rather than be one.")
    add("- **Absence of an event is not absence of a fault** when logging levels "
        "differ between the two peers, which they almost always do.")
    add("- **Apply nothing from section 3 outside a maintenance window** unless you "
        "have out-of-band access to the far end. Several of the changes above - MTU, "
        "OSPF timers, BGP router-id - reset the adjacency as they are applied, and "
        "if you are reaching the remote device through this tunnel you will lose it.")
    add("")

    return "\n".join(out) + "\n"


def _md_cell(text):
    """Keep a log line inside one Markdown table cell."""
    cleaned = (text or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    cleaned = re.sub(r"`", "'", cleaned)
    if len(cleaned) > 220:
        cleaned = cleaned[:217] + "..."
    return cleaned


def to_json(report, max_events):
    def event_json(event):
        return {
            "peer": event["peer"],
            "line": event["line"],
            "timestamp": event["timestamp"].isoformat() if event["timestamp"] else None,
            "aligned": (event["aligned"].isoformat()
                        if event.get("aligned") else None),
            "precision": event["precision"],
            "vendor": event["vendor"],
            "event_id": event["event_id"],
            "all_event_ids": event["all_event_ids"],
            "layer": event["layer"],
            "severity": event["severity"],
            "direction": event["direction"],
            "subject": event["subject"],
            "mtu": event["mtu"],
            "text": event["text"],
        }

    out = {
        "schema_version": report["schema_version"],
        "generated_utc": report["generated_utc"],
        "peer_labels": report["peer_labels"],
        "window_seconds": report["window_seconds"],
        "ingest": report["ingest"],
        "clock_skew": report["clock_skew"],
        "periodicity": report["periodicity"],
        "event_counts": report["event_counts"],
        "direction_counts": report["direction_counts"],
        "hypotheses": report["hypotheses"],
        "incidents": [
            {
                "index": incident["index"],
                "start": incident["start"].isoformat() if incident["start"] else None,
                "end": incident["end"].isoformat() if incident["end"] else None,
                "duration_seconds": incident["duration_seconds"],
                "event_count": incident["event_count"],
                "peers": incident["peers"],
                "both_peers": incident["both_peers"],
                "chain": [event_json(e) for e in incident["chain"]],
                "events": [event_json(e) for e in incident["events"][:max_events]],
            }
            for incident in report["incidents"]
        ],
        "undated_events": [event_json(e) for e in report["undated_events"][:200]],
    }
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _tz_minutes(value):
    """Accept +HH:MM, -HH:MM, +HHMM, HH, or a bare number of minutes."""
    if value is None:
        return 0
    raw = str(value).strip()
    if not raw:
        return 0
    match = re.match(r"^([+-]?)(\d{1,2}):?(\d{2})?$", raw)
    if not match:
        raise argparse.ArgumentTypeError(
            "timezone offset must look like +02:00, -0500 or 0, not %r" % value)
    sign = -1 if match.group(1) == "-" else 1
    hours = int(match.group(2))
    minutes = int(match.group(3) or 0)
    if hours > 14 or minutes > 59:
        raise argparse.ArgumentTypeError("timezone offset out of range: %r" % value)
    return sign * (hours * 60 + minutes)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="correlate-routing-logs.py",
        description="Correlate IPsec VPN and BGP/OSPF syslog from one or both ends "
                    "of a tunnel into a ranked, evidence-carrying RCA report. "
                    "Read-only: it never contacts a device.",
        epilog="Supply both peers' logs whenever you can. One side alone cannot "
               "establish which direction failed.",
    )
    parser.add_argument("-a", "--peer-a-log", required=True,
                        help="Log file from peer A (typically the hub or HQ).")
    parser.add_argument("-b", "--peer-b-log",
                        help="Log file from peer B (typically the branch or spoke).")
    parser.add_argument("--peer-a-label", default="peer-a",
                        help="Name for peer A in the report. Default: peer-a")
    parser.add_argument("--peer-b-label", default="peer-b",
                        help="Name for peer B in the report. Default: peer-b")
    parser.add_argument("--peer-a-tz", default="0", type=_tz_minutes,
                        help="UTC offset of peer A's timestamps when the log does "
                             "not carry one, e.g. +02:00. Default: 0 (UTC).")
    parser.add_argument("--peer-b-tz", default="0", type=_tz_minutes,
                        help="UTC offset of peer B's timestamps when the log does "
                             "not carry one. Default: 0 (UTC).")
    parser.add_argument("--year", type=int, default=None,
                        help="Year to assume for BSD syslog timestamps, which omit "
                             "it. Default: the current year.")
    parser.add_argument("-w", "--window", type=float, default=DEFAULT_WINDOW,
                        help="Seconds of quiet that separate one incident from the "
                             "next. Default: %.0f" % DEFAULT_WINDOW)
    parser.add_argument("-f", "--format", choices=("markdown", "json"),
                        default="markdown", help="Output format. Default: markdown")
    parser.add_argument("-o", "--output",
                        help="Write the report here instead of stdout.")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS,
                        help="Maximum events rendered per incident. Default: %d"
                             % DEFAULT_MAX_EVENTS)
    return parser


def _main_impl():
    parser = build_parser()
    try:
        args = parser.parse_args()
    except SystemExit:
        return 2

    if args.window <= 0:
        sys.stderr.write("Error: --window must be greater than zero.\n")
        return 2
    if args.max_events <= 0:
        sys.stderr.write("Error: --max-events must be greater than zero.\n")
        return 2
    year = args.year or datetime.now(timezone.utc).year
    if not (1970 <= year <= 2200):
        sys.stderr.write("Error: --year %d is outside a sensible range.\n" % year)
        return 2

    try:
        events_a, stats_a = parse_log(args.peer_a_log, args.peer_a_label,
                                      year, args.peer_a_tz)
    except FileNotFoundError:
        sys.stderr.write("Error: peer A log not found: %s\n" % args.peer_a_log)
        return 1
    except IsADirectoryError:
        sys.stderr.write("Error: --peer-a-log is a directory, not a file: %s\n"
                         % args.peer_a_log)
        return 1
    except ValueError as exc:
        sys.stderr.write("Error: peer A log unusable: %s\n" % exc)
        return 1

    events_b, stats_b = [], {}
    if args.peer_b_log:
        try:
            events_b, stats_b = parse_log(args.peer_b_log, args.peer_b_label,
                                          year, args.peer_b_tz)
        except FileNotFoundError:
            sys.stderr.write("Error: peer B log not found: %s\n" % args.peer_b_log)
            return 1
        except IsADirectoryError:
            sys.stderr.write("Error: --peer-b-log is a directory, not a file: %s\n"
                             % args.peer_b_log)
            return 1
        except ValueError as exc:
            sys.stderr.write("Error: peer B log unusable: %s\n" % exc)
            return 1

    report = correlate(events_a, events_b, stats_a, stats_b, args.window,
                       args.max_events, args.peer_a_label, args.peer_b_label)

    if args.format == "json":
        rendered = json.dumps(to_json(report, args.max_events), indent=2,
                              sort_keys=True, default=str)
    else:
        rendered = render_markdown(report, args.max_events)

    # Both formats go through the same scrub. A redaction that applies to one
    # output format and not the other is not a redaction.
    rendered = _scrub(rendered)

    if args.output:
        try:
            parent = os.path.dirname(os.path.abspath(args.output))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
            sys.stderr.write("Report written to: %s\n" % args.output)
        except OSError as exc:
            sys.stderr.write("Error: could not write report: %s\n" % exc)
            return 1
    else:
        sys.stdout.write(rendered + ("" if rendered.endswith("\n") else "\n"))

    return 0


def main():
    """
    Hardened entry point.

    Syslog arrives truncated mid-line, in UTF-16 labelled as UTF-8, with NUL
    bytes from a crashed collector, as a directory someone meant to glob, and
    occasionally as a 4 GB file someone meant to tail. Each of those must produce
    one clear sentence and a non-zero exit, never a traceback - a tool that
    panics during an incident is a tool nobody runs during the next one.
    """
    try:
        return _main_impl() or 0
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.stderr.write("Error: interrupted.\n")
        return 1
    except IsADirectoryError:
        sys.stderr.write("Error: input path is a directory, not a file.\n")
        return 1
    except FileNotFoundError as exc:
        sys.stderr.write("Error: input file not found: %s\n" % exc)
        return 1
    except PermissionError as exc:
        sys.stderr.write("Error: permission denied reading input: %s\n" % exc)
        return 1
    except UnicodeError as exc:
        sys.stderr.write("Error: input encoding could not be decoded (%s).\n" % exc)
        return 1
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        sys.stderr.write("Error: input could not be parsed as a log file "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1
    except RecursionError:
        sys.stderr.write("Error: input is nested too deeply to parse safely.\n")
        return 1
    except MemoryError:
        sys.stderr.write("Error: input exhausted available memory; refusing to "
                         "continue.\n")
        return 1
    except OSError as exc:
        sys.stderr.write("Error: could not read or write a file: %s\n" % exc)
        return 1
    except Exception as exc:  # pragma: no cover - last resort
        sys.stderr.write("Error: unrecoverable problem correlating these logs "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
