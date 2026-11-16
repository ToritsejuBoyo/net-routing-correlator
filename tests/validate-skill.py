#!/usr/bin/env python3
"""
Known-answer validation for net-routing-correlator.

Every assertion here is tied to a synthetic fixture whose correct answer is
known by construction. A correlator that merely runs without crashing is
worthless: the question is whether it reaches the RIGHT conclusion about a log
whose cause we already know, and whether it declines to reach one when the
evidence is not there.

Run:  python tests/validate-skill.py
"""

import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "scripts", "correlate-routing-logs.py")
FIXTURES = os.path.join(HERE, "fixtures")


def _load_engine():
    spec = importlib.util.spec_from_file_location("routing_engine", ENGINE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["routing_engine"] = module
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    spec.loader.exec_module(module)
    return module


ENG = _load_engine()


def fixture(name):
    return os.path.join(FIXTURES, name)


def run(args, timeout=180):
    return subprocess.run(
        [sys.executable, ENGINE] + args,
        capture_output=True, text=True, timeout=timeout,
    )


def run_json(args):
    proc = run(args + ["-f", "json"])
    assert proc.returncode == 0, "engine failed: %s" % proc.stderr
    return json.loads(proc.stdout)


REKEY = ["-a", fixture("fixture-rekey-flap-peer-a-cisco.log"),
         "-b", fixture("fixture-rekey-flap-peer-b-fortigate.log"),
         "--year", "2026"]
OSPF = ["-a", fixture("fixture-ospf-exstart-mtu-peer-a.log"),
        "-b", fixture("fixture-ospf-exstart-mtu-peer-b.log"),
        "--year", "2026"]
RECURSIVE = ["-a", fixture("fixture-recursive-routing.log"), "--year", "2026"]
PROPOSAL = ["-a", fixture("fixture-proposal-mismatch-peer-a-strongswan.log"),
            "-b", fixture("fixture-proposal-mismatch-peer-b-mikrotik.log"),
            "--year", "2026"]
SECRETS_LOG = ["-a", fixture("fixture-secrets-in-logs.log"), "--year", "2026"]


def ids(report):
    return [h["id"] for h in report["hypotheses"]]


# ---------------------------------------------------------------------------
class TimestampParsing(unittest.TestCase):
    """Five dialects, one timeline. Anything less and the merge is fiction."""

    def test_iso8601_with_offset_is_converted_to_utc(self):
        stamp, note = ENG.parse_timestamp("2026-02-11T14:03:11+02:00 msg", 2026)
        self.assertEqual(stamp.hour, 12)
        self.assertEqual(note, "iso8601")

    def test_iso8601_zulu(self):
        stamp, _ = ENG.parse_timestamp("2026-02-11T14:03:11Z msg", 2026)
        self.assertEqual(stamp.hour, 14)

    def test_fortigate_key_value_header(self):
        stamp, note = ENG.parse_timestamp("date=2026-02-11 time=14:03:11 devname=x", 2026)
        self.assertEqual(note, "vendor-header")
        self.assertEqual((stamp.month, stamp.day, stamp.hour), (2, 11, 14))

    def test_bsd_syslog_takes_the_supplied_year(self):
        stamp, note = ENG.parse_timestamp("Feb 11 14:03:11.233 host msg", 2019)
        self.assertEqual(stamp.year, 2019)
        self.assertEqual(note, "bsd-syslog-year-assumed")

    def test_cisco_unsynced_clock_marker_is_reported(self):
        _, note = ENG.parse_timestamp("*Feb 11 14:03:11.233 host msg", 2026)
        self.assertEqual(note, "bsd-syslog-clock-unsynced")

    def test_routeros_format(self):
        stamp, note = ENG.parse_timestamp("may/19/2026 11:00:01 br-mt ipsec,error x", 2000)
        self.assertEqual((stamp.year, stamp.month, stamp.day), (2026, 5, 19))
        self.assertEqual(note, "routeros")

    def test_timezone_offset_is_applied_when_the_log_carries_none(self):
        stamp, _ = ENG.parse_timestamp("Feb 11 14:03:11 host msg", 2026,
                                       tz_offset_minutes=120)
        self.assertEqual(stamp.hour, 12)

    def test_unparseable_line_is_reported_not_guessed(self):
        stamp, note = ENG.parse_timestamp("no time here at all", 2026)
        self.assertIsNone(stamp)
        self.assertEqual(note, "no-timestamp")

    def test_impossible_date_is_rejected_rather_than_clamped(self):
        stamp, _ = ENG.parse_timestamp("2026-02-30T10:00:00Z msg", 2026)
        self.assertIsNone(stamp)


# ---------------------------------------------------------------------------
class CredentialRedaction(unittest.TestCase):
    """Credentials are removed on ingest, so no output format can leak them."""

    def test_pre_shared_key_assignment(self):
        out = ENG.redact_secrets("pre-shared-key = Sup3rSecretPSK!2026 rejected")
        self.assertNotIn("Sup3rSecretPSK", out)
        self.assertIn("[REDACTED-SECRET]", out)

    def test_cisco_type_7_hash_not_the_type_digit(self):
        out = ENG.redact_secrets("neighbor 10.255.0.2 password 7 104B0718071B17 set")
        self.assertNotIn("104B0718071B17", out)
        self.assertIn("password 7 [REDACTED-SECRET]", out)

    def test_strongswan_psk_line(self):
        out = ENG.redact_secrets('198.51.100.7 203.0.113.42 : PSK "shared-value-x"')
        self.assertNotIn("shared-value-x", out)

    def test_fortigate_psksecret_keyword(self):
        self.assertNotIn("ThisIsTheKey99",
                         ENG.redact_secrets("set psksecret ThisIsTheKey99"))

    def test_snmp_community(self):
        self.assertNotIn("PrivateCommunityStr",
                         ENG.redact_secrets("snmp-community = PrivateCommunityStr"))

    def test_already_redacted_text_is_not_rewritten(self):
        once = ENG.redact_secrets("psk = TopSecretValue")
        twice = ENG.redact_secrets(once)
        self.assertEqual(once, twice)

    def test_peer_addresses_are_preserved(self):
        out = ENG.redact_secrets("peer 203.0.113.42 psk = Secret1")
        self.assertIn("203.0.113.42", out)

    def test_no_secret_reaches_any_output_format(self):
        plaintext = ["Sup3rSecretPSK!2026", "104B0718071B17",
                     "another-shared-secret-value", "PrivateCommunityStr"]
        for extra in ([], ["-f", "json"]):
            proc = run(SECRETS_LOG + extra)
            self.assertEqual(0, proc.returncode, proc.stderr)
            for secret in plaintext:
                with self.subTest(fmt=extra or "markdown", secret=secret):
                    self.assertNotIn(secret, proc.stdout)

    def test_indicators_survive_because_they_are_the_evidence(self):
        proc = run(SECRETS_LOG)
        self.assertIn("203.0.113.42", proc.stdout,
                      "peer address was stripped; the report is unusable without it")


# ---------------------------------------------------------------------------
class ClockSkew(unittest.TestCase):
    """Peer B's clock is built 3 seconds fast. The tool must find that."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_json(REKEY)

    def test_offset_is_measured_to_within_a_tenth_of_a_second(self):
        self.assertAlmostEqual(3.0, self.report["clock_skew"]["offset_seconds"],
                               delta=0.1)

    def test_confidence_is_high_when_anchors_agree(self):
        self.assertEqual("high", self.report["clock_skew"]["confidence"])
        self.assertTrue(self.report["clock_skew"]["applied"])

    def test_spread_is_reported_so_the_estimate_can_be_judged(self):
        self.assertLess(self.report["clock_skew"]["spread_seconds"], 1.0)
        self.assertGreaterEqual(self.report["clock_skew"]["sample_count"], 4)

    def test_single_peer_cannot_measure_skew_and_says_so(self):
        report = run_json(RECURSIVE)
        self.assertEqual("none", report["clock_skew"]["confidence"])
        self.assertFalse(report["clock_skew"]["applied"])
        self.assertIn("Not enough events", report["clock_skew"]["note"])

    def test_unmeasurable_skew_raises_the_clock_integrity_hypothesis(self):
        self.assertIn("clock-integrity", ids(run_json(RECURSIVE)))

    def test_measured_skew_does_not_raise_it(self):
        self.assertNotIn("clock-integrity", ids(self.report))


# ---------------------------------------------------------------------------
class RekeyAlignedFlap(unittest.TestCase):
    """Four drops exactly 3600 s apart, each following a rekey."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_json(REKEY)

    def test_periodicity_is_detected(self):
        period = self.report["periodicity"]
        self.assertTrue(period["periodic"])
        self.assertAlmostEqual(3600.0, period["period_seconds"], delta=5.0)

    def test_period_is_matched_against_a_known_lifetime(self):
        self.assertEqual(3600, self.report["periodicity"]["matched_lifetime"]["seconds"])

    def test_drop_count_collapses_the_same_drop_seen_by_both_peers(self):
        # Four cycles, each logged by both peers. Counting eight would turn one
        # outage into two and halve the apparent period.
        self.assertEqual(4, self.report["periodicity"]["drop_count"])

    def test_rekey_hypothesis_ranks_first(self):
        self.assertEqual("rekey-aligned-flap", ids(self.report)[0])

    def test_rekey_hypothesis_is_high_confidence(self):
        top = self.report["hypotheses"][0]
        self.assertEqual("high", top["confidence"])
        self.assertGreaterEqual(top["score"], 0.75)

    def test_contested_evidence_is_flagged_not_asserted(self):
        top = self.report["hypotheses"][0]
        self.assertIn("contested", top["caveat"].lower())

    def test_every_hypothesis_carries_a_discriminating_test(self):
        for item in self.report["hypotheses"]:
            with self.subTest(hypothesis=item["id"]):
                self.assertTrue(item["discriminating_test"].strip())

    def test_every_hypothesis_carries_a_rollback(self):
        for item in self.report["hypotheses"]:
            with self.subTest(hypothesis=item["id"]):
                self.assertTrue(item["rollback"].strip())


# ---------------------------------------------------------------------------
class DirectionAttribution(unittest.TestCase):
    """
    Peer A sent the hold-timer notification; peer B received it. That is ONE
    failure in ONE direction, and must not be counted as two.
    """

    @classmethod
    def setUpClass(cls):
        cls.report = run_json(REKEY)

    def test_all_liveness_failures_point_the_same_way(self):
        directions = self.report["direction_counts"]
        self.assertGreater(directions.get("toward_peer_a", 0), 0)
        self.assertEqual(0, directions.get("toward_peer_b", 0),
                         "a one-way failure was counted as bidirectional")

    def test_report_names_the_failing_direction(self):
        bgp = [h for h in self.report["hypotheses"] if h["id"] == "bgp-hold-timer"]
        self.assertTrue(bgp, "BGP hold-timer hypothesis missing")
        self.assertIn("peer B -> peer A", " ".join(bgp[0]["evidence"]))

    def test_canonical_direction_mapping(self):
        self.assertEqual("toward_peer_a",
                         ENG.canonical_direction(True, "inbound-broken"))
        self.assertEqual("toward_peer_b",
                         ENG.canonical_direction(True, "outbound-broken"))
        self.assertEqual("toward_peer_b",
                         ENG.canonical_direction(False, "inbound-broken"))
        self.assertEqual("toward_peer_a",
                         ENG.canonical_direction(False, "outbound-broken"))


# ---------------------------------------------------------------------------
class CausalChaining(unittest.TestCase):
    """IPsec down causes BGP down. The reverse is never asserted."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_json(REKEY)

    def test_first_incident_includes_both_peers(self):
        self.assertTrue(self.report["incidents"][0]["both_peers"])

    def test_chain_starts_below_the_routing_layer(self):
        chain = self.report["incidents"][0]["chain"]
        self.assertTrue(chain)
        self.assertIn(chain[0]["layer"], ("transport", "ike", "ipsec"))

    def test_chain_never_moves_back_down_the_stack(self):
        rank = {name: i for i, name in enumerate(ENG.LAYERS)}
        for incident in self.report["incidents"]:
            previous = -1
            for step in incident["chain"]:
                with self.subTest(incident=incident["index"],
                                  event=step["event_id"]):
                    self.assertGreaterEqual(rank[step["layer"]], previous)
                    previous = rank[step["layer"]]

    def test_ipsec_teardown_precedes_the_bgp_drop_it_caused(self):
        chain = self.report["incidents"][0]["chain"]
        order = [step["event_id"] for step in chain]
        self.assertIn("IPSEC_SA_DOWN", order)
        self.assertIn("BGP_HOLD_EXPIRED_LOCAL", order)
        self.assertLess(order.index("IPSEC_SA_DOWN"),
                        order.index("BGP_HOLD_EXPIRED_LOCAL"))


# ---------------------------------------------------------------------------
class OspfMtuVersusDeadTimer(unittest.TestCase):
    """
    The two OSPF failure modes have opposite fixes and must never be merged.
    Hellos are small; Database Description packets are not.
    """

    @classmethod
    def setUpClass(cls):
        cls.report = run_json(OSPF)

    def test_mtu_hypothesis_ranks_first(self):
        self.assertEqual("mtu-exstart", ids(self.report)[0])

    def test_dead_timer_hypothesis_is_absent_when_no_dead_timer_expired(self):
        self.assertNotIn("ospf-dead-timer", ids(self.report))

    def test_mtu_evidence_names_the_conflicting_values(self):
        evidence = " ".join(self.report["hypotheses"][0]["evidence"])
        for value in ("1500", "1400", "1380"):
            with self.subTest(mtu=value):
                self.assertIn(value, evidence)

    def test_mtu_ignore_is_explicitly_warned_against(self):
        caveat = self.report["hypotheses"][0]["caveat"].lower()
        self.assertIn("mtu-ignore", caveat)

    def test_ipsec_up_is_not_misread_as_a_bgp_session(self):
        # "Crypto tunnel is UP ... IPsec SA established" once matched the BGP
        # rule on the bare word "established", inventing a BGP session that was
        # never in the log.
        self.assertNotIn("BGP_ADJ_UP", self.report["event_counts"])

    def test_remediation_is_offered_for_more_than_one_vendor(self):
        self.assertGreaterEqual(len(self.report["hypotheses"][0]["remediation"]), 3)


# ---------------------------------------------------------------------------
class RecursiveRouting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_json(RECURSIVE)

    def test_recursive_routing_ranks_first(self):
        self.assertEqual("recursive-routing", ids(self.report)[0])

    def test_it_is_high_confidence_because_the_message_is_unambiguous(self):
        self.assertEqual("high", self.report["hypotheses"][0]["confidence"])

    def test_single_peer_report_warns_that_direction_is_unknowable(self):
        proc = run(RECURSIVE)
        self.assertIn("Only one peer's log was supplied", proc.stdout)


# ---------------------------------------------------------------------------
class ProposalMismatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_json(PROPOSAL)

    def test_proposal_mismatch_is_found(self):
        self.assertIn("proposal-mismatch", ids(self.report))

    def test_evidence_locates_the_mismatch_in_phase_1(self):
        item = [h for h in self.report["hypotheses"]
                if h["id"] == "proposal-mismatch"][0]
        self.assertIn("Phase 1 never came up", " ".join(item["evidence"]))

    def test_both_vendor_dialects_were_recognised(self):
        self.assertIn("strongswan", self.report["ingest"]["a"]["vendors"])
        self.assertIn("mikrotik", self.report["ingest"]["b"]["vendors"])

    def test_gcm_integrity_trap_is_called_out(self):
        item = [h for h in self.report["hypotheses"]
                if h["id"] == "proposal-mismatch"][0]
        self.assertIn("GCM", item["caveat"])


# ---------------------------------------------------------------------------
class RestraintUnderThinEvidence(unittest.TestCase):
    """A tool that always finds a root cause is a tool that is often wrong."""

    def test_noise_only_log_produces_no_failure_hypothesis(self):
        report = run_json(["-a", fixture("fixture-no-events.log"), "--year", "2026"])
        self.assertEqual([], [i for i in ids(report) if i != "clock-integrity"])

    def test_noise_only_log_says_so_in_plain_words(self):
        proc = run(["-a", fixture("fixture-no-events.log"), "--year", "2026"])
        self.assertEqual(0, proc.returncode)
        self.assertIn("No classified failure events", proc.stdout)

    def test_empty_file_is_handled_without_a_traceback(self):
        proc = run(["-a", fixture("fixture-empty.log"), "--year", "2026"])
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_two_drops_are_too_few_to_claim_a_period(self):
        report = run_json(OSPF)
        self.assertFalse(report["periodicity"]["periodic"])

    def test_report_states_what_it_cannot_tell_you(self):
        proc = run(REKEY)
        self.assertIn("What this report cannot tell you", proc.stdout)

    def test_report_warns_about_losing_the_remote_device(self):
        proc = run(REKEY)
        self.assertIn("out-of-band", proc.stdout.lower())


# ---------------------------------------------------------------------------
class CommandLineBehaviour(unittest.TestCase):
    def test_missing_file_exits_one_with_a_sentence(self):
        proc = run(["-a", fixture("no-such-file.log")])
        self.assertEqual(1, proc.returncode)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("not found", proc.stderr)

    def test_directory_as_input_exits_one(self):
        proc = run(["-a", FIXTURES])
        self.assertEqual(1, proc.returncode)
        self.assertNotIn("Traceback", proc.stderr)

    def test_zero_window_is_rejected(self):
        self.assertEqual(2, run(REKEY + ["-w", "0"]).returncode)

    def test_negative_max_events_is_rejected(self):
        self.assertEqual(2, run(REKEY + ["--max-events", "-3"]).returncode)

    def test_absurd_year_is_rejected(self):
        self.assertEqual(2, run(REKEY + ["--year", "99999"]).returncode)

    def test_bad_timezone_is_rejected(self):
        self.assertEqual(2, run(REKEY + ["--peer-a-tz", "banana"]).returncode)

    def test_timezone_offset_shifts_the_timeline(self):
        base = run_json(REKEY)
        shifted = run_json(REKEY + ["--peer-a-tz", "+02:00"])
        a = base["incidents"][0]["start"]
        b = shifted["incidents"][0]["start"]
        self.assertNotEqual(a, b)

    def test_output_file_is_written(self):
        out = os.path.join(FIXTURES, "..", "_tmp-report.md")
        try:
            proc = run(REKEY + ["-o", out])
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertTrue(os.path.exists(out))
            with io.open(out, encoding="utf-8") as handle:
                self.assertIn("Correlation Report", handle.read())
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_output_is_deterministic_apart_from_the_generation_stamp(self):
        strip = lambda text: re.sub(r"Generated \S+", "Generated X", text)
        first = strip(run(REKEY).stdout)
        second = strip(run(REKEY).stdout)
        self.assertEqual(first, second)

    def test_json_carries_the_schema_version(self):
        self.assertEqual("1.0", run_json(REKEY)["schema_version"])

    def test_json_and_markdown_describe_the_same_hypotheses(self):
        report = run_json(REKEY)
        markdown = run(REKEY).stdout
        for item in report["hypotheses"]:
            with self.subTest(hypothesis=item["id"]):
                self.assertIn(item["title"], markdown)


# ---------------------------------------------------------------------------
class MarkdownIntegrity(unittest.TestCase):
    def test_log_lines_do_not_break_the_table(self):
        cell = ENG._md_cell("a | b | c\nnext line")
        self.assertNotIn("\n", cell)
        self.assertEqual(0, len(re.findall(r"(?<!\\)\|", cell)))

    def test_long_lines_are_truncated_rather_than_wrapped(self):
        self.assertLessEqual(len(ENG._md_cell("x" * 5000)), 221)

    def test_every_table_row_has_a_consistent_column_count(self):
        markdown = run(REKEY).stdout
        rows = [line for line in markdown.splitlines()
                if line.startswith("|") and not re.match(r"^\|[\s:\-|]+\|$", line)]
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(row=row[:60]):
                self.assertTrue(row.rstrip().endswith("|"))


# ---------------------------------------------------------------------------
class PatternSafety(unittest.TestCase):
    """
    Every detection pattern runs over text supplied by a third party's router.
    A quadratic pattern there is a denial of service with extra steps.
    """

    def test_no_rule_backtracks_catastrophically(self):
        payloads = [
            "%IKEV2-5-" + "A" * 40000,
            "a" * 20000 + "!",
            ("peer " * 8000),
            "BGP-3-NOTIFICATION: " + "0" * 30000,
            ("1.1.1.1 " * 5000),
            ("MTU " * 10000),
        ]
        for rule in ENG.RULES:
            for payload in payloads:
                start = time.time()
                rule.pattern.search(payload)
                elapsed = time.time() - start
                with self.subTest(rule=rule.event_id):
                    self.assertLess(elapsed, 0.75,
                                    "%s took %.2fs" % (rule.event_id, elapsed))

    def test_redaction_patterns_are_linear(self):
        start = time.time()
        ENG.redact_secrets("pre-shared-key = " + "A" * 120000 + " tail")
        self.assertLess(time.time() - start, 0.75)

    def test_every_rule_declares_a_known_layer(self):
        for rule in ENG.RULES:
            with self.subTest(rule=rule.event_id):
                self.assertIn(rule.layer, ENG.LAYERS)

    def test_every_rule_has_a_plain_english_meaning(self):
        for rule in ENG.RULES:
            with self.subTest(rule=rule.event_id):
                self.assertGreater(len(rule.meaning), 40)

    def test_rule_ids_are_unique(self):
        seen = [rule.event_id for rule in ENG.RULES]
        self.assertEqual(len(seen), len(set(seen)))

    def test_skew_anchors_all_name_real_rules(self):
        known = {rule.event_id for rule in ENG.RULES}
        self.assertTrue(ENG.SKEW_ANCHORS.issubset(known))

    def test_flap_events_all_name_real_rules(self):
        known = {rule.event_id for rule in ENG.RULES}
        self.assertTrue(ENG.FLAP_EVENTS.issubset(known))


# ---------------------------------------------------------------------------
class SkillContract(unittest.TestCase):
    """The packaging rules this library holds every skill to."""

    @classmethod
    def setUpClass(cls):
        with io.open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as handle:
            cls.skill = handle.read()

    def _repo_files(self):
        out = []
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = [d for d in dirs
                       if d not in (".git", "__pycache__", ".github")]
            for name in names:
                out.append(os.path.join(base, name))
        return out

    def test_frontmatter_declares_the_required_fields(self):
        head = self.skill.split("---")[1]
        for field in ("name:", "description:", "license:", "version:", "metadata:"):
            with self.subTest(field=field):
                self.assertIn(field, head)

    def test_description_carries_a_use_when_trigger(self):
        head = self.skill.split("---")[1]
        self.assertIn("Use when", head)

    def test_name_matches_the_directory(self):
        self.assertIn("name: net-routing-correlator", self.skill)

    def test_every_path_referenced_in_skill_md_exists(self):
        referenced = set(re.findall(r"\(((?:scripts|references|assets|tests)/[^)]+)\)",
                                    self.skill))
        referenced |= set(re.findall(r"`((?:scripts|references|assets)/[^`]+?\.\w+)`",
                                     self.skill))
        self.assertTrue(referenced, "SKILL.md references no bundled file")
        for path in referenced:
            with self.subTest(path=path):
                self.assertTrue(os.path.exists(os.path.join(ROOT, path)),
                                "%s is referenced but missing" % path)

    def test_every_bundled_reference_and_asset_is_referenced(self):
        for folder in ("references", "assets"):
            directory = os.path.join(ROOT, folder)
            if not os.path.isdir(directory):
                continue
            for name in os.listdir(directory):
                with self.subTest(file="%s/%s" % (folder, name)):
                    self.assertIn(name, self.skill,
                                  "%s/%s ships but nothing points at it" % (folder, name))

    def test_documented_flags_all_exist(self):
        """
        Catch the documentation drift that ships a flag the engine never had.

        Only flags attributed to THIS engine count. SKILL.md also quotes vendor
        commands (`swanctl --list-sas`), and failing on those would train the
        next person to delete the test rather than fix the drift.
        """
        documented = set()
        for block in re.findall(r"```[a-z]*\n(.*?)```", self.skill, re.S):
            if "correlate-routing-logs.py" not in block:
                continue
            documented |= set(re.findall(r"(--[a-z][a-z0-9-]{2,})", block))
        # An inline code span holding nothing but a flag is ours by convention.
        documented |= set(re.findall(r"`(--[a-z][a-z0-9-]{2,})`", self.skill))
        self.assertTrue(documented, "SKILL.md documents no engine flags at all")
        helptext = run(["--help"]).stdout
        for flag in sorted(documented):
            with self.subTest(flag=flag):
                self.assertIn(flag, helptext,
                              "SKILL.md documents %s but the engine has no such flag"
                              % flag)

    def test_no_emoji_anywhere_in_the_skill(self):
        pattern = re.compile(
            "[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F\u2190-\u21FF\u2B00-\u2BFF]")
        for path in self._repo_files():
            if not path.endswith((".md", ".py", ".yml", ".yaml", ".log", ".txt")):
                continue
            with io.open(path, encoding="utf-8", errors="replace") as handle:
                body = handle.read()
            found = pattern.findall(body)
            with self.subTest(file=os.path.relpath(path, ROOT)):
                self.assertEqual([], found, "emoji found: %r" % found[:5])

    def test_engine_imports_only_the_standard_library(self):
        with io.open(ENGINE, encoding="utf-8") as handle:
            source = handle.read()
        imports = set(re.findall(r"^\s*(?:import|from)\s+([a-zA-Z_][\w.]*)",
                                 source, re.M))
        allowed = set(sys.stdlib_module_names) | {"sanitizer"}
        for name in imports:
            with self.subTest(module=name):
                self.assertIn(name.split(".")[0], allowed)

    def test_sanitizer_is_vendored_next_to_the_engine(self):
        self.assertTrue(os.path.exists(os.path.join(ROOT, "scripts", "sanitizer.py")))

    def test_fixtures_use_documentation_address_space_only(self):
        banned = re.compile(r"\b(?:(?:1[0-9]{2}|[1-9][0-9]|[1-9])\.){3}\d{1,3}\b")
        allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.", "10.",
                            "192.168.", "172.16.", "127.", "0.")
        for name in os.listdir(FIXTURES):
            path = os.path.join(FIXTURES, name)
            with io.open(path, encoding="utf-8", errors="replace") as handle:
                body = handle.read()
            for found in set(banned.findall(body)):
                with self.subTest(fixture=name, ip=found):
                    self.assertTrue(found.startswith(allowed_prefixes),
                                    "%s contains non-documentation address %s"
                                    % (name, found))


if __name__ == "__main__":
    print("=" * 78)
    print("KNOWN-ANSWER VALIDATION: net-routing-correlator")
    print("engine: %s" % os.path.relpath(ENGINE, ROOT))
    print("=" * 78)
    unittest.main(verbosity=2)
