"""Offline regressions for native capture provenance and pagination failures.

Run from cisco/fmc: python -B -m unittest -v test_capture_evidence test_static_routes test_safe_stdio
No API authentication or network calls. All output uses temporary directories.
"""
import copy
import html
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import fmc_collect_data as collector
import build_html
from core.html_site import SiteBuilder


def rows(start, stop):
    return [{"id": str(i), "name": f"Object {i}", "type": "Host"} for i in range(start, stop)]


class CaptureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.client = collector.FMCClient("fmc.example.invalid", "offline", "unused",
                                          domain_uuid="domain-a", log=self.logs.append)
        self.path = "/object/hosts"
        self.sleep = patch.object(collector.time, "sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)
        self.network = patch("socket.socket.connect", side_effect=AssertionError("Offline test attempted network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def collect(self, bodies, **kwargs):
        self.client.get_json = Mock(side_effect=bodies)
        result = self.client.get_all(self.path, **kwargs)
        return result, self.client.endpoint_evidence[self.path]

    def test_server_short_pages_follow_total_without_next(self):
        result, evidence = self.collect([
            {"items": rows(0, 2), "paging": {"count": 5, "limit": 2}},
            {"items": rows(2, 4), "paging": {"count": 5, "limit": 2}},
            {"items": rows(4, 5), "paging": {"count": 5, "limit": 2}},
        ])
        self.assertEqual(result, rows(0, 5))
        self.assertEqual([p["offset"] for p in evidence["pages"]], [0, 2, 4])
        self.assertEqual(evidence["status"], "complete")
        self.assertEqual(evidence["reported_total"], 5)

    def test_next_link_with_short_page_and_string_total(self):
        result, evidence = self.collect([
            {"items": rows(0, 2), "paging": {"count": "3", "next": [self.client.config_base + self.path + "?offset=2&limit=2"]}},
            {"items": rows(2, 3), "paging": {"count": "3", "next": []}},
        ])
        self.assertEqual(result, rows(0, 3))
        self.assertEqual(evidence["pages"][0]["next_offset"], 2)
        self.assertEqual(evidence["status"], "complete")

    def test_fmc_multiple_future_links_select_smallest_forward_offset(self):
        result, evidence = self.collect([
            {"items": rows(0, 2), "paging": {"count": 6, "next": ["?offset=4&limit=2", "?offset=2&limit=2"]}},
            {"items": rows(2, 4), "paging": {"count": 6, "next": ["?offset=4&limit=2"]}},
            {"items": rows(4, 6), "paging": {"count": 6}},
        ])
        self.assertEqual(result, rows(0, 6))
        self.assertEqual([page["offset"] for page in evidence["pages"]], [0, 2, 4])
        self.assertEqual(evidence["pages"][0]["next_offsets"], [2, 4])
        self.assertEqual(evidence["status"], "complete")

    def test_bad_link_cannot_hide_among_valid_future_links(self):
        for links in (["?offset=1", "https://other.invalid/?offset=2"],
                      ["?offset=1", "?offset=0"], ["?offset=1", "?offset=1"]):
            result, evidence = self.collect([{"items": rows(0, 1), "paging": {"count": 3, "next": links}}])
            self.assertEqual(result, rows(0, 1))
            self.assertEqual(self.client.get_json.call_count, 1)
            self.assertEqual(evidence["status"], "partial")

    def test_short_page_without_count_needs_explicit_end_evidence(self):
        result, evidence = self.collect([{"items": rows(0, 1)}, {"items": rows(1, 2)}, {"items": []}])
        self.assertEqual(result, rows(0, 2))
        self.assertEqual(len(evidence["pages"]), 3)
        self.assertIsNone(evidence["reported_total"])
        self.assertEqual(evidence["status"], "complete")

    def test_later_http_failure_retains_partial_and_real_total(self):
        result, evidence = self.collect([{"items": rows(0, 2), "paging": {"count": 3}}, {"_error": 503}])
        self.assertEqual(result, rows(0, 2))
        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["reported_total"], 3)
        self.assertFalse(evidence["empty"])
        self.assertIn("HTTP 503", self.logs[-1])
        snap = {"collection_evidence": {"endpoints": self.client.endpoint_evidence}}
        before = self.client.get_json.call_count
        audit = collector.audit_completeness(self.client, snap, lambda _: None)
        self.assertEqual(before, self.client.get_json.call_count, "Audit must not overwrite failure with a fresh probe")
        row = next(r for r in audit if r["endpoint"] == self.path)
        self.assertEqual((row["captured"], row["live_total"], row["status"]), (2, 3, "PARTIAL"))

    def test_first_failure_and_successful_empty_are_distinct(self):
        for body, status, empty in [({"_error": 403}, "error", False),
                                    ({"items": [], "paging": {"count": 0}}, "complete", True),
                                    ({"paging": {"count": 0}}, "complete", True),
                                    ({}, "error", False)]:
            with self.subTest(body=body):
                result, evidence = self.collect([body])
                self.assertEqual(result, [])
                self.assertEqual((evidence["status"], evidence["empty"]), (status, empty))

    def test_explicit_empty_before_total_is_partial_not_complete(self):
        result, evidence = self.collect([{"items": rows(0, 2), "paging": {"count": 3}},
                                         {"items": [], "paging": {"count": 3}}])
        self.assertEqual(len(result), 2)
        self.assertEqual(evidence["status"], "partial")
        self.assertIn("before reported total", evidence["error"])

    def test_repeated_pages_do_not_loop_or_relabel_complete(self):
        body = {"items": rows(0, 2), "paging": {"count": 4}}
        result, evidence = self.collect([body, body])
        self.assertEqual(result, rows(0, 2))
        self.assertEqual(evidence["status"], "partial")
        self.assertIn("Repeated", evidence["error"])

    def test_count_changes_or_bad_offset_refuse_completion(self):
        for second in ({"items": rows(2, 3), "paging": {"count": 4}},
                       {"items": rows(2, 3), "paging": {"count": 3, "offset": 0}}):
            result, evidence = self.collect([{"items": rows(0, 2), "paging": {"count": 3}}, second])
            self.assertEqual(evidence["status"], "partial")
            self.assertEqual(evidence["reported_total"], 3)

    def test_untrusted_next_links_never_trigger_followup(self):
        links = ["https://other.invalid/api?offset=1", "http://fmc.example.invalid/api?offset=1",
                 self.client.config_base + "/object/networks?offset=1", "?offset=0", "?offset=99",
                 "?offset=1&offset=2", "?offset=-1", "?limit=1", ["?offset=1", "?offset=1"]]
        for link in links:
            with self.subTest(link=link):
                result, evidence = self.collect([{"items": rows(0, 1), "paging": {"count": 2, "next": link}}])
                self.assertEqual(result, rows(0, 1))
                self.assertEqual(self.client.get_json.call_count, 1)
                self.assertEqual(evidence["status"], "partial")

    def test_page_and_item_bounds_are_explicit(self):
        with patch.object(collector, "MAX_PAGES", 1):
            _, evidence = self.collect([{"items": rows(0, 1), "paging": {"count": 2}}])
            self.assertEqual(evidence["status"], "partial")
            self.assertIn("page limit", evidence["error"])
        with patch.object(collector, "MAX_ITEMS", 1):
            result, evidence = self.collect([{"items": rows(0, 2), "paging": {"count": 2}}])
            self.assertEqual(result, [])
            self.assertNotEqual(evidence["status"], "complete")
            self.assertIn("item limit", evidence["error"])

    def test_transport_exception_is_recorded_not_empty(self):
        _, evidence = self.collect([RuntimeError("transport failed")])
        self.assertEqual(evidence["status"], "error")
        self.assertFalse(evidence["empty"])

    def test_get_json_rejects_cross_origin_and_does_not_follow_redirect(self):
        self.client.session.get = Mock(return_value=Mock(status_code=302, text="redirect"))
        with self.assertRaisesRegex(ValueError, "origin"):
            self.client.get_json("https://other.invalid/private")
        self.client.session.get.assert_not_called()
        result = self.client.get_json(self.path)
        self.assertEqual(result["_error"], 302)
        self.assertFalse(self.client.session.get.call_args.kwargs["allow_redirects"])

    def test_audit_without_total_never_invents_live_count(self):
        _, evidence = self.collect([{"items": rows(0, 2), "paging": {"next": []}}])
        audit = collector.audit_completeness(self.client, {"collection_evidence": {"endpoints": {self.path: evidence}}}, lambda _: None)
        row = next(r for r in audit if r["endpoint"] == self.path)
        self.assertEqual((row["live_total"], row["captured"], row["status"]), ("", 2, "captured"))

    def test_actual_assignment_shape_and_empty_rule_files_keep_evidence(self):
        assignment = {"id": "assign", "type": "PolicyAssignment", "policy": {
            "id": "acp", "type": "AccessPolicy", "name": "same-policy"}, "targets": [
            {"id": "dev", "type": "Device", "name": "same-firewall"}]}
        device = {"id": "dev", "type": "Device", "name": "same-firewall"}
        api = {
            "/api/fmc_platform/v1/info/domain": {"items": [{"uuid": "domain-a", "name": "Global"}], "paging": {"count": 1}},
            "/devices/devicerecords": {"items": [device], "paging": {"count": 1}},
            "/devices/devicerecords/dev": device,
            "/assignment/policyassignments": {"items": [assignment], "paging": {"count": 1}},
            "/policy/accesspolicies": {"items": [{"id": "acp", "name": "same-policy", "type": "AccessPolicy"},
                                                     {"id": "failed", "name": "failed", "type": "AccessPolicy"}], "paging": {"count": 2}},
            "/policy/accesspolicies/failed/accessrules": {"_error": 403},
            "/devices/devicerecords/dev/physicalinterfaces": {"items": [{"id": "if1", "type": "PhysicalInterface"}], "paging": {"count": 1}},
            "/devices/devicerecords/dev/routing/ipv4staticroutes": {"_error": 404},
            "/devices/devicerecords/dev/routing/staticroutes": {"items": [{"id": "v4", "type": "IPv4StaticRoute"}], "paging": {"count": 1}},
            "/devices/devicerecords/dev/routing/ipv6staticroutes": {"_error": 403},
        }
        pristine = copy.deepcopy(api)
        self.client.get_json = Mock(side_effect=lambda path, **kwargs: copy.deepcopy(api.get(path, {"items": [], "paging": {"count": 0}})))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snap = collector.collect(self.client, root, quick=True, log=lambda _: None)
            self.assertEqual(json.loads((root / "policy-assignments.json").read_bytes()), [assignment])
            self.assertEqual(json.loads((root / "devices.json").read_bytes()), [device])
            detail = json.loads((root / "device-details/same-firewall__dev.json").read_bytes())
            self.assertEqual(detail["device"], device)
            self.assertNotIn("accessPolicy", detail["device"])
            self.assertEqual(json.loads((root / "policy-rules/accesspolicies/same-policy__acp.json").read_bytes()), {"accessrules": []})
            self.assertFalse((root / "policy-rules/accesspolicies/failed__failed.json").exists())
            evidence = json.loads((root / "collection-evidence.json").read_bytes())
            self.assertEqual(evidence, snap["collection_evidence"])
            self.assertEqual(evidence["domain_id"], "domain-a")
            self.assertEqual(evidence["collector_version"], collector.__version__)
            endpoints = evidence["endpoints"]
            self.assertTrue(endpoints["/policy/accesspolicies/acp/accessrules"]["empty"])
            self.assertEqual(endpoints["/policy/accesspolicies/failed/accessrules"]["status"], "error")
            self.assertEqual(endpoints["/assignment/policyassignments"]["reported_total"], 1)
            for endpoint in ("ipv4staticroutes", "ipv6staticroutes"):
                self.assertEqual(endpoints["/devices/devicerecords/dev/routing/" + endpoint]["status"], "error")
            self.assertEqual(endpoints["/devices/devicerecords/dev/routing/staticroutes"]["status"], "complete")
            self.assertEqual([r["id"] for r in detail["routes"]], ["v4"])
        self.assertEqual(api, pristine)


class HTMLCompatibilityTests(unittest.TestCase):
    def test_existing_searchbox_output_and_escaped_csv_action(self):
        site = SiteBuilder(Path("unused"), "fmc", "test", [])
        self.assertEqual(site.searchbox("table", "count"),
                         '<input class="search" type="search" placeholder="Filter…" data-target="table" data-count="count" oninput="filterTable(this)">')
        value = site.searchbox("table", "count", export_csv='a\" onclick=\"bad.csv')
        self.assertIn("Export filtered CSV", value)
        self.assertIn("&quot;", value)
        self.assertIn('exportTableCSV("table",', html.unescape(value))
        self.assertNotIn('onclick="bad', value)

    def test_empty_and_audited_bundles_build_every_page(self):
        for completeness in ([], [{"object_type": "accessrules", "live_total": 2, "captured": 1,
                                   "status": "PARTIAL", "note": "Later page failed"}]):
            with self.subTest(completeness=completeness), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run = root / "run"
                run.mkdir()
                out = root / "html"
                build_html.FMCReport(run, out, {"counts": {"access_rules": 0}, "completeness": completeness}).build()
                for name in ("index.html", "completeness.html", "devices.html", "domains.html",
                             "apps_in_use.html", "access_rules.html", "raw.json.html"):
                    self.assertTrue((out / name).is_file(), name)
                self.assertIn("Export filtered CSV", (out / "domains.html").read_text())
                if completeness:
                    self.assertIn("currently filtered rows", (out / "completeness.html").read_text())

    def test_native_object_and_detail_json_cannot_close_script_tags(self):
        payload = {"id": {"name": '</script><script>alert("capture")</script>'}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site = SiteBuilder(root, "fmc", "test", [])
            report = build_html.FMCReport(root, root, {})
            site.page("page.html", "test", "", obj_data=payload, extra_script=report._detail_script(payload))
            page = (root / "page.html").read_text()
            self.assertNotIn('</script><script>alert', page)
            self.assertIn('\\u003c/script>', page)
            self.assertIn("var OBJ=", page)
            self.assertIn("var DETAIL=", page)


if __name__ == "__main__":
    unittest.main()
