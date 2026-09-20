"""Offline device collection regressions; no API authentication or network calls."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import fmc_collect_data as collector


class StaticRouteCollectionTests(unittest.TestCase):
    def collect(self, primary, fallback, ipv6):
        client = Mock()
        client.capture_record.return_value = {'id': 'lab', 'name': 'lab'}
        calls = []
        def get_all(path, **kwargs):
            calls.append(path.rsplit('/', 1)[-1])
            return {'ipv4staticroutes': primary, 'staticroutes': fallback,
                    'ipv6staticroutes': ipv6}.get(calls[-1], [])
        client.get_all.side_effect = get_all
        snap = {'counts': {}}
        with tempfile.TemporaryDirectory() as root, patch.object(collector.time, 'sleep'):
            collector.collect_device_details(client, Path(root), [{'id': 'lab', 'name': 'lab'}], snap, lambda _: None)
            raw = json.loads((Path(root) / 'device-details/lab__lab.json').read_text())
        return snap, raw, calls

    def test_dual_stack_keeps_both_families(self):
        v4 = {'id': 'v4', 'destination': '192.0.2.0/24'}
        v6 = {'id': 'v6', 'destination': '2001:db8::/64'}
        snap, raw, calls = self.collect([v4], [{'id': 'alias'}], [v6])
        self.assertEqual(raw['routes'], [v4, v6])
        self.assertEqual(snap['counts']['routes'], 2)
        self.assertEqual([r['id'] for r in snap['routes']], ['v4', 'v6'])
        self.assertNotIn('staticroutes', calls)

    def test_ipv4_fallback_does_not_replace_ipv6(self):
        v4, v6 = {'id': 'legacy'}, {'id': 'v6'}
        snap, raw, calls = self.collect([], [v4], [v6])
        self.assertEqual(raw['routes'], [v4, v6])
        self.assertIn('staticroutes', calls)
        self.assertIn('ipv6staticroutes', calls)

    def test_ipv6_only(self):
        snap, raw, calls = self.collect([], [], [{'id': 'v6'}])
        self.assertEqual(snap['counts']['routes'], 1)
        self.assertEqual(raw['routes'], [{'id': 'v6'}])


if __name__ == '__main__':
    unittest.main()
