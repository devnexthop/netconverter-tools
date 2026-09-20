"""Same-input hierarchy preservation and failed-capture regressions."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'common'))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from panorama_export import (HIERARCHY_XPATH, audit_completeness, build_export_root,
                             fetch_hierarchy, strip_branches)
from panorama_hierarchy import hierarchy_coverage
from palo_model import PaloPanoramaModel, _collect_device_group_entries


def capture():
    return ET.fromstring('''<config><panorama/><mgt-config><users><entry name="private-admin"/></users></mgt-config>
      <devices><entry name="localhost.localdomain"><device-group>
      <entry name="Root"><description>preserve unknown configuration</description><pre-rulebase><security><rules><entry name="inherited-rule"/></rules></security></pre-rulebase></entry>
      <entry name="Leaf"><devices><entry name="SERIAL"/></devices><pre-rulebase><security><rules><entry name="local-rule"/></rules></security></pre-rulebase></entry>
      </device-group></entry></devices>
      <readonly><devices><entry name="localhost.localdomain"><device-group>
      <entry name="Root"><id>1</id><address-group><entry name="mirror-object"/></address-group></entry>
      <entry name="Leaf"><id>2</id><parent-dg>Root</parent-dg></entry>
      </device-group><template><entry name="mirror-template"/></template></entry></devices></readonly></config>''')


class HierarchyCollectionTests(unittest.TestCase):
    def test_strip_preserves_all_native_parent_and_root_assertions(self):
        root=capture(); before=deepcopy(root.find('devices'))
        self.assertTrue(hierarchy_coverage(root)['complete'])
        removed=strip_branches(root,config_store='running')
        self.assertEqual(set(removed),{'readonly','mgt-config'})
        self.assertIsNone(root.find('readonly'))
        self.assertIsNone(root.find('mgt-config'))
        self.assertEqual(ET.tostring(root.find('devices')),ET.tostring(before))
        metadata=root.find('nc-device-group-hierarchy')
        self.assertEqual(metadata.get('status'),'complete')
        self.assertEqual(metadata.get('config-store'),'running')
        self.assertEqual(metadata.get('collector-version'),'1.7.2')
        self.assertNotIn('mirror-object',ET.tostring(metadata,encoding='unicode'))
        self.assertEqual(hierarchy_coverage(root)['parents'],{'Leaf':'Root','Root':''})
        self.assertEqual(_collect_device_group_entries(root)['Leaf']['parent'],'Root')

    def test_missing_readonly_does_not_turn_into_proven_flat_collection(self):
        root=capture(); root.remove(root.find('readonly'))
        strip_branches(root)
        self.assertFalse(hierarchy_coverage(root)['complete'])
        self.assertEqual(root.find('nc-device-group-hierarchy').get('status'),'incomplete')

    def test_per_entry_candidate_capture_preserves_same_hierarchy(self):
        root=capture(); response=ET.Element('response',{'status':'success'})
        result=ET.SubElement(response,'result')
        result.append(deepcopy(root.find('./readonly/devices/entry/device-group')))
        with patch('panorama_export.get_with_retry',return_value=(True,200,response,'success')) as request:
            metadata=fetch_hierarchy('synthetic.invalid','secret-test-key')
        self.assertEqual(request.call_args.args[2],HIERARCHY_XPATH)
        self.assertEqual(request.call_args.kwargs,{'timeout':25,'retry':False})
        assembled=build_export_root(list(deepcopy(root.find('./devices/entry/device-group'))),[],hierarchy=metadata)
        strip_branches(root,config_store='running')
        self.assertTrue(hierarchy_coverage(assembled)['complete'])
        self.assertEqual(hierarchy_coverage(root)['parents'],hierarchy_coverage(assembled)['parents'])
        self.assertEqual(metadata.get('config-store'),'candidate')
        self.assertEqual(metadata.get('collection-consistency'),'multi-request-not-atomic')

    def test_failed_or_empty_candidate_request_stays_unverified_without_running_fallback(self):
        empty=ET.fromstring('<response status="success"><result/></response>')
        for outcome in ((False,403,None,'forbidden'),(True,200,empty,'success')):
            with patch('panorama_export.get_with_retry',return_value=outcome) as request:
                metadata=fetch_hierarchy('synthetic.invalid','secret-test-key')
            self.assertEqual(request.call_count,1)
            self.assertEqual(metadata.get('status'),'incomplete')
            self.assertTrue(metadata.findall('error'))

    def test_branch_audit_failures_are_not_successful_empty_results(self):
        with patch('panorama_export.get_with_retry',return_value=(False,403,None,'forbidden')):
            self.assertEqual(audit_completeness('synthetic.invalid','key',set(),set(),return_status=True),([],[],'unverified'))

    def test_duplicate_conflicting_or_cyclic_hierarchy_is_not_preserved_as_complete(self):
        for variant in ('duplicate','conflicting','cyclic'):
            root=capture(); groups=root.find('./readonly/devices/entry/device-group')
            if variant=='duplicate': groups.append(deepcopy(groups[0]))
            elif variant=='conflicting': ET.SubElement(root.find("./devices/entry/device-group/entry[@name='Leaf']"),'parent-dg').text='Elsewhere'
            else: ET.SubElement(groups.find("entry[@name='Root']"),'parent-dg').text='Leaf'
            strip_branches(root)
            self.assertFalse(hierarchy_coverage(root)['complete'],variant)

    def test_generated_html_refuses_incomplete_device_policy_and_optimization(self):
        from html_common import build_panorama_site
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.xml'
            for complete in (True,False):
                root=capture()
                if not complete: root.remove(root.find('readonly'))
                path.write_bytes(ET.tostring(root))
                model=PaloPanoramaModel(path); model.load()
                row=model.firewall_view_rows()[0]
                self.assertEqual(row['available'],complete)
                if not complete:
                    self.assertIsNone(row['applicable_rules'])
                    self.assertIsNone(row['inherited_nat'])
                    self.assertEqual(model.optimization_findings(),[])
                    with self.assertRaisesRegex(ValueError,'ancestry is unverified'):
                        model.split_rules_for_serial(model.rules,'SERIAL','Leaf')
                out=Path(directory)/str(complete)
                build_panorama_site(model,out,viewer_version='1.7.2')
                policy=(out/'devices/SERIAL.html').read_text()
                if complete:
                    self.assertIn('inherited-rule',policy)
                    self.assertIn('local-rule',policy)
                else:
                    self.assertNotIn('inherited-rule',policy)
                    self.assertNotIn('local-rule',policy)
                    self.assertIn('unavailable',policy)
                    self.assertIn('Unavailable',(out/'firewalls.html').read_text())
                    self.assertIn('Optimization unavailable',(out/'optimization.html').read_text())
                    self.assertIn('Unused objects unavailable',(out/'unused.html').read_text())


if __name__=='__main__': unittest.main()
