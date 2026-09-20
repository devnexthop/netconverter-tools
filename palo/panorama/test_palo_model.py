"""Tests for shared Palo XML model (public-repo HTML collector)."""

from __future__ import annotations

import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

_TECH = Path(__file__).resolve().parent
_COMMON = _TECH.parent / "common"
_ROOT = _TECH.parents[1]
for _p in (_ROOT, _COMMON, _TECH):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from palo_model import (  # noqa: E402
    PaloPanoramaModel,
    PaloStandaloneModel,
    dedupe_routes,
    detect_export_kind,
    load_palo_model,
)


def test_dedupe_routes():
    routes = [
        {"name": "a", "destination": "10.0.0.0/8", "nexthop": "1.1.1.1", "interface": ""},
        {"name": "a", "destination": "10.0.0.0/8", "nexthop": "1.1.1.1", "interface": ""},
        {"name": "b", "destination": "0.0.0.0/0", "nexthop": "2.2.2.2", "interface": "eth1"},
    ]
    assert len(dedupe_routes(routes)) == 2


def test_detect_export_kind():
    pano = (
        "<config><panorama/><devices><entry name='localhost'>"
        "<device-group><entry name='DG1'/></device-group>"
        "</entry></devices></config>"
    )
    standalone = "<config><devices><entry name='localhost'><vsys><entry name='vsys1'/></vsys></entry></devices></config>"
    assert detect_export_kind(ET.fromstring(pano)) == "panorama"
    assert detect_export_kind(ET.fromstring(standalone)) == "standalone"


def test_palo_standalone_minimal():
    xml = """<config><devices><entry name="localhost">
      <vsys><entry name="vsys1"><rulebase><security><rules>
        <entry name="r1"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action></entry>
      </rules></security></rulebase></entry></vsys>
    </entry></devices></config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloStandaloneModel(path)
        model.load()
        assert model.stats["security_rules"] == 1
        assert model.rules[0]["name"] == "r1"
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_pre_post_rulebase():
    xml = """<config><panorama/><devices><entry name="localhost">
      <device-group><entry name="DG1">
        <pre-rulebase><security><rules>
          <entry name="pre1"><from><member>any</member></from><to><member>any</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>any</member></application><service><member>any</member></service>
          <action>allow</action></entry>
        </rules></security></pre-rulebase>
        <post-rulebase><security><rules>
          <entry name="post1"><from><member>any</member></from><to><member>any</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>any</member></application><service><member>any</member></service>
          <action>deny</action></entry>
        </rules></security></post-rulebase>
      </entry></device-group>
    </entry></devices></config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        assert model.stats["security_rules"] == 2
        names = {r["name"] for r in model.rules}
        assert names == {"pre1", "post1"}
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_template_routing():
    xml = """<config><panorama/><devices><entry name="localhost">
      <template><entry name="T1">
        <config><devices><entry name="localhost.localdomain">
          <vsys><entry name="vsys1"><display-name>Prod</display-name>
            <import><network><virtual-router><member>VR1</member></virtual-router></network></import>
          </entry><entry name="vsys2"/></vsys>
          <network><virtual-router><entry name="VR1">
            <interface><member>ethernet1/1</member></interface>
            <routing-table><ip><static-route>
              <entry name="def"><destination>0.0.0.0/0</destination>
              <nexthop><ip-address>10.0.0.1</ip-address></nexthop></entry>
            </static-route></ip></routing-table>
            <protocol><bgp><enable>yes</enable><router-id>1.1.1.1</router-id><local-as>65001</local-as>
              <peer><entry name="p1"><peer-as>65000</peer-as><peer-address>10.0.0.2</peer-address></entry></peer>
            </bgp><ospf><enable>yes</enable><area><entry name="0.0.0.0">
              <interface><entry name="ethernet1/1"/></interface>
            </entry></area></ospf></protocol>
          </entry></virtual-router></network>
        </entry></devices></config>
      </entry></template>
      <template-stack><entry name="ST1"><templates><member>T1</member></templates>
        <devices><entry name="001"/></devices>
      </entry></template-stack>
      <device-group><entry name="DG1"><devices><entry name="001"><vsys><member>vsys1</member></vsys></entry></devices>
      </entry></device-group>
    </entry></devices></config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        assert model.stats["virtual_routers"] == 1
        assert model.stats["routes"] == 1
        assert model.stats["bgp_peers"] >= 1
        assert model.stats["ospf_areas"] == 1
        assert model.stats["template_vsys"] == 2
        assert model.managed_devices[0]["template_vsys"] == "vsys1, vsys2"
        route = model.routes[0]
        assert route["template"] == "T1"
        assert route["virtual_router"] == "VR1"
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_merge_duplicate_templates():
    xml = """<config><panorama/><devices><entry name="localhost">
      <template>
        <entry name="T-rich">
          <config><devices><entry name="localhost.localdomain">
            <vsys><entry name="vsys1">
              <import><network><virtual-router><member>VR1</member></virtual-router></network></import>
            </entry></vsys>
            <network><virtual-router><entry name="VR1">
              <interface><member>eth1</member></interface>
              <routing-table><ip><static-route>
                <entry name="r1"><destination>10.0.0.0/8</destination></entry>
              </static-route></ip></routing-table>
            </entry></virtual-router></network>
          </entry></devices></config>
        </entry>
        <entry name="T-rich">
          <config><devices><entry name="localhost.localdomain">
            <vsys><entry name="vsys1"/><entry name="vsys2"/></vsys>
          </entry></devices></config>
        </entry>
      </template>
    </entry></devices></config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        rows = [t for t in model.templates if t["name"] == "T-rich"]
        assert len(rows) == 1
        assert rows[0]["virtual_router_count"] == 1
        assert rows[0]["static_route_count"] == 1
        assert len([v for v in model.template_vsys if v["template"] == "T-rich"]) == 1
    finally:
        path.unlink(missing_ok=True)


def test_load_palo_model_dispatch():
    pano = (
        "<config><panorama/><devices><entry name='localhost'>"
        "<device-group><entry name='DG1'/></device-group>"
        "</entry></devices></config>"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(pano)
        path = Path(f.name)
    try:
        model = load_palo_model(path, mode="panorama")
        assert isinstance(model, PaloPanoramaModel)
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_merge_duplicate_stacks():
    xml = """<config><panorama/><devices><entry name="localhost">
      <template><entry name="T1">
        <config><devices><entry name="localhost.localdomain">
          <deviceconfig><system><hostname>SITE-FW-01</hostname></system></deviceconfig>
          <vsys><entry name="vsys1"/></vsys>
        </entry></devices></config>
      </entry></template>
      <template-stack>
        <entry name="ST1">
          <templates><member>T1</member></templates>
          <devices><entry name="001"/></devices>
        </entry>
        <entry name="ST1"><id>9</id></entry>
      </template-stack>
      <device-group><entry name="DG1">
        <devices><entry name="001"><vsys><entry name="vsys1"/></vsys></entry></devices>
      </entry></device-group>
    </entry></devices></config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        assert model.stats["template_stacks"] == 1
        assert model.managed_devices[0]["hostname"] == "SITE-FW-01"
        assert model.managed_devices[0]["template_vsys"] == "vsys1"
        assert model.managed_devices[0]["vsys"] == "vsys1"
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_decrypt_shared_interfaces():
    xml = """<config>
      <devices><entry name="localhost">
        <deviceconfig><system><hostname>PANO</hostname></system></deviceconfig>
        <device-group><entry name="DG1">
          <pre-rulebase><decryption><rules>
            <entry name="d1"><action>no-decrypt</action>
              <type><ssl-forward-proxy/></type>
              <from><member>trust</member></from><to><member>untrust</member></to>
              <source><member>any</member></source><destination><member>any</member></destination>
              <service><member>any</member></service>
            </entry>
          </rules></decryption></pre-rulebase>
          <external-list><entry name="EDL1"><type><ip><url>https://example/edl</url></ip></type></entry></external-list>
        </entry></device-group>
        <template><entry name="T1">
          <config><devices><entry name="localhost.localdomain">
            <network><interface><ethernet>
              <entry name="ethernet1/1"><layer3><ip><entry name="10.1.1.1/24"/></ip></layer3>
                <comment>untrust</comment></entry>
            </ethernet></interface></network>
          </entry></devices></config>
        </entry></template>
      </entry></devices>
      <shared>
        <address><entry name="shared-host"><ip-netmask>10.9.9.9</ip-netmask></entry></address>
        <service><entry name="udp-10002"><protocol><udp><port>10002</port></udp></protocol></entry></service>
      </shared>
    </config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        assert model.hostname == "PANO"
        assert model.stats["decrypt_rules"] == 1
        assert model.decrypt_rules[0]["action"] == "no-decrypt"
        assert model.stats["edls"] == 1
        assert model.edls[0]["url"] == "https://example/edl"
        assert any(a["name"] == "shared-host" and a["device_group"] == "Shared" for a in model.addresses)
        assert any(s["name"] == "udp-10002" and s["device_group"] == "Shared" for s in model.services)
        assert model.stats["interfaces"] == 1
        assert model.interfaces[0]["ip"] == "10.1.1.1/24"
    finally:
        path.unlink(missing_ok=True)


def test_palo_panorama_gp_ipsec_profiles_ha_logfwd():
    xml = """<config>
      <devices><entry name="localhost">
        <deviceconfig><system><hostname>PANO</hostname></system></deviceconfig>
        <device-group><entry name="DG1">
          <post-rulebase><application-override><rules>
            <entry name="Veeam_Override">
              <from><member>trust</member></from><to><member>untrust</member></to>
              <source><member>Veeam</member></source><destination><member>any</member></destination>
              <port>443</port><protocol>tcp</protocol><application>veeam</application>
            </entry>
          </rules></application-override></post-rulebase>
          <log-settings><profiles>
            <entry name="AUS-Log-Forwarding">
              <match-list>
                <entry name="All_Traffic">
                  <send-syslog><member>SYSLOG1</member></send-syslog>
                  <log-type>traffic</log-type>
                </entry>
              </match-list>
            </entry>
          </profiles></log-settings>
        </entry></device-group>
        <template><entry name="T1">
          <config><devices><entry name="localhost">
            <vsys><entry name="vsys1">
              <global-protect><global-protect-portal>
                <entry name="globalprotect">
                  <portal-config>
                    <local-address>
                      <ip><ipv4>1.2.3.4/32</ipv4></ip>
                      <interface>loopback.10</interface>
                    </local-address>
                    <ssl-tls-service-profile>GP-SSL</ssl-tls-service-profile>
                    <client-auth><entry name="Entra">
                      <authentication-profile>Entra_PAN_GP_VPN</authentication-profile>
                    </entry></client-auth>
                  </portal-config>
                </entry>
              </global-protect-portal>
              <global-protect-gateway>
                <entry name="SF-gw">
                  <client-auth><entry name="Entra">
                    <authentication-profile>Entra_PAN_GP_VPN</authentication-profile>
                  </entry></client-auth>
                </entry>
              </global-protect-gateway></global-protect>
            </entry></vsys>
            <network>
              <ike><crypto-profiles>
                <ike-crypto-profiles>
                  <entry name="default">
                    <encryption><member>aes-256-cbc</member></encryption>
                    <hash><member>sha256</member></hash>
                    <dh-group><member>group14</member></dh-group>
                  </entry>
                </ike-crypto-profiles>
                <ipsec-crypto-profiles>
                  <entry name="default">
                    <esp><encryption><member>aes-256-gcm</member></encryption></esp>
                    <dh-group>group14</dh-group>
                  </entry>
                </ipsec-crypto-profiles>
              </crypto-profiles>
              <gateway>
                <entry name="IKE-PEER">
                  <peer-address><ip>9.9.9.9</ip></peer-address>
                  <local-address><interface>ethernet1/1</interface></local-address>
                </entry>
              </gateway></ike>
              <tunnel>
                <ipsec><entry name="TUN1">
                  <tunnel-interface>tunnel.1</tunnel-interface>
                  <auto-key><ike-gateway><member>IKE-PEER</member></ike-gateway></auto-key>
                </entry></ipsec>
                <global-protect-gateway>
                  <entry name="SF-gw">
                    <local-address>
                      <ip><ipv4>1.2.3.4/32</ipv4></ip>
                      <interface>loopback.10</interface>
                    </local-address>
                    <tunnel-interface>tunnel.10</tunnel-interface>
                    <ipsec><ipsec-crypto-profile>gp_ipsec_secure</ipsec-crypto-profile></ipsec>
                  </entry>
                </global-protect-gateway>
              </tunnel>
            </network>
          </entry></devices></config>
        </entry></template>
        <template-stack><entry name="HA_stack">
          <templates><member>T1</member></templates>
          <devices>
            <entry name="021209011978">
              <variable>
                <entry name="$ha1a"><type><ip-netmask>192.168.10.2</ip-netmask></type></entry>
                <entry name="$hapriority"><type><device-priority>90</device-priority></type></entry>
              </variable>
            </entry>
          </devices>
        </entry></template-stack>
        <log-collector-group><entry name="NOS-PAPAN-01">
          <log-settings>
            <globalprotect><match-list>
              <entry name="Syslog_Forward_GP">
                <send-syslog><member>NOS-SYSLOG</member></send-syslog>
              </entry>
            </match-list></globalprotect>
          </log-settings>
        </entry></log-collector-group>
      </entry></devices>
      <shared>
        <profile-group>
          <entry name="default">
            <virus><member>Outbound-AV</member></virus>
          </entry>
        </profile-group>
        <profiles>
          <virus><entry name="Outbound-AV"/></virus>
          <decryption><entry name="Recommended_Decryption_Profile"/></decryption>
        </profiles>
      </shared>
    </config>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        assert model.stats["app_overrides"] == 1
        assert model.app_overrides[0]["application"] == "veeam"
        assert model.stats["gp_portals"] == 1
        assert model.gp_portals[0]["ip"] == "1.2.3.4/32"
        assert model.stats["gp_gateways"] == 1
        gw = model.gp_gateways[0]
        assert gw["name"] == "SF-gw"
        assert gw["tunnel_interface"] == "tunnel.10"
        assert gw["auth"] == "Entra_PAN_GP_VPN"
        kinds = {o["kind"] for o in model.ike_objects}
        assert "ike-crypto" in kinds and "ipsec-crypto" in kinds and "ike-gateway" in kinds
        assert model.stats["ipsec_tunnels"] == 1
        assert any(p["kind"] == "profile-group" and p["name"] == "default" for p in model.security_profiles)
        assert any(p["kind"] == "virus" and p["name"] == "Outbound-AV" for p in model.security_profiles)
        assert any(v["name"] == "$ha1a" and v["value"] == "192.168.10.2" for v in model.ha_variables)
        assert any(p["name"] == "AUS-Log-Forwarding" for p in model.log_forwarding)
        assert any(p["name"] == "Syslog_Forward_GP" for p in model.log_forwarding)
    finally:
        path.unlink(missing_ok=True)


_FW_XML = """<config><panorama/>
<shared>
  <pre-rulebase><security><rules>
    <entry name="shared-pre">
      <from><member>any</member></from><to><member>any</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <application><member>any</member></application><service><member>any</member></service>
      <action>allow</action>
    </entry>
  </rules></security></pre-rulebase>
</shared>
<devices><entry name="localhost.localdomain"><device-group>
  <entry name="Parent"><parent-dg/>
    <pre-rulebase><security><rules>
      <entry name="parent-pre">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></pre-rulebase>
  </entry>
  <entry name="Dallas">
    <parent-dg>Parent</parent-dg>
    <devices>
      <entry name="016201002144"/>
      <entry name="016201008423"/>
    </devices>
    <pre-rulebase><security><rules>
      <entry name="all-in-dg">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="only-first">
        <target><negate>no</negate>
          <devices><entry name="016201002144"/></devices>
        </target>
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="only-second">
        <target>
          <devices><entry name="016201008423"/></devices>
        </target>
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>deny</action>
      </entry>
    </rules></security></pre-rulebase>
  </entry>
  <entry name="Austin">
    <parent-dg>Parent</parent-dg>
    <devices><entry name="AUS-ONLY"/></devices>
    <pre-rulebase><security><rules>
      <entry name="sibling-only">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></pre-rulebase>
  </entry>
</device-group></entry></devices></config>"""


def test_rule_target_and_firewall_view():
    from palo_model import rule_applies_to_serial

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(_FW_XML)
        path = Path(f.name)
    try:
        model = PaloPanoramaModel(path)
        model.load()
        by_name = {r["name"]: r for r in model.rules if r.get("device_group") == "Dallas"}
        assert by_name["only-first"]["target_serials"] == ["016201002144"]
        assert by_name["only-first"]["target_negate"] is False
        assert by_name["all-in-dg"]["target_serials"] == []
        assert rule_applies_to_serial(by_name["only-first"], "016201002144") is True
        assert rule_applies_to_serial(by_name["only-first"], "016201008423") is False
        assert rule_applies_to_serial(by_name["all-in-dg"], "016201008423") is True

        mine_a, other_a = model.split_rules_for_serial(model.rules, "016201002144", "Dallas")
        names_a = {r["name"] for r in mine_a}
        assert "shared-pre" in names_a
        assert "parent-pre" in names_a
        assert "all-in-dg" in names_a
        assert "only-first" in names_a
        assert "only-second" not in names_a
        assert "sibling-only" not in names_a
        assert {r["name"] for r in other_a} == {"only-second"}

        mine_b, _ = model.split_rules_for_serial(model.rules, "016201008423", "Dallas")
        names_b = {r["name"] for r in mine_b}
        assert "only-second" in names_b
        assert "only-first" not in names_b
        assert "sibling-only" not in names_b

        mine_aus, _ = model.split_rules_for_serial(model.rules, "AUS-ONLY", "Austin")
        names_aus = {r["name"] for r in mine_aus}
        assert "sibling-only" in names_aus
        assert "all-in-dg" not in names_aus
        assert "parent-pre" in names_aus

        rows = {r["serial"]: r for r in model.firewall_view_rows()}
        assert rows["016201002144"]["applicable_rules"] == 4  # shared + parent + all-in-dg + only-first
        assert rows["016201002144"]["inherited_rules"] == 5  # + only-second
        assert rows["016201008423"]["applicable_rules"] == 4
        assert len(model.managed_devices) == 3
    finally:
        path.unlink(missing_ok=True)


# Yesterday's Nossaman running-config pull (not in git). Skip in CI.
_NOSSAMAN_DIR = Path(
    "/Users/marcinzgola/Library/CloudStorage/OneDrive-NEXTHOPLLC/"
    "netconverter-clients/nossaman"
)
_NOSSAMAN_XML = next(_NOSSAMAN_DIR.glob("*2125*running*.xml"), Path("/nonexistent"))


def test_nossaman_firewall_view_twelve_boxes():
    """A legacy stripped capture supports inventory, never proven flat policy."""
    if not _NOSSAMAN_XML.is_file():
        print("skip test_nossaman_firewall_view_twelve_boxes (XML not on this machine)")
        return
    model = PaloPanoramaModel(_NOSSAMAN_XML)
    model.load()
    rows = {r["serial"]: r for r in model.firewall_view_rows()}
    assert len(rows) == 12, f"expected 12 firewalls, got {len(rows)}"
    assert len(model.managed_devices) == 12

    aus_serial = "021201005286"
    assert aus_serial in rows
    assert rows[aus_serial]["hostname"] == "AUS-PAFW-01"
    assert rows[aus_serial]["device_group"] == "AUS"
    assert not model.hierarchy_coverage["complete"]
    assert all(row["available"] is False for row in rows.values())
    assert all(row["applicable_rules"] is None and row["inherited_rules"] is None for row in rows.values())
    assert model.optimization_findings() == []
    try:
        model.split_rules_for_serial(model.rules, aus_serial, "AUS")
    except ValueError as exc:
        assert "ancestry is unverified" in str(exc)
    else:
        raise AssertionError("Incomplete capture was presented as device policy")



if __name__ == "__main__":
    tests = [
        test_dedupe_routes,
        test_detect_export_kind,
        test_palo_standalone_minimal,
        test_palo_panorama_pre_post_rulebase,
        test_palo_panorama_template_routing,
        test_palo_panorama_merge_duplicate_templates,
        test_palo_panorama_merge_duplicate_stacks,
        test_palo_panorama_decrypt_shared_interfaces,
        test_palo_panorama_gp_ipsec_profiles_ha_logfwd,
        test_load_palo_model_dispatch,
        test_rule_target_and_firewall_view,
        test_nossaman_firewall_view_twelve_boxes,
    ]
    for fn in tests:
        fn()
        print(f"ok {fn.__name__}")
    print(f"All {len(tests)} tests passed.")


def test_nat_pool_dependencies_preserve_display_summary():
    from palo_model import _nat_translation, _nat_translation_refs
    entry = ET.fromstring('''<entry><source-translation><dynamic-ip-and-port>
      <translated-address><member>pool-a</member><member>pool-b</member></translated-address>
      </dynamic-ip-and-port></source-translation><destination-translation>
      <translated-address>server</translated-address><translated-port>8443</translated-port>
      </destination-translation></entry>''')
    assert _nat_translation(entry, 'source-translation') == 'pool-a'
    assert _nat_translation_refs(entry, 'source-translation') == ['pool-a', 'pool-b']
    assert _nat_translation_refs(entry, 'destination-translation') == ['server']
    for cls in (PaloStandaloneModel, PaloPanoramaModel):
        model = cls(Path('unused.xml'))
        row = model._parse_nat_rule(entry, 'scope', 'pre-rulebase')
        assert row['source_translation_refs'] == ['pool-a', 'pool-b']
        assert row['dest_translation_refs'] == ['server']
