# test_collect_helpers.py — no Management API required
from __future__ import annotations

import traceback

from collect_helpers import (
    exception_layer_uid,
    https_layer_refs,
    merge_vpn_detail,
    threat_exception_payload,
    vpn_membership_empty,
)

_FAILED = 0


def _test(fn):
    global _FAILED
    try:
        fn()
        print("ok   {}".format(fn.__name__))
    except AssertionError as exc:
        _FAILED += 1
        print("FAIL {}: {}".format(fn.__name__, exc))
    except Exception:
        _FAILED += 1
        print("ERROR {}".format(fn.__name__))
        traceback.print_exc()
    return fn


@_test
def test_https_layers_r81_bool_policy_plus_dict():
    pkg = {
        "https-inspection-policy": True,
        "https-inspection-layers": {
            "inbound-https-layer": {"uid": "in-1", "name": "Default Inbound Layer"},
            "outbound-https-layer": {"uid": "out-1", "name": "Default Outbound Layer"},
        },
        "https-layers": None,
        "https-inspection-layer": None,
    }
    names = [ly["name"] for ly in https_layer_refs(pkg)]
    assert names == ["Default Inbound Layer", "Default Outbound Layer"]


@_test
def test_https_layers_nested_under_policy_dict():
    pkg = {
        "https-inspection-policy": {
            "https-inspection-layers": [
                {"name": "Inbound"},
                {"name": "Outbound"},
            ]
        }
    }
    assert [ly["name"] for ly in https_layer_refs(pkg)] == ["Inbound", "Outbound"]


@_test
def test_https_layers_dedupe():
    pkg = {
        "https-layers": [{"name": "Default Inbound Layer", "uid": "in-1"}],
        "https-inspection-layers": {
            "inbound-https-layer": {"name": "Default Inbound Layer", "uid": "in-1"},
        },
    }
    assert len(https_layer_refs(pkg)) == 1


@_test
def test_https_layers_empty_when_policy_bool_only():
    assert https_layer_refs({"https-inspection-policy": True}) == []


@_test
def test_exception_payload_sends_layer_with_rule_uid():
    payload = threat_exception_payload(
        package_name="EDGE_PKG",
        rule_uid="rule-1",
        layer_name="EDGE Threat Prevention",
        layer_uid="layer-uid-1",
    )
    assert payload["rule-uid"] == "rule-1"
    assert payload["layer-name"] == "EDGE Threat Prevention"
    assert payload["name"] == "EDGE Threat Prevention"
    assert payload["package"] == "EDGE_PKG"
    assert "layer-uid" not in payload


@_test
def test_exception_payload_layer_uid_opt_in():
    payload = threat_exception_payload(
        package_name="EDGE_PKG",
        rule_uid="rule-1",
        layer_name="EDGE Threat Prevention",
        layer_uid="layer-uid-1",
        include_layer_uid=True,
    )
    assert payload["layer-uid"] == "layer-uid-1"


@_test
def test_exception_layer_uid_string_or_object():
    assert exception_layer_uid({"exceptions-layer": "abc-def"}) == "abc-def"
    assert exception_layer_uid({"exceptions-layer": {"uid": "u1"}}) == "u1"
    assert exception_layer_uid({"exceptions-layer": {}}) is None


@_test
def test_vpn_membership_empty_and_merge():
    empty = {"uid": "c1", "gateways": [], "ike-phase-1": {}}
    assert vpn_membership_empty(empty) is True
    filled = merge_vpn_detail(empty, {
        "object": {"uid": "c1", "gateways": [{"name": "ALIUTMEDGE"}]},
    })
    assert vpn_membership_empty(filled) is False
    assert filled["gateways"][0]["name"] == "ALIUTMEDGE"


if __name__ == "__main__":
    raise SystemExit(1 if _FAILED else 0)
