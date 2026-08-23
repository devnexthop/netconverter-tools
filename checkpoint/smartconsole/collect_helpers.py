"""Pure helpers for Check Point Management API collection (no network)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


VPN_MEMBER_FIELDS = (
    "gateways",
    "center-gateways",
    "satellite-gateways",
    "participant-gateways",
)

VPN_SHOW_BY_FILE = {
    "vpn-communities-meshed.json": "show-vpn-community-meshed",
    "vpn-communities-star.json": "show-vpn-community-star",
    "vpn-communities-remote-access.json": "show-vpn-community-remote-access",
}


def _is_layer_obj(item: Any) -> bool:
    return isinstance(item, dict) and bool(item.get("name") or item.get("uid"))


def https_layer_refs(pkg_detail: Any) -> List[dict]:
    """HTTPS inspection layers referenced by a show-package body.

    Check Point has shipped several shapes:
      * https-layers: list
      * https-inspection-layer: one object
      * https-inspection-layers: list OR inbound/outbound dict (R81 CMA)
      * https-inspection-policy: bool, or a dict wrapping any of the above
    """
    if not isinstance(pkg_detail, dict):
        return []
    found: List[dict] = []

    def add(item: Any) -> None:
        if _is_layer_obj(item):
            found.append(item)
            return
        if isinstance(item, list):
            for child in item:
                add(child)
            return
        if isinstance(item, dict):
            for child in item.values():
                add(child)

    add(pkg_detail.get("https-layers"))
    add(pkg_detail.get("https-inspection-layer"))
    add(pkg_detail.get("https-inspection-layers"))
    hip = pkg_detail.get("https-inspection-policy")
    if isinstance(hip, dict):
        add(hip.get("https-layers"))
        add(hip.get("https-inspection-layer"))
        add(hip.get("https-inspection-layers"))

    out: List[dict] = []
    seen = set()
    for layer in found:
        key = layer.get("name") or layer.get("uid")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(layer)
    return out


def exception_layer_uid(rule: Any) -> Optional[str]:
    """UID (or name) of the exceptions layer on a threat-prevention rule."""
    if not isinstance(rule, dict):
        return None
    el = rule.get("exceptions-layer")
    if isinstance(el, dict):
        uid = el.get("uid") or el.get("name")
        return uid if uid else None
    if isinstance(el, str) and el.strip():
        return el.strip()
    return None


def threat_exception_payload(
    package_name: str = "",
    rule_uid: Optional[str] = None,
    rule_number: Any = None,
    layer_name: Optional[str] = None,
    layer_uid: Optional[str] = None,
    offset: int = 0,
    limit: int = 500,
    include_layer_uid: bool = False,
) -> Dict[str, Any]:
    """Payload for show-threat-rule-exception-rulebase.

    Management API requires a layer identifier plus rule-uid. R81 CMA
    accepts ``layer-name`` / ``name`` and returns
    ``generic_err_invalid_parameter_name`` for ``layer-uid``. Newer APIs
    may require ``layer-uid`` — callers retry with ``include_layer_uid``.
    """
    payload: Dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "use-object-dictionary": True,
    }
    if package_name:
        payload["package"] = package_name
    if rule_uid:
        payload["rule-uid"] = rule_uid
    if rule_number is not None:
        payload["rule-number"] = str(rule_number)
    if layer_name:
        payload["layer-name"] = layer_name
        payload["name"] = layer_name
    if include_layer_uid and layer_uid:
        payload["layer-uid"] = layer_uid
    return payload


def vpn_member_fields(comm: Any) -> Dict[str, list]:
    if not isinstance(comm, dict):
        return {}
    out = {}
    for key in VPN_MEMBER_FIELDS:
        val = comm.get(key)
        if isinstance(val, list) and val:
            out[key] = val
    return out


def vpn_membership_empty(comm: Any) -> bool:
    return not vpn_member_fields(comm)


def merge_vpn_detail(base: dict, detail: Any) -> dict:
    """Copy membership lists from a per-UID show onto the list-API object."""
    if not isinstance(detail, dict):
        return base
    if isinstance(detail.get("object"), dict):
        detail = detail["object"]
    out = dict(base)
    members = vpn_member_fields(detail)
    out.update(members)
    return out


def unwrap_vpn_show(data: Any) -> Optional[dict]:
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("object"), dict):
        return data["object"]
    if data.get("uid") or data.get("type"):
        return data
    return None
