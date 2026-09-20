"""Conservative Panorama hierarchy evidence shared by collection and review.

An omitted parent is unknown unless the group is present in the native readonly
hierarchy, has an explicit parent-dg element (empty means root), or carries a
validated nc.panorama-hierarchy.v1 assertion. Names never imply ancestry.
"""
import hashlib
from pathlib import Path
from xml.etree import ElementTree as ET

SCHEMA = "nc.panorama-hierarchy.v1"
TAG = "nc-device-group-hierarchy"
MAX_XML_BYTES = 128 * 1024 * 1024


def _root(value):
    if hasattr(value, "findall"):
        return value
    if isinstance(value, Path) or (isinstance(value, str) and not value.lstrip().startswith("<")):
        with Path(value).open("rb") as stream:
            value = stream.read(MAX_XML_BYTES + 1)
    if isinstance(value, str):
        value = value.encode("utf-8")
    if len(value) > MAX_XML_BYTES:
        raise ValueError("Panorama hierarchy input exceeds 128 MiB")
    if b"\x00" in value:
        raise ValueError("NUL/UTF-16/UTF-32 XML is not supported; supply a UTF-8 capture")
    value.decode("utf-8-sig")
    # The standalone collector supports Python+requests installations without
    # defusedxml. Explicitly reject declarations before the stdlib parser.
    import re
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", value, re.I):
        raise ValueError("DTD/entity declarations are not allowed in Panorama captures")
    return ET.fromstring(value)


def hierarchy_coverage(value):
    """Return explicit completeness, parent map, missing evidence and errors."""
    errors, missing, assertions, sources = [], [], {}, set()
    try:
        root = _root(value)
    except (OSError, ValueError, ET.ParseError, TypeError) as exc:
        return {"complete": False, "status": "incomplete", "parents": {}, "groups": [],
                "missing": [], "errors": ["Unreadable hierarchy input: " + str(exc)], "source": "unknown", "provenance": {}}
    groups = {}
    if root.tag != "config":
        errors.append("A native config root is required; unwrap a successful API result explicitly")
    collections = root.findall("nc-collection")
    if len(collections) > 1:
        errors.append("Multiple collection provenance blocks")
    for collection in collections:
        if collection.get("schema") != "nc.panorama-collection.v1":
            errors.append("Unsupported collection provenance contract")
        if collection.get("native-content") == "stubs":
            errors.append("Collector captured identity stubs, not complete native configuration")
        if collection.get("entry-coverage") == "partial" or collection.findall("missing"):
            errors.append("Collector reported missing native configuration entries or branches")
    for node in root.findall("./devices/entry/device-group/entry"):
        name = (node.get("name") or "").strip()
        if not name or name in groups:
            errors.append("Unnamed or duplicate native device group: " + name)
        groups[name] = node

    def add(name, parent, source):
        if not name:
            errors.append("Unnamed hierarchy identity")
            return
        previous = assertions.get(name)
        if previous is not None and previous != parent:
            errors.append("Conflicting device-group ancestry: " + name)
        else:
            assertions[name] = parent
        sources.add(source)

    for name, node in groups.items():
        links = node.findall("parent-dg")
        if len(links) > 1:
            errors.append("Duplicate parent assertions: " + name)
        if links:
            add(name, (links[0].text or "").strip(), "explicit-parent-dg")
    seen = set()
    for node in root.findall("./readonly/devices/entry/device-group/entry"):
        name = (node.get("name") or "").strip()
        if name in seen:
            errors.append("Duplicate readonly hierarchy identity: " + name)
        seen.add(name)
        links = node.findall("parent-dg")
        if len(links) > 1:
            errors.append("Duplicate readonly parent assertions: " + name)
        add(name, (links[0].text or "").strip() if links else "", "native-readonly")

    provenance = {}
    metadata = root.findall(TAG)
    if len(metadata) > 1:
        errors.append("Multiple collector hierarchy metadata blocks")
    if metadata:
        meta = metadata[0]
        provenance = {k: v for k, v in meta.attrib.items() if k not in {"schema", "status"}}
        if meta.get("schema") != SCHEMA or meta.get("status") not in {"complete", "incomplete"}:
            errors.append("Unsupported collector hierarchy contract")
        if meta.get("status") != "complete":
            errors.append("Collector did not establish complete device-group ancestry")
        seen = set()
        for entry in meta.findall("entry"):
            name = (entry.get("name") or "").strip()
            parent = entry.get("parent")
            if name in seen or parent is None or entry.get("root") != ("yes" if parent == "" else "no"):
                errors.append("Invalid collector parent/root assertion: " + name)
                continue
            seen.add(name)
            add(name, parent, "collector-hierarchy")
        errors.extend((e.text or "Hierarchy collection error").strip() for e in meta.findall("error"))

    for name in groups:
        if name not in assertions:
            missing.append(name)
    for name in assertions:
        walked, current = set(), name
        while current:
            if current in walked:
                errors.append("Device-group ancestry contains a cycle: " + name)
                break
            walked.add(current)
            if current not in assertions:
                errors.append("Parent has no hierarchy assertion: " + current)
                break
            if name in groups and current not in groups:
                errors.append("Ancestor configuration was not captured: " + current)
            current = assertions[current]
    if not groups:
        errors.append("No native device-group configuration was captured")
    if missing:
        errors.append("Device-group ancestry was not captured for: " + ", ".join(sorted(missing)))
    errors = list(dict.fromkeys(errors))
    complete = not errors and not missing
    return {"complete": complete, "status": "complete" if complete else "incomplete",
            "parents": dict(sorted(assertions.items())), "groups": sorted(groups),
            "missing": sorted(missing), "errors": errors,
            "source": "+".join(sorted(sources)) or "unknown", "provenance": provenance}


def hierarchy_metadata(coverage, *, source="", config_store="unknown", observed_at="", source_tree_sha256="", collector_version="", collection_consistency="", names=None):
    """A minimal inert assertion block; contains no objects, rules or secrets."""
    attributes = {"schema": SCHEMA, "status": coverage["status"],
                  "source": source or coverage.get("source", "unknown"), "config-store": config_store}
    if observed_at:
        attributes["observed-at"] = observed_at
    if source_tree_sha256:
        attributes["source-tree-sha256"] = source_tree_sha256
    if collector_version:
        attributes["collector-version"] = collector_version
    if collection_consistency:
        attributes["collection-consistency"] = collection_consistency
    result = ET.Element(TAG, attributes)
    wanted = set(names) if names is not None else None
    for name, parent in sorted(coverage["parents"].items()):
        if wanted is None or name in wanted:
            ET.SubElement(result, "entry", {"name": name, "parent": parent, "root": "yes" if not parent else "no"})
    for name in coverage["missing"]:
        if wanted is None or name in wanted:
            ET.SubElement(result, "missing", {"name": name})
    for message in coverage["errors"]:
        ET.SubElement(result, "error").text = message
    return result


def preserve_hierarchy(config, *, source="native-config", config_store="unknown", observed_at=""):
    """Record native assertions before callers discard the readonly mirror."""
    coverage = hierarchy_coverage(config)
    digest = hashlib.sha256(ET.tostring(config, encoding="utf-8")).hexdigest()
    metadata = hierarchy_metadata(coverage, source=source, config_store=config_store,
                                  observed_at=observed_at, source_tree_sha256=digest)
    for old in config.findall(TAG):
        config.remove(old)
    config.append(metadata)
    return coverage
