"""Shared conservative CVE/CPE product and version matching."""

import re


def _numeric_version_parts(value):
    """Parse conservative dotted numeric versions; reject ambiguous formats."""
    value = str(value or "").strip()
    if not value or not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    try:
        return tuple(int(part) for part in value.split("."))
    except (TypeError, ValueError):
        return None


def _match_cve_version_range(
    detected_version,
    version=None,
    version_start_including=None,
    version_start_excluding=None,
    version_end_including=None,
    version_end_excluding=None,
):
    """Compare a detected numeric version with an NVD-style version range.

    Returns Version Match, Not Matched, or Unassessed.
    This is correlation evidence, not vulnerability confirmation.
    """
    detected = _numeric_version_parts(detected_version)
    if detected is None:
        return "Unassessed"

    bounds = (
        version,
        version_start_including,
        version_start_excluding,
        version_end_including,
        version_end_excluding,
    )
    parsed = {
        name: _numeric_version_parts(value)
        for name, value in (
            ("version", version),
            ("start_including", version_start_including),
            ("start_excluding", version_start_excluding),
            ("end_including", version_end_including),
            ("end_excluding", version_end_excluding),
        )
        if value is not None and str(value).strip()
    }

    if any(value is None for value in parsed.values()):
        return "Unassessed"

    if version is not None and str(version).strip():
        if any(
            value is not None and str(value).strip()
            for value in (
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding,
            )
        ):
            return "Unassessed"
        return "Version Match" if detected == parsed["version"] else "Not Matched"

    if version_start_including and version_start_excluding:
        return "Unassessed"
    if version_end_including and version_end_excluding:
        return "Unassessed"

    # Reject inverted or empty ranges before comparing the detected version.
    lower_bound = (
        parsed.get("start_including")
        or parsed.get("start_excluding")
    )
    upper_bound = (
        parsed.get("end_including")
        or parsed.get("end_excluding")
    )

    if lower_bound is not None and upper_bound is not None:
        if lower_bound > upper_bound:
            return "Unassessed"

        if lower_bound == upper_bound and (
            version_start_excluding or version_end_excluding
        ):
            return "Unassessed"

    if version_start_including and detected < parsed["start_including"]:
        return "Not Matched"
    if version_start_excluding and detected <= parsed["start_excluding"]:
        return "Not Matched"
    if version_end_including and detected > parsed["end_including"]:
        return "Not Matched"
    if version_end_excluding and detected >= parsed["end_excluding"]:
        return "Not Matched"

    if not any(
        value is not None and str(value).strip()
        for value in (
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        )
    ):
        return "Unassessed"

    return "Version Match"



def _match_nvd_cpe(
    product,
    detected_version,
    criteria,
    version_start_including=None,
    version_start_excluding=None,
    version_end_including=None,
    version_end_excluding=None,
):
    """Conservatively compare a detected product/version with an NVD CPE.

    Returns Version Match, Not Matched, or Unassessed.
    This is correlation evidence, not vulnerability confirmation.
    """
    if (
        not isinstance(product, str)
        or not product.strip()
        or not isinstance(detected_version, str)
        or not detected_version.strip()
        or not isinstance(criteria, str)
    ):
        return "Unassessed"

    # Do not interpret escaped delimiters or other escaped CPE attributes.
    # They require a complete CPE 2.3 binding parser.
    if "\\" in criteria:
        return "Unassessed"

    parts = criteria.split(":")
    if len(parts) != 13 or parts[0:2] != ["cpe", "2.3"]:
        return "Unassessed"

    cpe_product = parts[4].strip().casefold()
    cpe_version = parts[5].strip()

    if not cpe_product or cpe_product in {"*", "-"}:
        return "Unassessed"

    detected_product = re.sub(r"[^a-z0-9]", "", product.casefold())
    normalized_cpe_product = re.sub(r"[^a-z0-9]", "", cpe_product)

    if not detected_product or not normalized_cpe_product:
        return "Unassessed"

    if detected_product != normalized_cpe_product:
        return "Not Matched"

    if cpe_version not in {"*", "-"}:
        return _match_cve_version_range(
            detected_version,
            version=cpe_version,
            version_start_including=version_start_including,
            version_start_excluding=version_start_excluding,
            version_end_including=version_end_including,
            version_end_excluding=version_end_excluding,
        )

    return _match_cve_version_range(
        detected_version,
        version_start_including=version_start_including,
        version_start_excluding=version_start_excluding,
        version_end_including=version_end_including,
        version_end_excluding=version_end_excluding,
    )




def _cpe_product_identity_match(product, criteria):
    """Return True/False for an identifiable CPE product, or None if unclear."""
    if (
        not isinstance(product, str)
        or not product.strip()
        or not isinstance(criteria, str)
        or "\\" in criteria
    ):
        return None

    parts = criteria.split(":")
    if len(parts) != 13 or parts[0:2] != ["cpe", "2.3"]:
        return None

    cpe_product = parts[4].strip().casefold()
    if not cpe_product or cpe_product in {"*", "-"}:
        return None

    detected = re.sub(r"[^a-z0-9]", "", product.casefold())
    candidate = re.sub(r"[^a-z0-9]", "", cpe_product)

    if not detected or not candidate:
        return None

    return detected == candidate


def _vulnerable_product_candidate_status(product, configurations):
    """Identify whether vulnerable CPE entries identify the observed product."""
    has_vulnerable_entry = False
    has_uncertain_entry = False
    visited = 0
    pending = list(configurations)

    while pending:
        item = pending.pop()
        visited += 1

        if visited > 10000:
            return "No Match" if has_vulnerable_entry else "Uncertain"

        if isinstance(item, list):
            pending.extend(item)
            continue

        if not isinstance(item, dict):
            has_uncertain_entry = True
            continue

        if "cpeMatch" in item:
            entries = item["cpeMatch"]

            if not isinstance(entries, list):
                has_uncertain_entry = True
            else:
                for entry in entries:
                    if not isinstance(entry, dict):
                        has_uncertain_entry = True
                        continue

                    if entry.get("vulnerable") is False:
                        continue

                    if entry.get("vulnerable") is not True:
                        has_uncertain_entry = True
                        continue

                    has_vulnerable_entry = True
                    identity_match = _cpe_product_identity_match(
                        product, entry.get("criteria")
                    )

                    if identity_match is True:
                        return "Match"

                    if identity_match is None:
                        has_uncertain_entry = True

        for key in ("nodes", "children"):
            if key in item:
                child_items = item[key]

                if not isinstance(child_items, list):
                    has_uncertain_entry = True
                else:
                    pending.extend(child_items)

    # An explicit vulnerable entry with no identifiable product match
    # must not create an exposure for an unrelated observed product.
    if has_vulnerable_entry:
        return "No Match"

    if has_uncertain_entry:
        return "Uncertain"

    return "No Vulnerable Entry"

def _match_nvd_configuration(product, detected_version, configurations):
    """Evaluate simple NVD OR configurations conservatively.

    Returns Version Match, Not Matched, or Unassessed.
    Complex configuration logic is deliberately not flattened.
    """
    if (
        not isinstance(product, str)
        or not product.strip()
        or not isinstance(detected_version, str)
        or not detected_version.strip()
        or not isinstance(configurations, list)
        or not configurations
        or len(configurations) > 20
    ):
        return "Unassessed"

    # Establish product identity before accepting an inconclusive configuration.
    candidate_status = _vulnerable_product_candidate_status(
        product, configurations
    )

    if candidate_status == "No Match":
        return "Not Matched"

    if candidate_status != "Match":
        return "Unassessed"

    # Multiple configuration branches and nested Boolean expressions
    # require a complete NVD configuration-tree evaluator.
    if len(configurations) != 1:
        return "Unassessed"

    configuration = configurations[0]
    if not isinstance(configuration, dict):
        return "Unassessed"

    nodes = configuration.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 1:
        return "Unassessed"

    node = nodes[0]
    if not isinstance(node, dict):
        return "Unassessed"

    if (
        node.get("operator") != "OR"
        or node.get("negate", False) is not False
        or node.get("children") not in (None, [])
    ):
        return "Unassessed"

    cpe_matches = node.get("cpeMatch")
    if (
        not isinstance(cpe_matches, list)
        or not cpe_matches
        or len(cpe_matches) > 100
    ):
        return "Unassessed"

    results = []
    for entry in cpe_matches:
        if not isinstance(entry, dict):
            return "Unassessed"

        # Environmental CPE entries are not evidence that the product
        # itself is affected.
        if entry.get("vulnerable") is not True:
            continue

        criteria = entry.get("criteria")
        if not isinstance(criteria, str):
            return "Unassessed"

        result = _match_nvd_cpe(
            product,
            detected_version,
            criteria,
            version_start_including=entry.get("versionStartIncluding"),
            version_start_excluding=entry.get("versionStartExcluding"),
            version_end_including=entry.get("versionEndIncluding"),
            version_end_excluding=entry.get("versionEndExcluding"),
        )
        results.append(result)

    if not results:
        return "Unassessed"

    if "Version Match" in results:
        return "Version Match"

    if all(result == "Not Matched" for result in results):
        return "Not Matched"

    return "Unassessed"
