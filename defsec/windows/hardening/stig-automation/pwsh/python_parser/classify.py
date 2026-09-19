"""Classifies a parsed XCCDF rule's check-content into one of the CheckTypes used by
this repo's PowerShell scripts (Registry / UserRight / AuditPolicy), or leaves it
unclassified (Manual) when the check requires per-deployment parameters, GUI/zone
navigation, or human judgment that can't be reduced to a single queryable value.

This is intentionally conservative: a STIG hardening tool that mis-files a control
under the wrong CheckType produces a false compliance signal, which is worse than
leaving it as a TODO for a human to classify.
"""
import re

from xccdf_parser import registry_path_name
from windows_known_values import USER_RIGHTS, AUDIT_NAME_TO_GUID

_AUDIT_CATEGORY_RE = re.compile(
    r'([A-Z][\w/ ]+?)\s*>>\s*([A-Z][\w/ ]+?)\s*-\s*(Success and Failure|Success|Failure)',
    re.IGNORECASE)

_USER_RIGHT_RE = re.compile(r'`?"([A-Z][^"`]{2,60})`?"\s+user right', re.IGNORECASE)


def classify(rec):
    """Returns (check_type, fields) where fields is a dict of rule-specific properties,
    or ('Manual', {}) if no confident pattern match was found."""
    blob = rec['title'] + '\n' + rec['fixtext'] + '\n' + rec['check']

    pairs = registry_path_name(rec)
    if len(pairs) == 1:
        return 'Registry', {'path': pairs[0][0], 'name': pairs[0][1]}

    m = _AUDIT_CATEGORY_RE.search(blob)
    if m:
        subcat = m.group(2).strip().lower()
        guid = AUDIT_NAME_TO_GUID.get(subcat)
        if guid:
            mask = {'success': 1, 'failure': 2, 'success and failure': 3}[m.group(3).lower()]
            return 'AuditPolicy', {'guid': guid, 'subcategory': m.group(2).strip(), 'expected': mask}

    # Only auto-classify when the check-content names exactly one distinct user right -
    # a control that bundles several rights into one VID can't be represented as a
    # single pscustomobject rule without silently dropping the other right(s).
    found = {USER_RIGHTS[m.group(1).strip()] for m in _USER_RIGHT_RE.finditer(blob)
             if m.group(1).strip() in USER_RIGHTS}
    if len(found) == 1:
        right_name = next(iter(found))
        friendly = next(name for name, right in USER_RIGHTS.items() if right == right_name)
        return 'UserRight', {'right_name': right_name, 'friendly': friendly}

    return 'Manual', {}
