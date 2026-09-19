"""Parses a DISA XCCDF "Manual" XML benchmark into a flat VID -> rule dict.

Used to backfill Severity/Description onto existing rule scripts (see
server2022/server2025) and to draft new rule scripts for STIGs that don't
have one yet (see generate_ps1_rules.py).

Usage:
    python xccdf_parser.py <xccdf.xml> <out.json>
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET


def _local(tag):
    return tag.split('}')[-1]


def parse(path):
    """Returns {VID: {severity, title, version, fixtext, check}}."""
    tree = ET.parse(path)
    root = tree.getroot()
    out = {}
    for grp in root.iter():
        if _local(grp.tag) != 'Group':
            continue
        vid = grp.get('id')
        rule = next((c for c in grp if _local(c.tag) == 'Rule'), None)
        if rule is None:
            continue

        title_el = version_el = fixtext_el = check_content = None
        for c in rule:
            lt = _local(c.tag)
            if lt == 'title' and title_el is None:
                title_el = c
            elif lt == 'version':
                version_el = c
            elif lt == 'fixtext':
                fixtext_el = c
            elif lt == 'check':
                for cc in c:
                    if _local(cc.tag) == 'check-content':
                        check_content = cc

        out[vid] = {
            'severity': rule.get('severity', ''),
            'title': (title_el.text or '').strip() if title_el is not None else '',
            'version': (version_el.text or '').strip() if version_el is not None else '',
            'fixtext': (fixtext_el.text or '').strip() if fixtext_el is not None else '',
            'check': (check_content.text or '').strip() if check_content is not None else '',
        }
    return out


# A check-content block for a registry-backed control almost always contains a
# stereotyped "Registry Path: ... \r\n\r\n Value Name: ..." pair. Extracting these
# is far more reliable than guessing from the prose title.
_REGISTRY_RE = re.compile(
    r'Registry Path:\s*\\?([^\r\n]+?)\\?\s*\r?\n+\s*Value Name:\s*([^\r\n]+)',
    re.IGNORECASE)


def registry_path_name(rec):
    """Returns a list of (path, name) pairs explicitly stated in check-content."""
    return [(p.strip(), n.strip()) for p, n in _REGISTRY_RE.findall(rec['check'])]


def severity_title_case(sev):
    return {'high': 'High', 'medium': 'Medium', 'low': 'Low'}.get(sev.lower(), 'Medium')


def parse_benchmark_meta(path):
    """Returns {id, title, version, release} for the <Benchmark> root element.

    version/release together give the "V{version}R{release}" suffix DISA uses in its
    own filenames (e.g. V2R8), parsed from the <version> element and the "Release: N"
    line in the release-info <plain-text>.
    """
    root = ET.parse(path).getroot()
    title = ''
    version = ''
    release = ''
    for c in root:
        lt = _local(c.tag)
        if lt == 'title' and not title:
            title = (c.text or '').strip()
        elif lt == 'version' and not version:
            version = (c.text or '').strip()
        elif lt == 'plain-text' and c.get('id') == 'release-info':
            m = re.search(r'Release:\s*(\d+)', c.text or '')
            if m:
                release = m.group(1)
    return {'id': root.get('id', ''), 'title': title, 'version': version, 'release': release}


def derive_basename(xccdf_path):
    """Derives a script basename matching this repo's convention (e.g.
    "WindowsServerDNS-STIG-V2R4") from DISA's own XCCDF filename, which already
    encodes the product and V{version}R{release}: U_<Product>_STIG_V<x>R<y>_Manual-xccdf.xml
    """
    stem = re.sub(r'\.xml$', '', os.path.basename(xccdf_path), flags=re.IGNORECASE)
    stem = re.sub(r'_Manual-xccdf$', '', stem, flags=re.IGNORECASE)
    stem = re.sub(r'^U_', '', stem)
    stem = re.sub(r'^MS_', '', stem)
    parts = [p for p in stem.split('_') if p]
    try:
        idx = next(i for i, p in enumerate(parts) if p.upper() == 'STIG')
    except StopIteration:
        return stem.replace('_', '')
    product = ''.join(parts[:idx])
    rest = '-'.join(parts[idx:])
    return f'{product}-{rest}'


if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    data = parse(src)
    with open(dst, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1)
    print(f"{len(data)} rules parsed from {src} -> {dst}")
