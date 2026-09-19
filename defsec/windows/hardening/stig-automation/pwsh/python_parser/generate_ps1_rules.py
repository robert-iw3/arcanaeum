"""Drafts a PowerShell $rules array (and matching .ini RulesFile) from a DISA XCCDF
"Manual" XML benchmark.

Every control gets VID/Title/Severity/Description filled in from the XCCDF. Controls
that classify.py recognizes as a Registry, UserRight, or AuditPolicy check (the three
CheckTypes this repo's engine already knows how to evaluate/remediate - see
server2022/server2025/win11) are fully drafted, with one deliberate gap: Registry rules
leave Expected as a TODO, since free-text "Value: 0x...(n)" parsing is failure-prone
(ranges, SDDL strings, multi-value checks) and a security hardening tool should not
guess at the value a human must remediate to.

Everything else (account policy, service/feature checks, zone-level/per-deployment
config, organizational/documented-procedure checks) is emitted as a commented-out TODO
block with the full check-content, for a human to classify and finish.

The .ini RulesFile only lists VIDs that are real $rules array entries (Registry/
UserRight/AuditPolicy) - a commented-out TODO block isn't a rule the engine can
evaluate, so it can't be toggled in/out via the ini.

Usage:
    python generate_ps1_rules.py <xccdf.xml> <out.ps1.partial> [out.ini]
"""
import re
import sys

from xccdf_parser import parse, severity_title_case
from classify import classify

_HIVE_RE = re.compile(r'Registry Hive:\s*(HKEY_\w+)', re.IGNORECASE)
_HIVE_MAP = {
    'HKEY_LOCAL_MACHINE': 'HKLM:',
    'HKEY_CURRENT_USER': 'HKCU:',
}


def esc(s):
    # Collapse embedded newlines/runs of whitespace - the XCCDF title text sometimes
    # wraps across lines, which would otherwise break out of a single-line PS comment.
    s = re.sub(r'\s+', ' ', s).strip()
    return s.replace('`', '``').replace('"', '`"')


def hive_prefix(rec):
    m = _HIVE_RE.search(rec['check'])
    return _HIVE_MAP.get(m.group(1).upper(), 'HKLM:') if m else 'HKLM:'


def short_title(rec):
    """A short label for the Title field; the full official wording goes in Description."""
    t = rec['title']
    return t if len(t) <= 70 else t[:67] + '...'


def build(xccdf_path):
    """Returns (ps1_lines, ini_entries, total, counts).

    ini_entries is a list of (vid, title, check_type) for the rules that actually made
    it into the $rules array (i.e. NOT 'Manual'), in VID order, for the ini generator.
    """
    data = parse(xccdf_path)
    ps1_lines = []
    ini_entries = []
    counts = {'Registry': 0, 'UserRight': 0, 'AuditPolicy': 0, 'Manual': 0}

    for vid, rec in sorted(data.items()):
        severity = severity_title_case(rec['severity'])
        desc = esc(rec['title'])
        raw_title = re.sub(r'\s+', ' ', short_title(rec)).strip()
        title = esc(short_title(rec))
        check_type, fields = classify(rec)
        counts[check_type] += 1

        # No trailing comma: PowerShell's @( ) collects one expression per line without
        # needing comma separators, and a trailing comma followed only by comments (the
        # Manual TODO blocks) before the closing ) is a syntax error ("Missing expression
        # after ','") - this bit a first draft of this generator.
        if check_type == 'Registry':
            path_norm = fields['path'].strip('\\').replace('\\\\', '\\')
            full_path = f"{hive_prefix(rec)}\\{path_norm}"
            ps1_lines.append(
                f'    [pscustomobject]@{{VID="{vid}"; Title="{title}"; Severity="{severity}"; '
                f'Description="{desc}"; CheckType="Registry"; Path="{full_path}"; '
                f'Name="{esc(fields["name"])}"; Expected="<TODO: see check-content below>"}} '
                f'# version={rec["version"]}'
            )
            ini_entries.append((vid, raw_title, check_type))
        elif check_type == 'UserRight':
            ps1_lines.append(
                f'    [pscustomobject]@{{VID="{vid}"; Title="{title}"; Severity="{severity}"; '
                f'Description="{desc}"; CheckType="UserRight"; RightName="{fields["right_name"]}"; '
                f'Allowed=@("<TODO: see check-content below for the allowed accounts/groups>")}} '
                f'# version={rec["version"]}'
            )
            ini_entries.append((vid, raw_title, check_type))
        elif check_type == 'AuditPolicy':
            ps1_lines.append(
                f'    [pscustomobject]@{{VID="{vid}"; Title="{title}"; Severity="{severity}"; '
                f'Description="{desc}"; CheckType="AuditPolicy"; '
                f'SubCategory="{fields["guid"]}"; Expected={fields["expected"]}}} '
                f'# {fields["subcategory"]}, version={rec["version"]}'
            )
            ini_entries.append((vid, raw_title, check_type))
        else:
            ps1_lines.append(f'    # TODO [{vid}] ({severity}, version={rec["version"]}): {desc}')
            ps1_lines.append(f'    #   Not auto-classified (Registry/UserRight/AuditPolicy) - '
                              f'classify by hand:')
            for ln in rec['check'].splitlines():
                if ln.strip():
                    ps1_lines.append(f'    #   {ln.strip()}')

    return ps1_lines, ini_entries, len(data), counts


def build_ini(ini_entries, source_name):
    lines = [
        f'; {source_name} - rule selection',
        '; ----------------------------------------------------------------------------',
        '; Auto-generated by python_parser/generate_ps1_rules.py. Lists only the VIDs that',
        '; made it into the $rules array as a real Registry/UserRight/AuditPolicy check -',
        "; everything else is still a TODO comment in the .ps1 and isn't toggleable here.",
        '; Comment out a line (prefix with ; or #) to EXCLUDE that control.',
        ';',
        '; Format: VID = Title',
        '',
    ]
    by_type = {}
    for vid, title, check_type in ini_entries:
        by_type.setdefault(check_type, []).append((vid, title))
    for check_type in ('Registry', 'UserRight', 'AuditPolicy'):
        entries = by_type.get(check_type, [])
        if not entries:
            continue
        lines.append(f'[{check_type.upper()}]')
        for vid, title in entries:
            lines.append(f'{vid} = {title}')
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


if __name__ == '__main__':
    src = sys.argv[1]
    dst = sys.argv[2]
    ini_dst = sys.argv[3] if len(sys.argv) > 3 else None

    ps1_lines, ini_entries, total, counts = build(src)
    with open(dst, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(ps1_lines) + '\n')
    auto = counts['Registry'] + counts['UserRight'] + counts['AuditPolicy']
    print(f"{total} rules total, {auto} auto-drafted "
          f"(Registry={counts['Registry']}, UserRight={counts['UserRight']}, "
          f"AuditPolicy={counts['AuditPolicy']}), {counts['Manual']} left as TODO -> {dst}")

    if ini_dst:
        import os
        ini_text = build_ini(ini_entries, os.path.basename(ini_dst))
        with open(ini_dst, 'w', encoding='utf-8', newline='\n') as f:
            f.write(ini_text)
        print(f"{len(ini_entries)} VID(s) written to ini -> {ini_dst}")
