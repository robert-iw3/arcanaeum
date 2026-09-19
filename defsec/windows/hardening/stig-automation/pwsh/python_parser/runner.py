"""One-shot pipeline: DISA XCCDF "Manual" XML in, a ready-to-finish PowerShell STIG
script + .ini RulesFile out, matching this repo's server2022/server2025/win11 engine.

Usage:
    python runner.py -i <stig.xml> -o <directory/> [--name <Basename>]

The output basename defaults to whatever derive_basename() reads out of DISA's own
XCCDF filename (e.g. U_MS_Windows_Server_DNS_STIG_V2R4_Manual-xccdf.xml ->
WindowsServerDNS-STIG-V2R4); override with --name if you want something else.

Writes <output>/<Basename>.ps1 and <output>/<Basename>.ini.
"""
import argparse
import os
import sys

from xccdf_parser import parse_benchmark_meta, derive_basename
from generate_ps1_rules import build, build_ini
from script_template import render


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-i', '--input', required=True, help='Path to the DISA XCCDF "Manual" XML benchmark')
    ap.add_argument('-o', '--output', required=True, help='Directory to write <Basename>.ps1 and <Basename>.ini into')
    ap.add_argument('--name', help='Override the auto-derived basename')
    args = ap.parse_args(argv)

    if not os.path.isfile(args.input):
        ap.error(f"input file not found: {args.input}")

    meta = parse_benchmark_meta(args.input)
    basename = args.name or derive_basename(args.input)
    os.makedirs(args.output, exist_ok=True)

    ps1_lines, ini_entries, total, counts = build(args.input)
    rules_body = '\n'.join(ps1_lines)
    script_text = render(basename, meta['title'] or basename, rules_body, counts)

    ps1_path = os.path.join(args.output, f'{basename}.ps1')
    ini_path = os.path.join(args.output, f'{basename}.ini')

    with open(ps1_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(script_text)
    with open(ini_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(build_ini(ini_entries, f'{basename}.ini'))

    auto = total - counts['Manual']
    print(f"{meta['title'] or '(untitled benchmark)'} "
          f"(V{meta['version']}R{meta['release']})" if meta['version'] else meta['title'])
    print(f"{total} controls total, {auto} auto-drafted "
          f"(Registry={counts['Registry']}, UserRight={counts['UserRight']}, "
          f"AuditPolicy={counts['AuditPolicy']}), {counts['Manual']} left as TODO")
    print(f"-> {ps1_path}")
    print(f"-> {ini_path}")


if __name__ == '__main__':
    main()
