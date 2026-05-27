# AppArmor

**Comprehensive, safe, zero-performance-impact AppArmor deployment** using only native Linux tools.

## 2026 Best Practices Implemented
- Start in **complain** mode for learning
- Dynamic scanning of **all user programs** via audit/syslog + `aa-logprof`
- Modular profiles per application
- YAML config for custom rules, tunables, and further hardening
- Automatic profile generation + optimization
- Multi-pass refinement for true least-privilege
- Full support for Ubuntu/Debian (native) and RHEL/Alma (via apparmor package)

## Recommended Workflow
```bash
sudo python3 configure_apparmor.py --mode=setup
sudo python3 configure_apparmor.py --mode=learn     # use system normally 24-72h
sudo python3 configure_apparmor.py --mode=generate
sudo python3 configure_apparmor.py --mode=optimize  # advanced minimization
sudo python3 configure_apparmor.py --mode=enforce
```

## Policy Optimization Report
After `--mode=optimize`:
```bash
cat /var/lib/apparmor_guardian/optimization_report.txt
```

- Typical result: **65-90% rule reduction** vs raw profiles.

**Test in non-production first.** Always review generated profiles.