# triage/TEMPLATE — copy to NN-<name>.sh to add a host triage plugin.
# (Files without a NN- numeric prefix are never loaded. NN controls run
# order — keep the diagnostic-value ordering: kernel complaints first,
# then saturation, capacity, network, platform. Slot new plugins where
# their findings rank.)
#
# Contract — define two functions named after the file (<name> from NN-<name>.sh):
#
#   <name>_detect   Return 0 if the checks can run here, 1 to skip the
#                   plugin entirely. Set PLUGIN_DETAIL[<name>] ("ready" /
#                   "unavailable (why)").
#
#   <name>_triage   Run checks and print verdicts. Use the helpers:
#
#                     section "<heading>"            once, at the top
#                     verdict ok|warn|crit <check> <detail>
#
#                   verdict tracks the global TRIAGE_WORST, which decides
#                   the final "fix host first / go look at apps" message —
#                   so severity honesty matters more than completeness.
#
# Detail strings should say what the finding MEANS for troubleshooting
# ("'no space left' with free GB is this"), not just restate the number.
# A check that cannot read its source should degrade to a warn verdict or
# silence, never an error.
#
# Portability rules (any distro): prefer /proc and /sys over tools; no
# GNU-only flags; guard optional tools with `have`.

example_detect() {
    PLUGIN_DETAIL[example]="unavailable (template)"
    return 1
}

example_triage() {
    section "example"
    verdict ok "example check" "nothing to report"
}
