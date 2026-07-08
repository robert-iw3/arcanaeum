# collect/TEMPLATE — copy to NN-<name>.sh to add a collection plugin.
# (Files without a NN- numeric prefix are never loaded, so this template
# is inert. NN controls load order; detection runs in that order, so later
# plugins can consult PLUGIN_ACTIVE — see 20-syslog.sh for an example.)
#
# Contract — define two functions named after the file (<name> from NN-<name>.sh):
#
#   <name>_detect   Return 0 if this collector can run on this host, 1 if
#                   not. Always set PLUGIN_DETAIL[<name>] to a short status
#                   string ("active (...)" / "unavailable (why)") — it is
#                   shown by `unidiag collectors`. Runs once at startup.
#
#   <name>_collect  Emit zero or more normalized events on stdout, one per
#                   line, tab-separated:
#
#                     ts_iso <TAB> severity <TAB> source <TAB> origin <TAB> message
#
#                     ts_iso    UTC ISO-8601 with millis (2026-07-02T14:02:11.480Z)
#                               — lexicographic sort must equal time sort
#                     severity  crit | error | warn
#                     source    short collector/layer name (this plugin)
#                     origin    unit/container/pod that produced the message
#                     message   free text; strip tabs and newlines
#
# Available globals: $SINCE (1h), $SINCE_JOURNAL (-1h), $SINCE_DOCKER (1h),
# $CUTOFF_ISO / $CUTOFF_EPOCH (window start), $HAS_JQ.
# Available helpers (lib/core.sh): have, die, ncpus, hostname_.
#
# Portability rules (any distro): no GNU-only flags, no hard systemd
# dependency, degrade gracefully — prefer "unavailable" over an error.
#
# If a message keyword severity classifier is needed (sources without
# native severity), reuse the regexes in 30-container.sh verbatim so
# classification stays consistent across collectors.

example_detect() {
    PLUGIN_DETAIL[example]="unavailable (template)"
    return 1
}

example_collect() {
    :
}
