# profile/TEMPLATE — copy to NN-<name>.sh to add a host-profiling plugin.
# (Files without a NN- numeric prefix are never loaded.)
#
# Profile plugins answer "what IS this host?" so collection and analysis
# spend effort where it matters. They run before collection conceptually:
# wide net first, then narrow.
#
# Contract — define two functions named after the file:
#
#   <name>_detect    Return 0 to run, 1 to skip; set PLUGIN_DETAIL[<name>].
#
#   <name>_profile   Populate the shared associative arrays:
#
#     PROFILE_ROLES[<role>]=high|medium|low   confidence this role applies
#     PROFILE_EVIDENCE[<role>]="why"          shown in the report
#     PROFILE_FOCUS[<role>]="guidance"        what to prioritize collecting
#     PROFILE_HINT[<origin-substring>]=<role> fed to the analysis layer:
#                                             origins matching the substring
#                                             inherit the role's causal prior
#                                             (see ROLE_PRIOR in unidiag_ml.py)
#
# Evidence should name its source ("nginx (process)", "port 5432",
# "systemd unit enabled") so a human can audit the inference. Prefer
# multiple weak signals merged over one clever heuristic.
#
# Ideas for future plugins: package-manager introspection (rpm/dpkg/apk),
# systemd enabled-unit scan, container image names, cloud metadata,
# /etc fingerprints (nginx sites-enabled, pg_hba.conf presence).

example_detect() {
    PLUGIN_DETAIL[example]="unavailable (template)"
    return 1
}

example_profile() {
    :
}
