# Optional shared-state backend for running multiple ai-protect instances in
# HA. Today's shared policy state (`state_db`, see TODO.md "Policy state is
# process-local and in-memory" and ARCHITECTURE.md "SQLite-backed policy
# state") needs a shared filesystem; Valkey is the network-reachable
# alternative for hosts with no shared disk.
# https://valkey.io/
FROM valkey/valkey:8-alpine
