#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com>
#
# Prove that a release binary bundles both Google OAuth clients:
#
#   packaging/check-bundled-clients.sh BINARY
#
# The ZDRIVE_GOOGLE_* client values are compiled in through option_env!, so
# a release built without the repository secrets lacks them. `doctor --json`
# reports only whether each client is present, never its value. Its exit
# status is printed but not enforced, because doctor also judges the host
# (FUSE, configured remotes), which says nothing about the build.
set -euo pipefail

[ "$#" -eq 1 ] || {
    printf 'usage: %s BINARY\n' "$0" >&2
    exit 2
}
binary=$1
case "$binary" in
    */*) ;;
    *) binary="./$binary" ;;
esac

status=0
report=$("$binary" doctor --json) || status=$?
printf 'zdrive doctor exit status: %s\n' "$status"
printf '%s' "$report" | python3 -c '
import json, sys

bundled = json.load(sys.stdin)["bundled_client"]
print("bundled_client:", json.dumps(bundled, sort_keys=True))
missing = [kind for kind in ("desktop", "device") if bundled.get(kind) is not True]
if missing:
    sys.exit(
        "bundled Google OAuth client missing: " + ", ".join(missing)
        + "; set the ZDRIVE_GOOGLE_{DESKTOP,DEVICE}_CLIENT_{ID,SECRET} repository secrets"
    )
'
