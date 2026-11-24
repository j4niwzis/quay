#!/bin/bash
# Runs a live test that writes a link for simplex-chat's CLI (its WebSocket
# API on 127.0.0.1:5225) to connect to -- an invitation, or quay's contact
# address: the CLI's own invitation asked for only to learn its router, the
# test started, and the CLI told to connect to the link the test writes.
# Usage: live_cli_invite.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
timeout 40 python3 "$here/cli_ws.py" 5225 "/c" > "$dir/invitation.json"
python3 - "$dir" <<'EOF'
import json, sys
d = sys.argv[1]
for line in open(d + "/invitation.json"):
    r = json.loads(line).get("resp", {})
    if r.get("type") == "invitation":
        link = r["connLinkInvitation"]
        open(d + "/invitation.txt", "w").write(link.get("connFullLink") if isinstance(link, dict) else link)
EOF
timeout 120 "$1" "$dir/invitation.txt" "$dir/ours.txt" &
test_pid=$!
for _ in $(seq 1 100); do [ -s "$dir/ours.txt" ] && break; sleep 0.2; done
[ -s "$dir/ours.txt" ] || { kill $test_pid; echo "the test wrote no invitation"; exit 1; }
timeout 40 python3 "$here/cli_ws.py" 5225 "/c $(cat "$dir/ours.txt")" --wait 15 > "$dir/join.json" || true
grep -o '"type":"[a-zA-Z]*"' "$dir/join.json" | sort | uniq -c || true
wait $test_pid
