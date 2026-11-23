#!/bin/bash
# Runs a live test that joins an invitation of simplex-chat's CLI (its
# WebSocket API on 127.0.0.1:5225): the invitation asked for, its link given
# to the test. Usage: live_cli.sh <test binary>
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
exec timeout 120 "$1" "$dir/invitation.txt"
