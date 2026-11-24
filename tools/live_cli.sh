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
if [ -z "$QUAY_CLI_SAYS" ]; then exec timeout 120 "$1" "$dir/invitation.txt"; fi
# The CLI says something to the test once connected, and shows whether
# the test's receipt marked it delivered.
timeout 120 "$1" "$dir/invitation.txt" > "$dir/test.log" 2>&1 &
test_pid=$!
tail -f "$dir/test.log" --pid=$test_pid &
for _ in $(seq 1 150); do grep -q "event: connected" "$dir/test.log" && break; sleep 0.2; done
name=$(sed -n 's/^our name: //p' "$dir/test.log")
sleep 1
timeout 30 python3 "$here/cli_ws.py" 5225 "@$name $QUAY_CLI_SAYS" > /dev/null || true
# And, where asked, the CLI moves its receiving queue: quay must follow.
if [ -n "$QUAY_CLI_SWITCHES" ]; then sleep 2; timeout 30 python3 "$here/cli_ws.py" 5225 "/switch @$name" > /dev/null || true; fi
wait $test_pid; status=$?
timeout 20 python3 "$here/cli_ws.py" 5225 "/tail @$name 3" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        ci = it.get("chatItem", {})
        print("the CLI item:", ci.get("meta", {}).get("itemText", "")[:60], "|", json.dumps(ci.get("meta", {}).get("itemStatus")))'
exit $status
