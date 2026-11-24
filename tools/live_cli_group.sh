#!/bin/bash
# Runs live_group: the CLI's invitation joined by the test; then the CLI
# makes a group, invites the test, says something in it once the test has
# joined, and shows whether the test's group message came.
# Usage: live_cli_group.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
ws() { timeout 40 python3 "$here/cli_ws.py" 5225 "$@"; }
ws "/c" > "$dir/invitation.json"
python3 - "$dir" <<'EOF'
import json, sys
d = sys.argv[1]
for line in open(d + "/invitation.json"):
    r = json.loads(line).get("resp", {})
    if r.get("type") == "invitation":
        link = r["connLinkInvitation"]
        open(d + "/invitation.txt", "w").write(link.get("connFullLink") if isinstance(link, dict) else link)
EOF
timeout 200 "$1" "$dir/invitation.txt" > "$dir/test.log" 2>&1 &
test_pid=$!
tail -f "$dir/test.log" --pid=$test_pid &
for _ in $(seq 1 150); do grep -q "the contact: connected" "$dir/test.log" && break; sleep 0.2; done
name=$(sed -n 's/^our name: //p' "$dir/test.log")
group="team$$"
sleep 2
ws "/g $group" > /dev/null || true
ws "/a $group $name" --wait 3 > "$dir/add.json" || true
for _ in $(seq 1 150); do grep -q "our member connection: connected" "$dir/test.log" && break; sleep 0.2; done
sleep 3
ws "#$group hello quay, from the group" --wait 5 > /dev/null || true
wait $test_pid; status=$?
sleep 2
ws "/tail #$group 4" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("the CLI, in the group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])'
exit $status
