#!/bin/bash
# Runs live_group_host: the CLI's invitation joined by the test, which then
# makes a group and invites the CLI; the CLI joins it (/j), says something
# in it, and shows whether quay's group message came.
# Usage: live_cli_group_host.sh <test binary>
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
group="quayhosted$$"
timeout 200 "$1" "$dir/invitation.txt" "$group" > "$dir/test.log" 2>&1 &
test_pid=$!
for _ in $(seq 1 200); do grep -q "the CLI invited to" "$dir/test.log" && break; sleep 0.2; done
sleep 3
ws "/j $group" --wait 5 > "$dir/join.json" || true
for _ in $(seq 1 200); do grep -q "the member connection: connected" "$dir/test.log" && break; sleep 0.2; done
sleep 3
ws "#$group hello host quay, from the CLI" --wait 5 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 2
ws "/tail #$group 4" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("the CLI, in quay'"'"'s group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])' | tee "$dir/tail.txt"
grep -q "from your host quay" "$dir/tail.txt" || { echo "the CLI did not get quay's group message"; grep -o '"type":"[a-zA-Z]*"' "$dir/join.json" | sort | uniq -c; exit 1; }
exit $status
