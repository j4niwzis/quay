#!/bin/bash
# Runs live_group_link_host: the CLI's invitation asked for only to learn
# its router; the test writes its group link; the CLI connects to it (/c),
# says something in the group once in, and shows whether the test's
# answer came. Usage: live_cli_group_link_host.sh <test binary>
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
group="quaylinked$$"
timeout 200 "$1" "$dir/invitation.txt" "$dir/link.txt" "$group" > "$dir/test.log" 2>&1 &
test_pid=$!
for _ in $(seq 1 100); do [ -s "$dir/link.txt" ] && break; sleep 0.2; done
ws "/c $(cat "$dir/link.txt")" --wait 5 > "$dir/connect.json" || true
for _ in $(seq 1 200); do grep -q "the member connection: connected" "$dir/test.log" && break; sleep 0.2; done
sleep 3
ws "#$group hello, host of the link" --wait 5 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 2
ws "/tail #$group 5" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("the CLI, in quay'"'"'s group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])' | tee "$dir/tail.txt"
grep -q "the link's host" "$dir/tail.txt" || { echo "the CLI did not get quay's message"; grep -o '"type":"[a-zA-Z]*"' "$dir/connect.json" | sort | uniq -c; exit 1; }
exit $status
