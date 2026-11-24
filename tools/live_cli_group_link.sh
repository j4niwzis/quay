#!/bin/bash
# Runs live_group_link: the CLI makes a group and its link; the test joins
# through it; the CLI says something in the group once the test is in, and
# shows whether the test's answer came.
# Usage: live_cli_group_link.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
ws() { timeout 40 python3 "$here/cli_ws.py" 5225 "$@"; }
group="linked$$"
ws "/g $group" > /dev/null || true
ws "/create link #$group" > "$dir/link.json" || true
python3 - "$dir" <<'EOF'
import json, sys
d = sys.argv[1]
for line in open(d + "/link.json"):
    r = json.loads(line).get("resp", {})
    link = r.get("connLinkContact") or (r.get("groupLink") or {}).get("connLinkContact")
    if link:
        open(d + "/link.txt", "w").write(link.get("connFullLink") if isinstance(link, dict) else link)
EOF
[ -s "$dir/link.txt" ] || { echo "no group link from the CLI:"; cut -c1-400 "$dir/link.json"; exit 1; }
timeout 200 "$1" "$dir/link.txt" > "$dir/test.log" 2>&1 &
test_pid=$!
for _ in $(seq 1 200); do grep -q "our member connection: connected" "$dir/test.log" && break; sleep 0.2; done
sleep 3
ws "#$group hello, whoever came by the link" --wait 5 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 2
ws "/tail #$group 5" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("the CLI, in its group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])' | tee "$dir/tail.txt"
grep -q "who came by the link" "$dir/tail.txt" || { echo "the CLI did not get quay's message"; exit 1; }
exit $status
