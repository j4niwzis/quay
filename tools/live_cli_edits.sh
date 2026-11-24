#!/bin/bash
# Runs live_edits: the CLI's invitation joined by the test; through the
# CLI's API, the CLI sends a message, edits it, reacts to quay's, deletes
# its own; then shows what quay did to it (its message reacted to, quay's
# edited). Usage: live_cli_edits.sh <test binary>
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
for _ in $(seq 1 200); do grep -q "ours sent" "$dir/test.log" && break; sleep 0.2; done
name=$(sed -n 's/^our name: //p' "$dir/test.log")
sleep 2
ws "@$name the CLI's first draft" > /dev/null || true
sleep 3
# The chat's items, by text: the contact's id and the items' ids, from /tail.
items() { ws "/tail @$name 10" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        ci = it.get("chatItem", {}); m = ci.get("meta", {})
        reactions = " ".join(r.get("reaction", {}).get("emoji", "") + str(r.get("totalReacted", "")) for r in ci.get("reactions", []))
        print(it.get("chatInfo", {}).get("contact", {}).get("contactId"), m.get("itemId"), m.get("itemText", "")[:50], "|", reactions, "|", "edited" if m.get("itemEdited") else "")'; }
items > "$dir/items1.txt"; cat "$dir/items1.txt"
contact=$(awk "/the CLI.s first draft/ {print \$1}" "$dir/items1.txt" | tail -1)
mine=$(awk "/the CLI.s first draft/ {print \$2}" "$dir/items1.txt" | tail -1)
quays=$(awk "/quay.s first draft|quay.s edited text/ {print \$2}" "$dir/items1.txt" | tail -1)
echo "contact $contact, the CLI's item $mine, quay's item $quays"
ws "/_update item @$contact $mine live=off text the CLI's edited text" --wait 2 > /dev/null || true
sleep 2
ws "/_reaction @$contact $quays on {\"type\":\"emoji\",\"emoji\":\"❤\"}" --wait 2 > "$dir/react.json" || true
sleep 2
ws "/_delete item @$contact $mine broadcast" --wait 2 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 2
items | tee "$dir/items2.txt"
grep -q "quay's edited text.*edited" "$dir/items2.txt" || { echo "the CLI does not show quay's edit"; exit 1; }
grep -q "👍" "$dir/items2.txt" || { echo "the CLI does not show quay's reaction"; exit 1; }
exit $status
