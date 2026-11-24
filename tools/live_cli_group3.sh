#!/bin/bash
# Runs live_group with three in the group: the CLI on 5225 (the host), a
# second CLI on 5226 ("bob", QUAY_CLI2_PORT), and the test. The host
# invites bob, then the test; bob says something in the group, which
# reaches the test forwarded by the host (x.grp.msg.forward); the test's
# group message reaches bob.
# Usage: live_cli_group3.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
host() { timeout 40 python3 "$here/cli_ws.py" 5225 "$@"; }
bob() { timeout 40 python3 "$here/cli_ws.py" "${QUAY_CLI2_PORT:-5226}" "$@"; }
link_of() {
  python3 -c '
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line).get("resp", {})
    if r.get("type") == "invitation":
        l = r["connLinkInvitation"]
        print(l.get("connFullLink") if isinstance(l, dict) else l)' "$1"
}
# The host and bob connected.
host "/c" > "$dir/bob_inv.json"
bob "/c $(link_of "$dir/bob_inv.json")" --wait 8 > /dev/null || true
bobname=$(host "/contacts" | python3 -c '
import json, sys
for line in sys.stdin:
    for c in json.loads(line).get("resp", {}).get("contacts", []):
        if c.get("profile", {}).get("displayName") == "bob": print(c["localDisplayName"])' | tail -1)
echo "the host knows bob as: $bobname"
[ -n "$bobname" ] || { echo "the host and bob did not connect"; exit 1; }
# The test joins the host's invitation.
host "/c" > "$dir/invitation.json"
link_of "$dir/invitation.json" | tr -d "\n" > "$dir/invitation.txt"
QUAY_GROUP_FORWARD=1 timeout 240 "$1" "$dir/invitation.txt" > "$dir/test.log" 2>&1 &
test_pid=$!

for _ in $(seq 1 150); do grep -q "the contact: connected" "$dir/test.log" && break; sleep 0.2; done
name=$(sed -n 's/^our name: //p' "$dir/test.log")
group="trio$$"
host "/g $group" > /dev/null || true
host "/a $group $bobname" --wait 3 > /dev/null || true
sleep 2
bob "/j $group" --wait 5 > /dev/null || true
sleep 2
host "/a $group $name" --wait 3 > /dev/null || true
for _ in $(seq 1 200); do grep -q "our member connection: connected" "$dir/test.log" && break; sleep 0.2; done
sleep 4
host "#$group hello quay, from the host" --wait 3 > /dev/null || true
sleep 2
bob "#$group hello quay, from bob" --wait 5 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 3
bob "/tail #$group 5" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("bob, in the group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])' | tee "$dir/bob_tail.txt"
grep -q "hello group, from quay" "$dir/bob_tail.txt" || { echo "bob did not get quay's message"; exit 1; }
exit $status
