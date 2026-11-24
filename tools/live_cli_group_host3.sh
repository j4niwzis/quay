#!/bin/bash
# Runs live_group_host3 with two CLIs (5225, and bob on QUAY_CLI2_PORT or
# 5226): each one's invitation joined by the test, each invited into its
# group and joining (/j); bob, introduced to the first by quay, says
# something; the first CLI must hear it.
# Usage: live_cli_group_host3.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
one() { timeout 40 python3 "$here/cli_ws.py" 5225 "$@"; }
bob() { timeout 40 python3 "$here/cli_ws.py" "${QUAY_CLI2_PORT:-5226}" "$@"; }
link_of() {
  python3 -c '
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line).get("resp", {})
    if r.get("type") == "invitation":
        l = r["connLinkInvitation"]
        sys.stdout.write(l.get("connFullLink") if isinstance(l, dict) else l)' "$1"
}
one "/c" > "$dir/one.json"; link_of "$dir/one.json" > "$dir/one.txt"
bob "/c" > "$dir/bob.json"; link_of "$dir/bob.json" > "$dir/bob.txt"
group="quaytrio$$"
timeout 240 "$1" "$group" "$dir/one.txt" "$dir/bob.txt" > "$dir/test.log" 2>&1 &
test_pid=$!
for _ in $(seq 1 200); do grep -q "member 1 invited" "$dir/test.log" && break; sleep 0.2; done
sleep 3
one "/j $group" --wait 3 > /dev/null || true
for _ in $(seq 1 200); do grep -q "member 2 invited" "$dir/test.log" && break; sleep 0.2; done
sleep 3
bob "/j $group" --wait 3 > /dev/null || true
for _ in $(seq 1 200); do grep -q "passed on to member 1" "$dir/test.log" && break; sleep 0.2; done
sleep 8
bob "#$group hello all, from bob" --wait 5 > /dev/null || true
wait $test_pid && status=0 || status=$?
echo "--- the test said:"; cat "$dir/test.log"
sleep 3
one "/tail #$group 10" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        m = it.get("chatItem", {}).get("meta", {})
        deleted = (m.get("itemDeleted") or {}).get("type")
        print("the first CLI, in quay'"'"'s group:", m.get("itemText", "")[:70], "(" + deleted + ")" if deleted else "")' | tee "$dir/tail.txt"
grep -q "hello all, from bob" "$dir/tail.txt" || { echo "the first CLI did not hear bob"; exit 1; }
grep -q "hello all, from bob (moderated)" "$dir/tail.txt" || { echo "bob's message was not moderated"; exit 1; }
grep -qi "removed" "$dir/tail.txt" || { echo "the first CLI did not see bob removed"; exit 1; }
bob "/tail #$group 4" | python3 -c '
import json, sys
for line in sys.stdin:
    for it in json.loads(line).get("resp", {}).get("chatItems", []):
        print("bob, in quay'"'"'s group:", it.get("chatItem", {}).get("meta", {}).get("itemText", "")[:70])'
exit $status
