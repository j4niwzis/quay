#!/bin/bash
# Runs live_chat_file: the CLI's invitation joined by the test, then the CLI
# told to send it a file (/f), and what the test wrote compared with what
# was sent. The CLI must have been started with --xftp-server.
# Usage: live_cli_file.sh <test binary>
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
head -c 200000 /dev/urandom > "$dir/sent.bin"
timeout 150 "$1" "$dir/invitation.txt" "$dir/got.bin" > "$dir/test.log" 2>&1 &
test_pid=$!
tail -f "$dir/test.log" --pid=$test_pid &
for _ in $(seq 1 150); do grep -q "event: connected" "$dir/test.log" && break; sleep 0.2; done
name=$(sed -n 's/^our name: //p' "$dir/test.log")
sleep 2
timeout 60 python3 "$here/cli_ws.py" 5225 "/f @$name $dir/sent.bin" --wait 10 > "$dir/send.json" || true
wait $test_pid
if cmp -s "$dir/sent.bin" "$dir/got.bin"; then echo "quay got the CLI's file, byte for byte"; else echo "quay's copy differs"; grep -o '"type":"[a-zA-Z]*"' "$dir/send.json" | sort | uniq -c; exit 1; fi
