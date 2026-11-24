#!/bin/bash
# Runs live_invite through simplex-chat's contact address: the CLI's address
# made (or shown) and set to accept requests, the test given it -- quay's
# contact request then accepted by the CLI. Usage: live_cli_contact.sh <test binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
timeout 40 python3 "$here/cli_ws.py" 5225 "/ad" > "$dir/address.json" || true
timeout 40 python3 "$here/cli_ws.py" 5225 "/sa" >> "$dir/address.json" || true
timeout 40 python3 "$here/cli_ws.py" 5225 "/auto_accept on" > "$dir/accept.json"
python3 - "$dir" <<'EOF'
import json, sys
d = sys.argv[1]
for line in open(d + "/address.json"):
    r = json.loads(line).get("resp", {})
    link = r.get("connLinkContact") or r.get("contactLink", {}).get("connLinkContact")
    if link:
        open(d + "/address.txt", "w").write(link.get("connFullLink") if isinstance(link, dict) else link)
EOF
[ -s "$dir/address.txt" ] || { echo "no address from the CLI:"; cut -c1-300 "$dir/address.json"; exit 1; }
exec timeout 120 "$1" "$dir/address.txt" "$dir/ours.txt"
