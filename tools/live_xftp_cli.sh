#!/bin/bash
# Runs live_xfile with simplexmq's xftp client (QUAY_XFTP_CLI, or xftp on
# the PATH) on the xftp-server at 127.0.0.1:15443 (QUAY_XFTP_FINGERPRINT):
# a file it sends, quay receives; a file quay sends, it receives -- and
# compares. Usage: live_xftp_cli.sh <test binary>
set -e
cli=${QUAY_XFTP_CLI:-xftp}
dir=$(mktemp -d)
export HOME=$dir
head -c 100000 /dev/urandom > "$dir/in.bin"
timeout 60 "$cli" send "$dir/in.bin" "$dir/out" -s "xftp://$QUAY_XFTP_FINGERPRINT@127.0.0.1:15443" -n 1 < /dev/null > "$dir/send.log" 2>&1 || { cat "$dir/send.log"; exit 1; }
timeout 120 "$1" "$dir/out/in.bin.xftp/rcv1.xftp" "$dir/in.bin" "$dir/quay.xftp"
mkdir -p "$dir/got"
timeout 60 "$cli" recv "$dir/quay.xftp" "$dir/got" -y < /dev/null > "$dir/recv.log" 2>&1 || { cat "$dir/recv.log"; exit 1; }
if cmp -s "$dir/got/from quay.bin" "$dir/quay.xftp.expected"; then
  echo "the xftp client received quay's file, byte for byte"
else
  echo "the xftp client's copy of quay's file differs"; ls -la "$dir/got"; tail -5 "$dir/recv.log"; exit 1
fi
