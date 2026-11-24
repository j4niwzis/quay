# quay's live tests against smp-server and simplex-chat's CLI, by quay.tls (127.0.0.1:15223).
export LD_LIBRARY_PATH=/data/work/llvm/usr/lib/x86_64-linux-gnu:/data/work/llvm/usr/lib/llvm-23/lib
Q=/data/work/chat_-1003343718758/w/quay; D=/data/work/chat_-1003343718758/w/dl/chat
B=/data/work/chat_-1003343718758/w/quay-build; CB=/data/work/chat_-1003343718758/w/cairn-build
CXX="/data/work/llvm/usr/bin/clang++-23 --sysroot=/data/work/llvm -stdlib=libc++ -std=c++26 -Wno-unused-command-line-argument"
M="-fmodule-file=std=$CB/std.pcm"; O="$CB/std.o $B/botan_all.o $B/sntrup761.o $B/glue.o"
for f in $CB/splice*.pcm; do n=$(basename $f .pcm); M="$M -fmodule-file=$n=$f"; O="$O $CB/$n.o"; done
for m in bytes crypto smp ratchet agent session connection; do M="$M -fmodule-file=quay.$m=$B/quay.$m.pcm"; O="$O $B/quay.$m.o"; done
export QUAY_SMP_FINGERPRINT=$(cat /tmp/opt/simplex/fingerprint) QUAY_SMP_ADDRESS=127.0.0.1:15223
for t in "$@"; do
  echo "== $t"
  $CXX $M $Q/test/$t.cc $O -fuse-ld=lld -o $B/$t 2>&1 | grep -E "error" -A3 | head -10
  if [ $t = live_join ] || [ $t = live_connection ]; then
    timeout 40 python3 -I $Q/tools/cli_ws.py 5225 "/c" > $D/invitation.json
    python3 -I -c "
import json
for line in open('$D/invitation.json'):
    r = json.loads(line).get('resp', {})
    if r.get('type') == 'invitation':
        link = r['connLinkInvitation']
        open('$D/invitation.txt', 'w').write(link.get('connFullLink') if isinstance(link, dict) else link)
"
    timeout 100 $B/$t $D/invitation.txt
  else
    timeout 60 $B/$t
  fi
  echo "exit $?"
done
