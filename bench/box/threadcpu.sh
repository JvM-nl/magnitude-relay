#!/bin/bash
# threadcpu.sh PID SECONDS: per-thread CPU% of PID over the interval.
pid=$1; secs=$2
snap() { for t in /proc/$pid/task/*; do n=$(cat $t/comm); s=($(cut -d' ' -f14,15 $t/stat)); echo "$n ${s[0]} ${s[1]}"; done | awk '{u[$1]+=$2; s[$1]+=$3} END {for (k in u) print k, u[k], s[k]}' | sort; }
a=$(snap); sleep $secs; b=$(snap)
join <(echo "$a") <(echo "$b") | awk -v s=$secs '{printf "%-14s user %5.1f%%  sys %5.1f%%\n", $1, ($4-$2)/s, ($5-$3)/s}'
