#!/bin/sh
HIST=/tmp/vpn-dashboard-history.tsv
EVENTS=/tmp/vpn-dashboard-events.tsv
TMP=/tmp/vpn-dashboard-events.$$
TAB=$(printf '\t')
trap 'rm -f "$TMP"' EXIT
esc(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r//g'; }

printf 'Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n'
printf '{"router_tz_offset":10800,"samples":['
first=1
if [ -f "$HIST" ]; then
  tail -n 1440 "$HIST" | while IFS="$TAB" read -r ts availability health failed overall switch node; do
    [ -n "$ts" ] || continue
    h=$((health + 0))
    f=$((4 - h)); [ "$f" -lt 0 ] && f=0
    if [ "$h" -ge 2 ]; then a=100; else a=$((h * 25)); fi
    if [ "$h" -ge 3 ]; then o=ok; elif [ "$h" -eq 2 ]; then o=degraded; else o=down; fi
    [ $first -eq 0 ] && printf ','; first=0
    printf '{"ts":%s,"availability":%s,"health":%s,"failed":%s,"overall":"%s","switch":%s,"node":"%s"}' "$ts" "$a" "$h" "$f" "$o" "$switch" "$(esc "$node")"
  done
fi
printf '],"events":['
: > "$TMP"
if [ -f "$EVENTS" ]; then
  tail -n 500 "$EVENTS" >> "$TMP"
fi
if [ -f "$HIST" ]; then
  tail -n 1440 "$HIST" | while IFS="$TAB" read -r ts availability health failed overall switch node; do
    [ "$switch" = "1" ] || continue
    printf '%s\tswitch\tАктивная нода → %s\n' "$ts" "$node" >> "$TMP"
  done

  tail -n 1440 "$HIST" | awk -F '\t' '
    function st(h){ if(h<=1)return "down"; if(h==2)return "degraded"; return "healthy" }
    {
      cur=st($3+0)
      if(NR==1){
        prev=cur
        if(cur=="down") print $1 "\toutage\tVPN backend недоступен: " $3 "/4 checks"
        else if(cur=="degraded") print $1 "\thealth\tVPN backend degraded: " $3 "/4 checks"
        next
      }
      if(cur!=prev){
        if(cur=="down") print $1 "\toutage\tVPN backend недоступен: " $3 "/4 checks"
        else if(cur=="degraded") print $1 "\thealth\tVPN backend degraded: " $3 "/4 checks"
        else print $1 "\trecovery\tVPN backend восстановлен: " $3 "/4 checks"
      }
      prev=cur
    }' >> "$TMP"
fi

first=1
sort -n -k1,1 "$TMP" 2>/dev/null | awk -F '\t' 'BEGIN{OFS="\t"} { if($2=="switch"){ if(lastSwitch && ($1-lastSwitch)<120) next; lastSwitch=$1 } print }' | tail -n 500 | while IFS="$TAB" read -r ts type msg; do
  [ -n "$ts" ] || continue
  [ $first -eq 0 ] && printf ','; first=0
  printf '{"ts":%s,"type":"%s","message":"%s"}' "$ts" "$(esc "$type")" "$(esc "$msg")"
done
printf ']}'
