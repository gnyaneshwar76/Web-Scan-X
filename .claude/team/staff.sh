#!/bin/sh
# Puts the WebScanX team at desks in Agent Office, even with no job.
#   sh staff.sh                 everyone idle (CEO + 13 agents)
#   sh staff.sh nav "fix N29"   that one shows as working on the job
#   sh staff.sh nav             that one back to idle
# Names are the agent names without the rcx- prefix (nav = rcx-nav).
# The office forgets desks after 6 hours of silence or a server restart: run it again.
URL="http://127.0.0.1:${AGENT_OFFICE_PORT:-4747}/hook"
post() { curl -s -m 2 -X POST -H 'Content-Type: application/json' -H 'X-Agent-Office-Entrypoint: claude-desktop' \
  -H 'X-Agent-Office-Project: E:/WebScanX' --data-binary "$1" "$URL" >/dev/null; }
title() { case "$1" in ceo) echo CEO;; ble) echo Bluetooth;; ui) echo Screens;; nav) echo Navigation;; *) echo "$1" | sed 's/./\U&/';; esac; }
desk() {  # name, job or empty
  post "{\"hook_event_name\":\"SessionEnd\",\"session_id\":\"staff-$1\"}"
  post "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"staff-$1\",\"cwd\":\"E:/WebScanX\"}"
  post "{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"staff-$1\",\"prompt\":\"$(title "$1")${2:+: $2}\"}"
  [ -z "$2" ] && post "{\"hook_event_name\":\"Notification\",\"session_id\":\"staff-$1\",\"notification_type\":\"idle_prompt\",\"message\":\"No job\"}"
}
if [ -n "$1" ]; then desk "$1" "$2"; exit 0; fi
for a in ceo manager api detect report ui pack test reviewer verify security laws policy privacy; do desk "$a" ""; done
