#!/bin/bash -eu

# Dropbox is considered reachable when its API server accepts connections,
# and, if DROPBOX_WIFI_SSIDS is set, the Pi is connected to one of the wifi
# networks listed in it (separated by '|'). The latter keeps archiving from
# happening anywhere but home, e.g. over a phone's hotspot.

readonly host="${1:-api.dropboxapi.com}"
# can be overridden for testing
readonly netdir="${DROPBOX_NET_DIR:-/sys/class/net}"

function connected_ssids () {
  local dev
  # only the wifi client interfaces, not teslausb's own access point (ap0)
  for dev in "$netdir"/wl*
  do
    if [ -e "$dev" ]
    then
      iwgetid -r "${dev##*/}" 2> /dev/null || true
    fi
  done
}

function on_allowed_wifi () {
  if [ -z "${DROPBOX_WIFI_SSIDS:-}" ]
  then
    return 0
  fi
  local -a allowed
  local ssid name
  IFS='|' read -r -a allowed <<< "$DROPBOX_WIFI_SSIDS"
  while IFS= read -r ssid
  do
    for name in "${allowed[@]}"
    do
      if [ -n "$ssid" ] && [ "$ssid" = "$name" ]
      then
        return 0
      fi
    done
  done < <(connected_ssids)
  return 1
}

function accepts_connections () {
  if command -v nc > /dev/null
  then
    nc -z -w 5 "$host" 443 &> /dev/null
  else
    # shellcheck disable=SC2016
    timeout 5 bash -c 'exec 3<> "/dev/tcp/$0/443"' "$host" &> /dev/null
  fi
}

on_allowed_wifi && accepts_connections
