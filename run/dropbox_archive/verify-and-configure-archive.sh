#!/bin/bash -eu

function log_progress () {
  if declare -F setup_progress > /dev/null
  then
    setup_progress "verify-and-configure-archive: $*"
    return
  fi
  echo "verify-and-configure-archive: $*"
}

readonly dropbox_archive=/root/bin/dropbox_archive.py

# Runs a command, sending its output to the setup log, and returns its exit status.
function run_logged () {
  "$@" 2>&1 | while IFS= read -r line
  do
    log_progress "$line"
  done
  return "${PIPESTATUS[0]}"
}

function install_required_packages () {
  log_progress "Installing/updating required packages if needed"
  if ! command -v python3 > /dev/null
  then
    apt-get -y --force-yes install python3
  fi
  if ! command -v nc > /dev/null
  then
    apt-get -y --force-yes install netcat-openbsd || apt-get -y --force-yes install netcat
  fi
  if ! command -v iwgetid > /dev/null
  then
    apt-get -y --force-yes install wireless-tools
  fi
  log_progress "Done"
}

function store_credentials () {
  if [ -n "${DROPBOX_REFRESH_TOKEN:-}" ]
  then
    log_progress "Storing the Dropbox credentials from DROPBOX_APP_KEY and DROPBOX_REFRESH_TOKEN..."
    if ! run_logged "$dropbox_archive" import-credentials
    then
      log_progress "STOP: could not store the Dropbox credentials from DROPBOX_APP_KEY and DROPBOX_REFRESH_TOKEN"
      exit 1
    fi
  fi
}

function check_archive () {
  log_progress "Verifying the Dropbox archive..."
  local status=0
  run_logged "$dropbox_archive" check || status=$?
  if [ "$status" = 5 ] && [ -t 0 ]
  then
    log_progress "teslausb has not been authorized to use Dropbox yet, starting authorization."
    "$dropbox_archive" authorize || true
    status=0
    run_logged "$dropbox_archive" check || status=$?
  fi
  if [ "$status" = 5 ]
  then
    log_progress "STOP: teslausb has not been authorized to use Dropbox. Run '$dropbox_archive authorize', or set DROPBOX_REFRESH_TOKEN as described in doc/SetupDropbox.md, then run setup again."
    exit 1
  elif [ "$status" != 0 ]
  then
    log_progress "STOP: the Dropbox archive could not be verified"
    exit 1
  fi
}

function check_reachable () {
  local -r server="${ARCHIVE_SERVER:-api.dropboxapi.com}"
  if /root/bin/archive-is-reachable.sh "$server"
  then
    return
  fi
  log_progress "WARNING: archiving would not start now, because Dropbox doesn't count as reachable. Check that:"
  if [ -n "${DROPBOX_WIFI_SSIDS:-}" ]
  then
    log_progress "WARNING: - DROPBOX_WIFI_SSIDS includes the name of the wifi network (which 'iwgetid -r' shows)"
  fi
  log_progress "WARNING: - ARCHIVE_SERVER ($server) accepts connections on port 443, or isn't set"
}

install_required_packages
store_credentials
check_archive
check_reachable
log_progress "Done"
