#!/bin/bash -eu

# Archives recordings to Dropbox. archiveloop calls this with pairs of
# arguments: a directory, and a file that lists the files in that directory
# to archive. Each file is removed from the directory once it is safely
# stored in Dropbox, which is how archiveloop tells which were archived.

if ! declare -F log > /dev/null
then
  function log () {
    echo "$(date): $*"
  }
fi

bindir="$(dirname "$(readlink -f "$0")")"
readonly bindir

function notify () {
  if [ -x "$bindir/send-push-message" ]
  then
    "$bindir/send-push-message" "${NOTIFICATION_TITLE:-teslausb}:" "$1" || true
  fi
}

python3 -u "$bindir/dropbox_archive.py" upload "$@" 2>&1 | while IFS= read -r line
do
  log "$line"
done
status=${PIPESTATUS[0]}

case $status in
  3)
    notify "Archiving to Dropbox failed: Dropbox did not accept teslausb's credentials or permissions. See the archiveloop log for details."
    ;;
  4)
    notify "Archiving to Dropbox failed: your Dropbox is full."
    ;;
  75)
    # The upload progress has been saved. Have archiveloop archive again as
    # soon as Dropbox is reachable, rather than waiting for the next time
    # the car comes home, in case the connection comes back before
    # archiveloop notices it was gone. connect-archive.sh clears this.
    log "Dropbox became unreachable, archiving will resume when it is reachable again."
    touch /tmp/archive_is_unreachable
    ;;
esac

exit "$status"
