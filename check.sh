#! /bin/bash

shopt -s globstar nullglob extglob

# print shellcheck version so we know what Github uses
shellcheck -V

status=0

# SC1091 - Don't complain about not being able to find files that don't exist.
shellcheck --exclude=SC1091 \
           ./setup/pi/setup-teslausb \
           ./pi-gen-sources/00-teslausb-tweaks/files/rc.local \
           ./run/archiveloop \
           ./run/auto.teslausb \
           ./run/awake_start \
           ./run/awake_stop \
           ./run/dropbox_archive/archive-clips.sh \
           ./run/dropbox_archive/archive-is-reachable.sh \
           ./run/dropbox_archive/connect-archive.sh \
           ./run/dropbox_archive/disconnect-archive.sh \
           ./run/dropbox_archive/verify-and-configure-archive.sh \
           ./run/mountimage \
           ./run/mountoptsforimage \
           ./run/remountfs_rw \
           ./run/send-push-message \
           ./run/temperature_monitor \
           ./run/waitforidle || status=1

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' || status=1

exit $status
