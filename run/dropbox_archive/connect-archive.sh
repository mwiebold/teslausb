#!/bin/bash -eu

# A request to archive again, left by an interrupted earlier run (see
# archive-clips.sh), is moot now that archiving is starting.
rm -f /tmp/archive_is_unreachable
