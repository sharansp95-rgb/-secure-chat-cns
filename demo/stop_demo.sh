#!/bin/bash
# Stop the live demo: our server.py, our chat windows and our security
# dashboard -- and nothing else (never macOS AirPlay/ControlCenter, never
# another project's processes). Also closes the Terminal windows the
# launcher opened.
#
#   demo/stop_demo.sh            stop everything of ours
#   demo/stop_demo.sh --port N   only stop our server listening on port N
#                                (chat windows and the dashboard still stop)
source "$(dirname "${BASH_SOURCE[0]}")/_demo_lib.sh"
PORT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done
echo "Stopping the Secure Chat demo (only processes started from $ROOT)..."
stop_demo_processes "$PORT"
echo "Done."
