#!/bin/bash
# Double-click me in Finder: starts the live demo (see start_demo.sh).
cd "$(dirname "$0")" && ./start_demo.sh "$@"
echo
echo "You can close this window; the demo keeps running. Stop it with demo/stop_demo.sh."
