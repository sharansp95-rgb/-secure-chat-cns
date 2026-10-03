#!/bin/bash
# One-command live demo: opens clearly titled Terminal windows for
#   1) the relay server (with the Attack Lab enabled)
#   2) chat window A   3) chat window B   4) the security dashboard
# and the three GUI windows, arranged so none fully covers another.
#
#   demo/start_demo.sh               server on port 5000, Attack Lab ON
#   demo/start_demo.sh --no-lab      normal mode (no Attack Lab)
#   demo/start_demo.sh --port 5055   use another port (e.g. if you prefer
#                                    to stay clear of macOS AirPlay on 5000)
#   demo/start_demo.sh --simple      NO extra windows: the server runs in the
#                                    background; you get only the two chat
#                                    windows (sender and receiver)
#   demo/start_demo.sh --wireshark   also start a live Wireshark capture of
#                                    the demo port BEFORE anything connects
#                                    (combine: --simple --wireshark)
#   demo/start_demo.sh --presentation  Presentation mode in every GUI window
#                                    (~25% larger text, for a projector); you can
#                                    also toggle it in any window with Cmd+Shift+P
#
# Windows are tiled to fit THIS screen (demo/layout.py): two chat windows side by
# side, the dashboard below them and the server's Terminal window beside it, so
# nothing is hidden behind anything else.
#
# Stop it again with demo/stop_demo.sh. Double-clickable twin:
# demo/start_demo.command.
source "$(dirname "${BASH_SOURCE[0]}")/_demo_lib.sh"

PORT=5000
LAB=1
SIMPLE=0
WIRESHARK=0
PRESENTATION=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-lab) LAB=0; shift ;;
        --simple) SIMPLE=1; shift ;;
        --wireshark) WIRESHARK=1; shift ;;
        --presentation) PRESENTATION=1; shift ;;
        --port)   PORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done
case "$PORT" in ''|*[!0-9]*) echo "--port needs a number, got '$PORT'" >&2; exit 2 ;; esac

cd "$ROOT" || exit 1
if [ ! -x "$PY" ]; then
    echo "No virtualenv at $ROOT/.venv. Create it first:" >&2
    echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

echo "=== Secure Chat demo launcher ==="
echo "Project: $ROOT"
echo "[1/5] Stopping any previous demo of ours (server on port $PORT, chat windows, dashboard)"
stop_demo_processes "$PORT"

echo "[2/5] Checking the TLS certificate"
cert_check() {
    "$PY" - <<'PYEOF'
import datetime, ssl, sys
sys.path.insert(0, ".")
try:
    from certs.generate_certs import CERT_PATH, KEY_PATH, cert_fingerprint_from_file
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(CERT_PATH, KEY_PATH)  # missing/corrupt/mismatched -> error
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(open(CERT_PATH, "rb").read())
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if expires < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError(f"certificate expired on {expires:%Y-%m-%d}")
    print(cert_fingerprint_from_file(CERT_PATH))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
PYEOF
}
CERT_ERR="$(mktemp)"; trap 'rm -f "$CERT_ERR"' EXIT
if FP="$(cert_check 2>"$CERT_ERR")"; then
    echo "    certificate OK, fingerprint $FP"
else
    echo "    certificate problem ($(cat "$CERT_ERR")) -- regenerating with demo/reset_environment.py"
    "$PY" demo/reset_environment.py --port "$PORT" --yes || exit 1
    FP="$(cert_check)" || { echo "certificate still invalid after reset" >&2; exit 1; }
    echo "    certificate regenerated, fingerprint $FP"
fi

# --- window layout: tiled to the VISIBLE frame of this screen (menu bar and Dock excluded) ---
screen_frame() {
    osascript -l JavaScript -e 'ObjC.import("AppKit"); var s=$.NSScreen.mainScreen; var f=s.visibleFrame; var a=s.frame; [Math.round(f.origin.x), Math.round(a.size.height-(f.origin.y+f.size.height)), Math.round(f.size.width), Math.round(f.size.height)].join(" ")' 2>/dev/null
}
SCREEN="$(screen_frame)"
case "$SCREEN" in
    [0-9]*" "[0-9]*" "[0-9]*" "[0-9]*) ;;
    *) SCREEN="0 25 1280 775" ;;     # safe fallback if the screen cannot be queried
esac
PRESFLAG=""; LAYOUT_FLAGS=""
[ "$PRESENTATION" = 1 ] && { PRESFLAG="--presentation"; LAYOUT_FLAGS="--presentation"; }
[ "$SIMPLE" = 1 ] && LAYOUT_FLAGS="$LAYOUT_FLAGS --simple"
eval "$("$PY" demo/layout.py $SCREEN $LAYOUT_FLAGS)"
echo "    screen $SCREEN -> windows tiled$( [ "$OVERLAP" = 1 ] && echo " (screen too small to tile without overlap: click a title bar to raise a window)" )"

LABFLAG=""; MODE="normal mode"
[ "$LAB" = 1 ] && { LABFLAG="--lab"; MODE="Attack Lab ON"; }

wait_for_server() {
    "$PY" - "$PORT" <<'PYEOF'
import sys, time
sys.path.insert(0, ".")
from client.client import TLSSetupError, connect_tls
port, deadline, last = int(sys.argv[1]), time.time() + 40, None
while time.time() < deadline:
    try:
        connect_tls("127.0.0.1", port, on_cert_fingerprint=lambda fp: None).close()
        sys.exit(0)
    except TLSSetupError as exc:
        last = str(exc).splitlines()[0]
        time.sleep(0.4)
print(f"    server not ready after 40s: {last}", file=sys.stderr)
sys.exit(1)
PYEOF
}

start_wireshark() {
    # Live capture of loopback traffic on our port, started BEFORE any client
    # connects so the TLS handshakes are recorded. (The one-time "Decode As:
    # port 5000 = TLS" rule is stored in Wireshark's own config.)
    if [ ! -d /Applications/Wireshark.app ]; then
        echo "    Wireshark is not installed in /Applications -- skipping the capture" >&2
        return 0
    fi
    pgrep -x Wireshark >/dev/null && osascript -e 'tell application "Wireshark" to quit' >/dev/null 2>&1 && sleep 1
    open -n -a Wireshark --args -i lo0 -f "tcp port $PORT" -Y tls -k
    sleep 4
    echo "    Wireshark is capturing loopback port $PORT (filter: tls)"
}

if [ "$SIMPLE" = 1 ]; then
    # Only the two chat windows. Server runs quietly in the background; its
    # output goes to logs/demo_server.log. Stop with demo/stop_demo.sh.
    mkdir -p "$ROOT/logs"
    if [ "$WIRESHARK" = 1 ]; then echo "[3/5] Starting the Wireshark capture"; start_wireshark; fi
    echo "[4/5] Starting the server in the background ($MODE, port $PORT)"
    nohup "$PY" -u server/server.py $LABFLAG --port "$PORT" > "$ROOT/logs/demo_server.log" 2>&1 &
    if ! wait_for_server; then
        echo "The server did not start; see logs/demo_server.log" >&2; exit 1
    fi
    echo "    server is up and its certificate matches certs/server.crt"
    echo "[5/5] Opening the sender and receiver windows"
    nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_A_GEOM" $PRESFLAG >/dev/null 2>&1 &
    nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_B_GEOM" $PRESFLAG >/dev/null 2>&1 &
    cat <<MSG

=== Demo is running (simple mode) ===
 Server  : 127.0.0.1:$PORT over TLS, cert fingerprint $FP, $MODE (background)
 Windows : the two chat windows (left = sender, right = receiver)$( [ "$WIRESHARK" = 1 ] && echo ", plus Wireshark" )
 Next    : Register a user in each window (name the OTHER as Peer), send a
           message$( [ "$WIRESHARK" = 1 ] && echo ", then look at Wireshark: Client Hello / Server Hello, then unreadable Application Data" ).
 Finish  : demo/stop_demo.sh   (Wireshark is left open; stop its capture yourself)
MSG
    exit 0
fi

[ "$WIRESHARK" = 1 ] && { echo "Starting the Wireshark capture"; start_wireshark; }

open_terminal() {  # title  command  x1 y1 x2 y2
    # `activate` first: otherwise Terminal's "front window" can still be an
    # OLDER window, and the bounds below would land on the wrong one.
    osascript >/dev/null <<OSA
tell application "Terminal"
    activate
    set t to do script "clear; cd '$ROOT' && source .venv/bin/activate && clear && $2"
    try
        set custom title of t to "$1"
    end try
    set bounds of front window to {$3, $4, $5, $6}
end tell
OSA
}

echo "[3/5] Opening the server window ($MODE, port $PORT)"
open_terminal "$TITLE_PREFIX · Server (port $PORT)" "python server/server.py $LABFLAG --port $PORT" $SERVER_BOUNDS

echo "[4/5] Waiting for the server to accept TLS connections"
if ! wait_for_server
then
    echo "The server window shows why. Fix that, then run this again (or demo/stop_demo.sh)." >&2
    exit 1
fi
echo "    server is up and its certificate matches certs/server.crt"

echo "[5/5] Opening chat windows A and B and the security dashboard"
nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_A_GEOM" $PRESFLAG >/dev/null 2>&1 &
nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_B_GEOM" $PRESFLAG >/dev/null 2>&1 &
nohup "$PY" gui/security_dashboard.py --geometry "$DASH_GEOM" $PRESFLAG >/dev/null 2>&1 &

cat <<MSG

=== Demo is running ===
 Server        : 127.0.0.1:$PORT over TLS, cert fingerprint $FP, $MODE
 Windows       : chat A (top-left), chat B (top-right), the security dashboard
                 (bottom-left) and the server's Terminal window (bottom-right),
                 tiled to this screen so nothing is hidden.
 What to do    : in window A log in (or Register) as one user and name the
                 OTHER user as "Peer"; in window B do the reverse. Once both
                 show a fingerprint, send a message, click a bubble for its
                 security receipt$( [ "$LAB" = 1 ] && echo ", open Attack Lab, and watch the dashboard" ).
 Projector     : Cmd+Shift+P toggles Presentation mode in any window
                 (or start with demo/start_demo.sh --presentation).
 When finished : demo/stop_demo.sh   (stops only our server and windows)
MSG
