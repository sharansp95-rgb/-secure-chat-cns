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
#
# Stop it again with demo/stop_demo.sh. Double-clickable twin:
# demo/start_demo.command.
source "$(dirname "${BASH_SOURCE[0]}")/_demo_lib.sh"

PORT=5000
LAB=1
while [ $# -gt 0 ]; do
    case "$1" in
        --no-lab) LAB=0; shift ;;
        --port)   PORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# --- window layout (points); screen size from Finder, with a safe fallback --
#   top-left: chat A    top-right: chat B (slight overlap on screens narrower
#   than ~1580pt -- click a title bar to raise either)
#   bottom-left: dashboard    bottom-right: server + three small status windows
read -r W H <<<"$(osascript -e 'tell application "Finder" to get bounds of window of desktop' 2>/dev/null | awk -F', *' 'NF==4{print $3, $4}')"
W="${W:-1280}"; H="${H:-800}"
GUI_W=780; GUI_H=540
DASH_W=700; DASH_H=340
DASH_Y=$(( 30 + GUI_H + 10 ))
TERM_X1=$(( DASH_W + 20 )); TERM_X2=$(( W - 10 ))
TERM_TOP=$(( 55 + GUI_H + 10 )); TERM_BOT=$(( H - 30 ))
[ "$TERM_BOT" -lt $(( TERM_TOP + 200 )) ] && TERM_BOT=$(( TERM_TOP + 200 ))
SERVER_BOT=$(( TERM_TOP + (TERM_BOT - TERM_TOP) * 55 / 100 ))
ST_W=$(( (TERM_X2 - TERM_X1) / 3 ))

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

LABFLAG=""; MODE="normal mode"
[ "$LAB" = 1 ] && { LABFLAG="--lab"; MODE="Attack Lab ON"; }

echo "[3/5] Opening the server window ($MODE, port $PORT)"
open_terminal "$TITLE_PREFIX · 1 Server (port $PORT)" "python server/server.py $LABFLAG --port $PORT" "$TERM_X1" "$TERM_TOP" "$TERM_X2" "$SERVER_BOT"

echo "[4/5] Waiting for the server to accept TLS connections"
if ! "$PY" - "$PORT" <<'PYEOF'
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
then
    echo "The server window shows why. Fix that, then run this again (or demo/stop_demo.sh)." >&2
    exit 1
fi
echo "    server is up and its certificate matches certs/server.crt"

echo "[5/5] Opening chat windows A and B and the security dashboard"
open_terminal "$TITLE_PREFIX · 2 Chat window A" "python gui/chat_gui.py --port $PORT --geometry ${GUI_W}x${GUI_H}+10+30" "$TERM_X1" $(( SERVER_BOT + 8 )) $(( TERM_X1 + ST_W - 4 )) "$TERM_BOT"
open_terminal "$TITLE_PREFIX · 3 Chat window B" "python gui/chat_gui.py --port $PORT --geometry ${GUI_W}x${GUI_H}+$(( W - GUI_W - 10 ))+55" $(( TERM_X1 + ST_W )) $(( SERVER_BOT + 8 )) $(( TERM_X1 + 2 * ST_W - 4 )) "$TERM_BOT"
open_terminal "$TITLE_PREFIX · 4 Dashboard" "python gui/security_dashboard.py --geometry ${DASH_W}x${DASH_H}+10+${DASH_Y}" $(( TERM_X1 + 2 * ST_W )) $(( SERVER_BOT + 8 )) "$TERM_X2" "$TERM_BOT"

cat <<MSG

=== Demo is running ===
 Server        : 127.0.0.1:$PORT over TLS, cert fingerprint $FP, $MODE
 Windows       : chat A (top-left), chat B (top-right), the dashboard
                 (bottom-left); the four Terminal windows are bottom-right.
                 Click any window's title bar to bring it to the front.
 What to do    : in window A log in (or Register) as one user and name the
                 OTHER user as "Peer"; in window B do the reverse. Once both
                 show a fingerprint, send a message, click a bubble for its
                 security receipt$( [ "$LAB" = 1 ] && echo ", open Attack Lab, and watch the dashboard" ).
 When finished : demo/stop_demo.sh   (stops only our server and windows)
MSG
