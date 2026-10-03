#!/usr/bin/env python3
"""Window tiling for the demo launcher (demo/start_demo.sh). Pure arithmetic, no Tk.

    python demo/layout.py X Y W H [--presentation] [--simple] [--no-terminal]

X Y W H is the VISIBLE screen frame in points, top-left origin (the menu bar and Dock are
already excluded). It prints shell-friendly KEY=VALUE lines for the launcher to eval:

    CHAT_A_GEOM / CHAT_B_GEOM / DASH_GEOM     "WxH+X+Y" for gui/*.py --geometry
    SERVER_BOUNDS                              "x1 y1 x2 y2" for the server's Terminal window
    OVERLAP                                    1 if the screen is too small to tile without overlap

Layout: the two chat windows side by side on top, the dashboard below them, and the server's
Terminal window on the right of the dashboard strip, so NOTHING is hidden behind anything else.
With --simple there is no dashboard or server window: the two chat windows use the full height.
On a screen too small to tile (too narrow for two readable chat windows, or too short for chats plus
dashboard at the chosen size), windows overlap or run past the bottom edge and OVERLAP=1 is reported
(click a title bar to raise one).
"""

import argparse
import sys

GAP = 8
TITLE_BAR = 28                     # macOS title bar height added to every window's content height
CHAT_MIN = (680, 460)              # gui/chat_gui.py minsize (content, normal size)
DASH_MIN = (640, 240)              # gui/security_dashboard.py minsize
SERVER_TERMINAL_W = 420
PRESENTATION = 1.25                # same factor as gui/theme.py PRESENTATION_SCALE


def compute_layout(screen, presentation=False, simple=False, server_terminal=True):
    """Return {"chat_a", "chat_b", "dash", "server", "overlap"}; each window is
    {"x", "y", "w", "h"} with (x, y) the frame's top-left and (w, h) the CONTENT size to pass as
    --geometry (the server entry's h is the full frame height, as Terminal wants it)."""
    x0, y0, width, height = screen
    scale = PRESENTATION if presentation else 1.0
    chat_min_w, chat_min_h = round(CHAT_MIN[0] * scale), round(CHAT_MIN[1] * scale)
    # The dashboard's height minimum does NOT scale: it has a compact mode for short windows.
    dash_min_w, dash_min_h = round(DASH_MIN[0] * scale), DASH_MIN[1]

    left, right, top = x0 + GAP, x0 + width - GAP, y0 + GAP
    usable_w, usable_h = right - left, height - 2 * GAP

    if simple:
        band = 0
    else:
        band = max(round(0.32 * height), dash_min_h + TITLE_BAR)
        band = min(band, usable_h - (chat_min_h + TITLE_BAR) - GAP)   # keep the chats readable
        band = max(band, dash_min_h + TITLE_BAR)
    chat_frame_h = usable_h - (band + GAP if band else 0)
    chat_h = max(chat_frame_h - TITLE_BAR, chat_min_h)

    chat_w = (usable_w - GAP) // 2
    overlap = chat_w < chat_min_w
    if overlap:
        chat_w = chat_min_w
    chat_a = {"x": left, "y": top, "w": chat_w, "h": chat_h}
    chat_b = {"x": right - chat_w, "y": top, "w": chat_w, "h": chat_h}
    layout = {"chat_a": chat_a, "chat_b": chat_b, "dash": None, "server": None,
              "overlap": overlap}
    if simple:
        return layout

    band_y = top + chat_h + TITLE_BAR + GAP
    band_frame_h = max(y0 + height - GAP - band_y, dash_min_h + TITLE_BAR)
    dash_w = usable_w - ((SERVER_TERMINAL_W + GAP) if server_terminal else 0)
    dash_w = max(dash_w, dash_min_w)
    layout["dash"] = {"x": left, "y": band_y, "w": dash_w, "h": band_frame_h - TITLE_BAR}
    if band_y + band_frame_h > y0 + height:      # does not fit vertically (e.g. 1.25x on a short screen)
        layout["overlap"] = True
    if server_terminal:
        layout["server"] = {"x": right - SERVER_TERMINAL_W, "y": band_y,
                            "w": SERVER_TERMINAL_W, "h": band_frame_h}
        if left + dash_w > right - SERVER_TERMINAL_W:
            layout["overlap"] = True
    return layout


def geometry(window):
    return f"{window['w']}x{window['h']}+{window['x']}+{window['y']}"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tile the demo windows on the visible screen.")
    parser.add_argument("x", type=int)
    parser.add_argument("y", type=int)
    parser.add_argument("w", type=int)
    parser.add_argument("h", type=int)
    parser.add_argument("--presentation", action="store_true")
    parser.add_argument("--simple", action="store_true")
    parser.add_argument("--no-terminal", action="store_true")
    args = parser.parse_args(argv)
    layout = compute_layout((args.x, args.y, args.w, args.h), presentation=args.presentation,
                            simple=args.simple, server_terminal=not args.no_terminal)
    print(f"CHAT_A_GEOM={geometry(layout['chat_a'])}")
    print(f"CHAT_B_GEOM={geometry(layout['chat_b'])}")
    if layout["dash"]:
        print(f"DASH_GEOM={geometry(layout['dash'])}")
    if layout["server"]:
        s = layout["server"]
        print(f"SERVER_BOUNDS=\"{s['x']} {s['y']} {s['x'] + s['w']} {s['y'] + s['h']}\"")
    print(f"OVERLAP={1 if layout['overlap'] else 0}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
