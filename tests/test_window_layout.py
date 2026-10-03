"""The demo launcher's window tiling (demo/layout.py): on any screen size, every window is
inside the visible screen, nothing is hidden behind anything else, and every window keeps at
least the size its GUI needs. Pure arithmetic; no display needed."""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo"))

import layout  # noqa: E402
from layout import CHAT_MIN, DASH_MIN, GAP, TITLE_BAR, compute_layout  # noqa: E402

# (x, y, w, h) of the VISIBLE frame: the user's MacBook Air, a 1080p projector, and others
SCREENS = {
    "macbook-air-1470x956": (0, 33, 1470, 923),
    "macbook-air-dock-shown": (0, 25, 1470, 860),
    "mbp-14-1512x982": (0, 33, 1512, 949),
    "1920x1080": (0, 25, 1920, 1055),
    "2560x1440": (0, 25, 2560, 1415),
    "1440x900": (0, 25, 1440, 875),
}


def frames(lay):
    """name -> (left, top, right, bottom) of each window's whole frame (title bar included)."""
    out = {}
    for name in ("chat_a", "chat_b", "dash"):
        w = lay[name]
        if w:
            out[name] = (w["x"], w["y"], w["x"] + w["w"], w["y"] + w["h"] + TITLE_BAR)
    if lay["server"]:
        s = lay["server"]
        out["server"] = (s["x"], s["y"], s["x"] + s["w"], s["y"] + s["h"])
    return out


def intersects(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


@pytest.mark.parametrize("name", SCREENS)
@pytest.mark.parametrize("presentation", [False, True])
@pytest.mark.parametrize("simple", [False, True])
def test_everything_is_inside_the_visible_screen_and_big_enough(name, presentation, simple):
    x0, y0, width, height = SCREENS[name]
    lay = compute_layout(SCREENS[name], presentation=presentation, simple=simple)
    scale = 1.25 if presentation else 1.0
    for window, (l, t, r, b) in frames(lay).items():
        inside = l >= x0 and t >= y0 and r <= x0 + width and b <= y0 + height
        # a layout that cannot fit (1.25x on a short screen) must SAY so instead of hiding it
        assert inside or lay["overlap"], (window, (l, t, r, b), SCREENS[name])
        if not presentation:
            assert inside, (window, (l, t, r, b), SCREENS[name])
    for chat in ("chat_a", "chat_b"):
        assert lay[chat]["w"] >= round(CHAT_MIN[0] * scale) and lay[chat]["h"] >= round(CHAT_MIN[1] * scale)
    if lay["dash"]:
        assert lay["dash"]["w"] >= round(DASH_MIN[0] * scale) and lay["dash"]["h"] >= DASH_MIN[1]


@pytest.mark.parametrize("name", SCREENS)
def test_nothing_is_hidden_behind_anything_else(name):
    lay = compute_layout(SCREENS[name])
    f = frames(lay)
    assert not intersects(f["chat_a"], f["dash"]) and not intersects(f["chat_b"], f["dash"])
    assert not intersects(f["server"], f["dash"]) and not intersects(f["server"], f["chat_a"])
    assert not intersects(f["server"], f["chat_b"])
    if not lay["overlap"]:
        assert not intersects(f["chat_a"], f["chat_b"])


def test_the_users_macbook_air_gets_two_fully_readable_chats_side_by_side():
    lay = compute_layout(SCREENS["macbook-air-1470x956"])
    a, b = lay["chat_a"], lay["chat_b"]
    assert not lay["overlap"]
    assert (a["w"], a["h"]) == (b["w"], b["h"]) and a["w"] >= 700 and a["h"] >= 500
    assert b["x"] >= a["x"] + a["w"], "chat B starts to the right of chat A"
    assert lay["dash"]["y"] > a["y"] + a["h"], "the dashboard is below the chats"
    assert lay["dash"]["w"] + GAP <= lay["server"]["x"], "server window sits beside the dashboard"


def test_presentation_mode_on_the_macbook_air_still_fits_vertically():
    lay = compute_layout(SCREENS["macbook-air-1470x956"], presentation=True)
    x0, y0, width, height = SCREENS["macbook-air-1470x956"]
    assert all(b <= y0 + height for (_l, _t, _r, b) in frames(lay).values())


def test_a_1080p_projector_tiles_without_overlap_even_in_presentation_mode():
    for presentation in (False, True):
        lay = compute_layout(SCREENS["1920x1080"], presentation=presentation)
        assert not lay["overlap"], presentation
    big = compute_layout(SCREENS["1920x1080"], presentation=True)
    assert big["chat_a"]["w"] >= 850          # 680 * 1.25


def test_a_screen_too_narrow_for_two_chats_overlaps_them_and_says_so():
    lay = compute_layout((0, 25, 1280, 775))
    assert lay["overlap"] and lay["chat_a"]["w"] == CHAT_MIN[0]
    f = frames(lay)
    assert not intersects(f["chat_a"], f["dash"]), "even then the dashboard stays visible"


def test_simple_mode_has_just_two_chats_using_the_full_height():
    lay = compute_layout(SCREENS["macbook-air-1470x956"], simple=True)
    assert lay["dash"] is None and lay["server"] is None
    assert lay["chat_a"]["h"] + TITLE_BAR + 2 * GAP == SCREENS["macbook-air-1470x956"][3]


def test_command_line_prints_the_variables_the_launcher_evals():
    out = subprocess.run([sys.executable, layout.__file__, "0", "33", "1470", "923"],
                         capture_output=True, text=True, check=True).stdout
    values = dict(line.split("=", 1) for line in out.strip().splitlines())
    assert set(values) == {"CHAT_A_GEOM", "CHAT_B_GEOM", "DASH_GEOM", "SERVER_BOUNDS", "OVERLAP"}
    assert values["CHAT_A_GEOM"].count("x") == 1 and values["CHAT_A_GEOM"].count("+") == 2
    assert len(values["SERVER_BOUNDS"].strip('"').split()) == 4
    simple = subprocess.run([sys.executable, layout.__file__, "0", "33", "1470", "923", "--simple"],
                            capture_output=True, text=True, check=True).stdout
    assert "DASH_GEOM" not in simple and "SERVER_BOUNDS" not in simple
