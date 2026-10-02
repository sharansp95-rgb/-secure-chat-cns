# Front-end redesign: progress and handoff

Written so a fresh session can continue **without the original chat**. Last updated at the
end of the session in which steps 0-4 were finished. Everything below "DONE" is committed
and pushed; the working tree was clean when this file was written.

## 1. The original task (verbatim)

> Improve the FRONT END only, for a live demo in front of professors. Use the project .venv. Run real commands; stop and show me the exact error if anything fails. Keep "CNS_Review1_Team15_Secure_Chat_v2 (1).pptx", CnsProj/ and _to_delete/ out of every commit. Never touch my real data/ (use the safe demo environment on a spare port for all testing and screenshots).
>
> HARD RULES
> - Presentation layer only: gui/chat_gui.py, gui/security_dashboard.py, gui/theme.py, and the demo launcher's window placement. Do NOT change protocol, crypto, server logic, the event_callback contract, or any security check. If a UI feature needs data the client doesn't expose, read it from existing events; if truly impossible, skip it and tell me.
> - Every rejection/detection shown in the UI must still come from the real client-side checks.
> - Stay with plain Tkinter (no new dependencies) unless a pinned, pure-Python theming library gives a big visible win AND installs cleanly in .venv AND all tests pass; if you add one, add it to requirements.txt and tell me why.
> - All existing tests must pass; update tests/test_gui_layout.py for the new layout and add tests for any new layout logic.
> - My screen is a MacBook Air (1470x956 points). The demo may also be on a 1920x1080 projector. Everything must look right on both.
>
> STEP 0: BEFORE
> Take "before" screenshots of the login screen, a chat window mid-conversation, the Attack Lab, the security receipt, and the dashboard (save to a scratch folder under _to_delete/, not docs/). Look at them and write me a short critique: the 5-8 weakest visual points.
>
> STEP 1: DESIGN SYSTEM (gui/theme.py)
> - One consistent palette: dark background, high-contrast text, one brand accent (teal, as now), one danger colour (red), one warning colour (amber for lab mode), one success colour (green). Check text/background contrast is at least 4.5:1 for body text.
> - A spacing scale (4/8/12/16/24/32) and type scale (title, heading, body, caption, mono), used everywhere.
> - Keep the existing font fallback (Poppins -> Segoe UI / SF -> Helvetica); mono for keys, hashes, ciphertext.
>
> STEP 2: LOGIN SCREEN
> - App name + a simple shield/lock logo drawn on a Canvas (no external image files needed), and a one-line tagline: "Accountable end-to-end encrypted messaging for hospitals".
> - Clean card layout; Enter key submits; show/hide password toggle; inline validation messages (empty fields, port not a number).
> - While connecting, show a step-by-step progress list that ticks off as each REAL step completes: "Connecting over TLS 1.3", "Server certificate verified (fingerprint XXXX)", "Logged in", "Exchanging keys with <peer>", "Handshake signature verified". Errors appear on the failed step in red with the existing clear message.
>
> STEP 3: CHAT WINDOW
> - Header: avatar circle with the peer's initial, peer name, and a status chip row: "TLS 1.3", "End-to-end encrypted", "Signed" (green when the session is established, grey before). Fingerprint shown as a readable chip; clicking it copies it to the clipboard.
> - Bubbles: keep left/right layout; add small avatar initials, sender name, time, and a small shield/check mark on each message that passed all checks (clicking still opens the security receipt). Add date separators.
> - Rejected messages: instead of plain red text, a distinct red "blocked" card in the conversation: "Message blocked: <reason>" plus a one-line plain-English explanation and the check that caught it (from the real event).
> - Input: Enter sends, Shift+Enter new line, Send button disabled when empty or when no session yet; placeholder text.
> - Wire log: keep it (it is a key demo element) but restyle: colour-coded tags per line (HANDSHAKE, CHAT, ALERT, TLS), mono font, truncated values, and a "Show/Hide network view" toggle so the conversation can take the full width when needed.
> - Attack Lab and Export Evidence buttons: consistent button styles (Attack Lab clearly amber, only enabled in lab mode as now).
>
> STEP 4: "WHAT JUST HAPPENED?" BANNERS (demo narration)
> - A dismissable banner strip under the header that appears for important real events, in plain English (1-2 sentences), e.g.:
>   - session established: "Keys were exchanged with ECDH and the exchange was signed with RSA. The server never saw the key."
>   - message blocked by GCM: "The relay changed one byte. AES-GCM's authentication tag no longer matched, so the message was rejected."
>   - replay: "An old message was sent again. The duplicate nonce/timestamp check rejected it."
>   - drop: "A message is missing. The hash chain noticed the gap in the sequence."
>   - MITM: "Someone swapped the key during the handshake. The RSA signature check failed, so no session was created."
>   - evidence exported: "A signed copy of this conversation was saved. Anyone can verify it offline."
> - A toggle "Explain events" (on by default) in a small settings menu.
>
> STEP 5: ATTACK LAB PANEL
> - One card per attack with an icon/glyph, a one-line description, and "Expected defence: <check>". After it fires, the card shows the live result from the victim's real detection event (green "Caught by AES-GCM tag" style) or "Waiting..." until it arrives.
> - Keep the LAB MODE banner and one-shot behaviour exactly as now.
>
> STEP 6: SECURITY RECEIPT
> - Card layout with green check rows, mono values truncated with a copy button, and a short plain-English line at the bottom: "This message is authentic, unmodified, fresh, and in order."
>
> STEP 7: SECURITY DASHBOARD
> - Top row of big KPI tiles: Attacks detected, Failed logins, Locked accounts, Active users (from the existing log events only).
> - Colour-coded event feed with an icon per event type and readable one-line descriptions instead of raw key=value strings (keep raw details available on click).
> - Locked accounts list with a live countdown.
>
> STEP 8: PRESENTATION MODE + WINDOW LAYOUT
> - A "Presentation mode" toggle (menu item and keyboard shortcut Cmd+Shift+P) that scales all fonts and padding up ~25% for a projector, in every window.
> - Update demo/start_demo.sh so the two chat windows and the dashboard are tiled to fit the current screen with nothing hidden (detect screen size; on the 1470x956 screen use a layout where both chats are fully readable, e.g. side by side with the dashboard below or as a narrower right column).
>
> STEP 9: VERIFY
> - Drive the full demo flow in the safe demo environment: login (progress list), chat both ways, click a bubble (receipt), each Attack Lab action (blocked card + banner + Attack Lab result + dashboard tile change), export evidence (banner), lockout on a throwaway account (dashboard countdown), presentation mode on/off, hide/show network view, resize the window small and large.
> - Take "after" screenshots and look at every one yourself: nothing clipped, overlapping, unreadable or misaligned, at both 1470x956 and 1920x1080 window sizes. Fix and retake until clean.
> - Run pytest tests/ -q (all pass), and confirm the terminal client is unaffected.
> - Replace docs/screenshots/01-10 with fresh "after" versions (same names), keep 12 and 13 as they are, and regenerate docs/pdf/README.pdf.
>
> Commit in logical steps (theme, login, chat, banners, attack lab + receipt, dashboard, presentation mode + layout, screenshots), pushing after each.
>
> FINAL SUMMARY: the before-critique, what changed in each window, any feature you skipped and why, test result, and git log --oneline -10 + git status -sb. Put the before and after screenshots side by side in a single comparison image at _to_delete/ui_before_after.png so I can review it.

## 2. Status by step

| Step | Status | Commit |
|---|---|---|
| 0 Before screenshots + critique | **DONE** (screenshots in `_to_delete/ui_before/`, gitignored) | n/a |
| 1 Design system (`gui/theme.py`, `gui/widgets.py`) | **DONE** | `a2c6921` |
| 2 Login screen | **DONE** | `1e947bd` |
| 3 Chat window | **DONE** | `b58a819` |
| 4 "What just happened?" banners + Explain events toggle | **DONE** | `e3bac32` |
| (test-stability fix, see section 5) | **DONE**, committed with this file | next commit |
| 5 Attack Lab panel | **NOT STARTED** (only inspected the server log format) | |
| 6 Security receipt | **NOT STARTED** | |
| 7 Security dashboard | **NOT STARTED** | |
| 8 Presentation mode + launcher layout | **NOT STARTED** (theme side is ready, see below) | |
| 9 Verify, "after" screenshots 01-10, README.pdf, comparison image | **NOT STARTED** | |

Nothing was left half-edited: the working tree was clean at the end of step 4.

### The Step 0 critique (for the final summary)
1. Login: bare card, no brand/logo/tagline, no password toggle, no feedback while connecting.
2. Chat header: the fingerprint is a huge monospace banner that outshouts the title; no avatar, no status chips.
3. Bubbles: no sender name on own messages, no date separators, no "verified" mark, ambiguous bare times.
4. Network view: base64 wrapped into walls of one-colour mono text, clipped legend, no way to hide it.
5. Rejections: a plain red text blob with no explanation and no named check.
6. Attack Lab / receipt: the modal covers the chat; no result feedback per attack, no "expected defence", no copy buttons, no plain-English summary.
7. Dashboard: raw `key=value` strings, counters as mono text, absolute path clipped in the header, empty Locked pane.
8. Input row: no placeholder, no disabled state; long status sentence in the header.

## 3. What exists now (so you can continue)

- `gui/theme.py`: `Theme` with the palette, `SPACING` (4/8/12/16/24/32 via `theme.sp("md")`), `TYPE_SCALE` (display, title, heading, body, caption, mono, ...) as **named tkinter fonts** (`theme.font("body")`), `contrast_ratio()`, `TEXT_PAIRS` (every pair tested >= 4.5:1), ttk styles `TButton` (primary teal), `Secondary.`, `Lab.` (amber), `Danger.`, `Ghost.` buttons, and **`set_presentation(on)`** which rescales every font and the ttk padding by 1.25 and returns the ratio (new/old).
- `gui/widgets.py`: `rescale_tree(widget, ratio)` (scales pack/grid padding, for presentation mode), `Logo`, `Avatar`, `Chip` (kinds off/ok/info/warn/bad/bad_dark/warn_dark), `PlaceholderText` (Enter -> `<<Send>>`, Shift+Enter newline, auto-grow), `Field`, `StepList`, `make_card`, `flat_button`, `scrolled_frame`, `copy_to_clipboard`, `draw_shield/draw_check/draw_lock`, `rounded_rect_points`.
- `gui/explain.py` (pure, no Tk): `describe_rejection()` (headline, explanation, the check that caught it), `banner_for()` (the six banner texts + an info banner for the attacker window), constants `REJECTIONS`, `HANDSHAKE_SIGNATURE`, `BANNER_TEXT`.
- `gui/chat_gui.py`: login screen (`validate_login_form`, `_set_login_busy`, `StepList` progress, hand-off buffering via `_chat_ready`/`_held_events`), chat screen (`_items` list re-rendered by `_rerender_items()`; `_add_message`, `_add_blocked_card`, `_add_system_notice`; header chips; network view toggle; banner strip `_show_banner`; settings menu `settings_menu` with `explain_var`). `_open_attack_lab`, `_show_receipt`, `_LAB_ACTIONS`, `_arm_lab_action` are still the OLD (pre-redesign) versions.
- `gui/security_dashboard.py`: **untouched, old design**.
- Tests added/updated: `tests/test_theme.py`, `tests/test_gui_login.py`, `tests/test_gui_chat.py`, `tests/test_gui_banners.py`, `tests/test_gui_layout.py` (rewritten for the new header/input; dashboard tests unchanged). Suite: **209 passed**.

## 4. Decisions made so far

- **Palette**: bg `#0d1117` / panel `#151b23` / raised `#1e2733`; text `#e6edf3` / `#a9b6c6` / `#8e9bad`; teal accent `#2dd4bf` (text), `#0f766e` (solid, sent bubble, primary button); success `#4ade80`; danger `#ff7b7b` (text) / `#b42318` (solid); amber `#fbbf24` (text) / `#b45309` (Attack Lab solid). Hover colours are *darker* (lighter ones failed 4.5:1 with white text).
- **Fonts**: priority list kept (Poppins -> Segoe UI -> SF Pro Text -> Helvetica Neue -> Helvetica -> Arial); on this Mac it resolves to Helvetica. macOS font scale 1.25 is kept.
- **Plain Tkinter only**, no new dependency. Two new modules were added under `gui/` (`widgets.py`, `explain.py`); both are presentation-only.
- **Login**: while connecting, the form is hidden and only the brand + 5-step list show (so it always fits a short window); on failure the failed step is red and a **Back** button restores the form. `connect_tls` reports the cert fingerprint *before* the handshake, so the "certificate verified" step only ticks after `connect_tls` returns (the verification happens inside it). The TLS version is read from `sock.version()`.
- **Chat**: network view is hidden automatically when the window is narrower than 860 px (`NETWORK_MIN_WIDTH`); the header's long status sentence is dropped on narrow windows (`_fit_header`); action buttons and the Send button are packed *first* so they can never be squeezed out. Send is disabled until a session exists (`_session_ready`) and text is non-empty. `ChatGUI.minsize` is 680x460.
- **Banners** are triggered only by real events (`handshake_established`, `message_rejected`, `chain_warning`, `handshake_aborted`, `lab_attack_performed` (info only, makes no detection claim), and the window's own `evidence_exported`).
- **Planned for Step 5 (not built)**: the attacker's own client is *never told* whether the victim caught an attack. The victim's client reports it to the server (`security_alert`: `alert`, `reason`, `reported_by`), and the server logs it in `logs/security_events.jsonl`. So the Attack Lab card should tail that log (read-only, like the dashboard does) for a `security_alert` with `reported_by == peer`, `ts >= fired_at` and matching `alert`/`reason` (tamper: `message_rejected`/`decryption_failed`; replay: `message_rejected`/`replay_duplicate`; drop: `chain_warning`/`chain_gap`; MITM: `handshake_aborted`). Needs a `log_path` argument on `ChatGUI` (+ `--log-path` CLI, default `server.security_log.DEFAULT_LOG_PATH`). If nothing arrives show "No report from <peer> yet - watch <peer>'s window". This is the only way to show the victim's result in the attacker's window without touching client/server code. **Tell the user this in the final summary.**
- **Planned for Step 7**: "Active users" cannot be exact (the log has no logout events). Use distinct usernames in `user_login`/`user_registered` events and label it honestly ("seen in this log"); tell the user.
- **Planned for Step 8**: Presentation mode is per window/process (the windows are separate processes); add a `--presentation` flag to both GUIs and to `demo/start_demo.sh`; `Theme.set_presentation()` + `widgets.rescale_tree()` + `_rerender_items()` (chat) do the work. Add the Cmd+Shift+P binding (`<Command-Shift-P>` and `<Command-Shift-p>`; Control on other platforms) and a "Presentation mode" menu entry in `settings_menu`. Launcher: get the visible screen frame (menu bar and Dock excluded) via `osascript -l JavaScript` (`ObjC.import('AppKit'); $.NSScreen.mainScreen.visibleFrame`), compute the tiling in a small testable Python helper (e.g. `demo/layout.py`, with tests), and use it in `start_demo.sh` for the chat windows and dashboard (currently fixed 780x540 / 700x340 placement). 1470x956 suggestion: chats side by side (each ~730 wide), dashboard below full width.

## 5. Known problems and things to re-check

- **Tk crash lesson (fixed, keep it)**: a full `pytest` run died with exit code **133** (silent abort, no Python traceback) in an unrelated networking test, because tkinter objects from destroyed windows were garbage-collected on a *server thread* ("Tcl_AsyncDelete: wrong thread"). Fixed by the autouse `_finalize_tk_objects_on_the_main_thread` fixture in `tests/conftest.py` (`gc.collect()` after each test). Also: on this macOS, creating a Tk root, destroying it *without ever calling `update()`*, then creating another root and updating can segfault, so GUI test fixtures call `update()` before yielding and before `destroy()`.
- **Never judge a pipeline by `tail`**: `pytest ... | tail -2 && git commit` hid a crash once. Redirect pytest output to a file and check its exit code (`echo $?`), or use `set -o pipefail`.
- The wire-log lines wrap in a narrow pane (each of nonce/ciphertext/tag on its own line); readable but long. Optional polish: shorter field names.
- Re-check at **1920x1080**: not yet verified at all (macOS may clamp a window taller than the screen; if so, verify the layout by `winfo_reqwidth/height` in tests and by tiling windows as the launcher would on a big screen).
- The old Attack Lab and receipt windows still use the new palette via legacy colour names but have the OLD layout; they still work.
- `README.md` "Screenshots" table and `docs/pdf/README.pdf` still show the OLD screenshots 01-10 until step 9 replaces them (same file names). Screenshots 12 and 13 are Wireshark and must stay as they are.
- Do not change `_demo_common.py` isolation: the earlier ACM/MedSecure plan is cancelled; nothing from it remains.

## 6. How to test safely (the "safe demo environment")

The scripts used lived in the session scratchpad (`.../scratchpad/ui/`: `safe_server.py`, `gui_driver.py`, `ctl.py`, `env.py`) and may no longer exist. Recreate the approach:

1. Start a lab-mode relay on a spare port (e.g. 5055) with a **temporary** user store and security log: patch `server.server.register_user/verify_user/get_public_key` with `functools.partial(..., path=<tmp>/users.json)` and `server.server.log_event` to write to `<tmp>/security_events.jsonl`, then `ChatServer("127.0.0.1", 5055, lab_mode=True).serve_forever()`.
2. Host each real window (`ChatGUI`, `SecurityDashboard`) in a small driver process that first redirects `gui.chat_gui.save_private_key/load_private_key` (`keys_dir=<tmp>/keys`), `client.evidence.DEFAULT_EXPORT_DIR` (`<tmp>/exports`) and the dashboard log path, then polls a command file and `exec`s code inside the Tk thread (invoke buttons, set variables). Chat input is `app.message_entry.set_text(...)`; `app._update_send_state()`; `app.send_button.invoke()`.
3. Capture with `screencapture -x -o -l <CGWindowID>` (window ids from Quartz via a venv that has pyobjc-Quartz + pillow); retry the window lookup (it is occasionally flaky).
4. Trigger the real attacks with `app.client.send_lab_control("tamper_next" | "replay_last" | "drop_next" | "mitm_next_handshake")` (or the Attack Lab buttons).
5. Never use the real `data/`, `exports/`, `logs/` (the user keeps them empty on purpose); never touch macOS AirPlay on port 5000; stop only our own processes (`demo/stop_demo.sh` is safe).

## 7. Exact next action when resuming

**Start Step 5 (Attack Lab panel)** in `gui/chat_gui.py`:
1. Add `log_path=None` to `ChatGUI.__init__` (default `DEFAULT_LOG_PATH`) and `--log-path` to `main()`.
2. Replace `_open_attack_lab` with the card layout (2x2 grid: glyph circle, title, one-line description, "Expected defence: <check from gui/explain.py>", a status chip that goes Not armed -> Armed -> Fired, waiting for <peer> -> green "Caught by <check> (reported by <peer>)" or an amber "No report yet" after ~10 s, and the amber **Arm** button using `Lab.TButton`). Keep the `LAB MODE: relay is acting maliciously on request` banner text and the one-shot behaviour; keep `_arm_lab_action` sending `client.send_lab_control(action)` on a thread.
3. Drive card state from the existing `lab_control_result` and `lab_attack_performed` events (the latter carries `action`), and poll the security log as described in section 4.
4. Add `tests/test_gui_attack_lab.py` (cards present, banner text, arm calls `send_lab_control` with the right action, state machine with a temp log file, unrelated/old/other-reporter alerts ignored, timeout wording), run the whole suite (output to a file, check the exit code), commit "gui(attack lab): ..." and push.
5. Then Step 6 (receipt), Step 7 (dashboard), Step 8 (presentation mode + launcher), Step 9 (verify, screenshots 01-10, README.pdf via the scratchpad `md2pdf.py` pipeline [markdown -> HTML -> headless Chrome PDF], comparison image `_to_delete/ui_before_after.png`), committing and pushing after each, then the final summary.
