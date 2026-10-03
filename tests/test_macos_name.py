"""gui/macos.py: the macOS menu-bar name is cosmetic, dependency-free and can never raise."""

import sys

import gui.macos as macos


def test_does_nothing_off_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert macos.set_app_name("Secure Chat") is False


def test_never_raises_even_if_the_objc_runtime_misbehaves(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")

    def boom(_name):
        raise OSError("no objc here")
    monkeypatch.setattr(macos, "_set_bundle_name", boom)
    assert macos.set_app_name("Secure Chat") is False


def test_skips_quietly_when_the_libraries_are_not_found(monkeypatch):
    import ctypes.util
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(ctypes.util, "find_library", lambda _n: None)
    assert macos.set_app_name("Secure Chat") is False


def test_imports_nothing_beyond_the_standard_library():
    source = open(macos.__file__).read()
    assert "import objc" not in source and "from Foundation" not in source and "AppKit" not in source
