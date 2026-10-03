"""macOS-only cosmetic: show "Secure Chat" instead of "python" in the menu bar.

Tk windows started with `python gui/chat_gui.py` belong to the Python process, so macOS titles
the application menu "python". The name comes from the main bundle's Info dictionary, which can
be overridden at runtime BEFORE Tk creates its first window. This uses only `ctypes` and the
Objective-C runtime that ships with macOS (no pyobjc or any other dependency), does nothing on
other platforms, and silently gives up if anything is unavailable -- it is purely cosmetic.
"""

import sys


def set_app_name(name="Secure Chat"):
    """Best effort. Returns True if the bundle name was set, False if skipped. Never raises."""
    if sys.platform != "darwin":
        return False
    try:
        return _set_bundle_name(name)
    except Exception:
        return False


def _set_bundle_name(name):
    import ctypes
    import ctypes.util

    objc_path = ctypes.util.find_library("objc")
    foundation_path = ctypes.util.find_library("Foundation")
    if not objc_path or not foundation_path:
        return False
    objc = ctypes.cdll.LoadLibrary(objc_path)
    ctypes.cdll.LoadLibrary(foundation_path)          # registers NSBundle / NSString

    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    send = objc.objc_msgSend

    def call(receiver, selector, *args, restype=ctypes.c_void_p, argtypes=()):
        send.restype = restype
        send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, *argtypes]
        return send(receiver, objc.sel_registerName(selector), *args)

    def nsstring(text):
        return call(objc.objc_getClass(b"NSString"), b"stringWithUTF8String:",
                    text.encode("utf-8"), argtypes=(ctypes.c_char_p,))

    bundle = call(objc.objc_getClass(b"NSBundle"), b"mainBundle")
    info = call(bundle, b"infoDictionary") if bundle else None
    if not info:
        return False
    key, value = nsstring("CFBundleName"), nsstring(name)
    call(info, b"setObject:forKey:", value, key, argtypes=(ctypes.c_void_p, ctypes.c_void_p))
    return True
