"""A thread-safe wrapper around an established ssl.SSLSocket.

Why this exists
---------------
Python's ssl.SSLSocket is NOT safe to use from several threads at once --
the underlying OpenSSL SSL object has no internal locking, and CPython
releases the GIL around SSL_read / SSL_write. This project nevertheless uses
one TLS connection from several threads, by design:

  * client: SecureChatClient.receive_loop() blocks reading on one thread
    while the main/GUI thread writes (register, login, chat, alerts);
  * server: each connection's handler thread blocks reading it while OTHER
    handler threads route()/broadcast() into the very same connection, and
    two such senders can write to it at the same time.

The symptom was rare and nasty: roughly 1 connection in 40 under load, a
login or registration envelope that was "sent" but never arrived, or the
reader dying with an SSL error. Found by dumping every thread's stack at the
moment of a hang (server blocked waiting for the first line, client blocked
waiting for the reply, nothing in between).

How this fixes it
-----------------
  * The socket is switched to non-blocking mode (after the blocking
    handshake), and EVERY SSL call (recv / send / shutdown / close) happens
    while holding one per-connection lock, so OpenSSL never sees two threads
    at once.
  * Waiting for data happens OUTSIDE that lock, in select(), so a reader
    parked waiting for the peer never blocks a writer -- full duplex is kept.
  * A second lock makes each sendall() atomic as a whole message, so two
    threads writing to the same connection can never interleave partial
    envelopes.

The object quacks like the socket the rest of the code already used:
sendall, recv, makefile("r"), shutdown, close, plus attribute delegation
(getsockname, fileno, ...) to the wrapped socket.
"""

import io
import select
import socket
import ssl
import threading

# How long a reader/writer sleeps in select() before re-checking whether the
# connection was closed from another thread. Data arrival wakes it
# immediately; this only bounds how long a close() takes to be noticed.
_POLL_SECONDS = 0.1


class _RawReader(io.RawIOBase):
    """Minimal raw stream over LockedTLSSocket.recv, so makefile() can hand
    out a normal buffered text reader (iterating lines) exactly as
    socket.makefile did before."""

    def __init__(self, wrapper):
        super().__init__()
        self._w = wrapper

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self._w.recv(len(buffer))
        n = len(data)
        buffer[:n] = data
        return n  # 0 == EOF


class LockedTLSSocket:
    def __init__(self, ssl_sock):
        ssl_sock.setblocking(False)
        self._s = ssl_sock
        self._ssl_lock = threading.Lock()    # guards every call into OpenSSL
        self._write_lock = threading.Lock()  # makes sendall() atomic per message
        self._closed = False

    # --- reading -----------------------------------------------------------

    def recv(self, bufsize):
        """Return up to `bufsize` bytes; b"" means the connection ended
        (EOF, reset, or closed from another thread)."""
        while True:
            if self._closed:
                return b""
            with self._ssl_lock:
                try:
                    return self._s.recv(bufsize)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                except ssl.SSLEOFError:
                    return b""  # peer closed without close_notify
                except ValueError:
                    return b""  # socket was shut down/unwrapped under us
            if not self._wait(read=True, write=False):
                return b""

    def makefile(self, mode="r", encoding=None, newline=None, **_ignored):
        if "r" not in mode or "w" in mode:
            raise ValueError("LockedTLSSocket.makefile supports read mode only")
        reader = io.BufferedReader(_RawReader(self))
        return io.TextIOWrapper(reader, encoding=encoding or "utf-8", newline=newline)

    # --- writing -----------------------------------------------------------

    def sendall(self, data):
        view = memoryview(data)
        with self._write_lock:  # one whole message at a time
            sent = 0
            while sent < len(view):
                if self._closed:
                    raise OSError("connection closed")
                with self._ssl_lock:
                    try:
                        sent += self._s.send(view[sent:])
                        continue
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                    except ValueError as exc:
                        raise OSError("connection closed") from exc
                if not self._wait(read=True, write=True):
                    raise OSError("connection closed")

    send = sendall

    # --- waiting (outside the SSL lock) -------------------------------------

    def _wait(self, read, write):
        """Sleep until the socket is ready or _POLL_SECONDS pass. Returns
        False if the connection is gone."""
        try:
            fd = self._s.fileno()
            if fd < 0 or self._closed:
                return False
            select.select([fd] if read else [], [fd] if write else [], [], _POLL_SECONDS)
        except (OSError, ValueError):
            return False
        return True

    # --- teardown ------------------------------------------------------------

    def shutdown(self, how):
        with self._ssl_lock:
            try:
                self._s.shutdown(how)
            except (OSError, ValueError):
                pass

    def close(self):
        self._closed = True
        with self._ssl_lock:
            try:
                self._s.close()
            except OSError:
                pass

    def __getattr__(self, name):  # getsockname, getpeername, fileno, ...
        return getattr(self._s, name)
