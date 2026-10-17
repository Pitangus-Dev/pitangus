"""The public demo (`PITANGUS_PUBLIC_DEMO`, deploy/demo): anyone on the internet signs in with published credentials and
browses made-up data, so the server itself, not the panel, keeps it read-only and closed to the outside.

* Requests: only reads, plus the explicit `ALLOWED` list (signing in and out, and the two evidence PDFs, which save
  nothing). The GETs in `REFUSED_READS` act or reach outside, so they are refused too. Checked in the API's middleware,
  before any route or body, whatever the session or role.
* Identity: only the demo account counts (`is_demo_account`); its password is public, so it gets no per-user lock-out
  and a cap on its sessions (identity/auth.py, `public_account`).
* Background and network: no embedded worker or periodic tasks (server.build_state), `worker` and `periodic` refuse to
  run, and the API process can't open network connections (`seal_outbound`). The settings check refuses to start with
  integration credentials or calling-out features on (settings.PUBLIC_DEMO_UNSET / PUBLIC_DEMO_OFF).
"""

from __future__ import annotations

import socket
import threading

from pitangus.shared import settings

READS = frozenset({"GET", "HEAD", "OPTIONS"})
# Writes that change nothing: signing in and out, and audit evidence rendered for the reader (a PDF, nothing saved).
ALLOWED = frozenset({("POST", "/api/auth/login"), ("POST", "/api/auth/logout"),
                     ("POST", "/api/reports/audit"), ("POST", "/api/evidence/portfolio")})
# Reads that act: a round of the periodic tasks, the operators' metrics and GitHub's return addresses (the App
# manifest's one saves credentials).
REFUSED_READS = frozenset({"/api/cron", "/api/metrics", "/github/app-created", "/oauth/callback"})


def enabled() -> bool:
    return settings.flag("PITANGUS_PUBLIC_DEMO")


def refuses(method: str, path: str) -> bool:
    """Whether the public demo turns this request away (always False outside the demo)."""
    if not enabled():
        return False
    method = method.upper()
    if (method, path) in ALLOWED:
        return False
    return method not in READS or path in REFUSED_READS


def username() -> str:
    return settings.text("PITANGUS_PUBLIC_DEMO_USER").strip().lower()


def is_demo_account(user: dict | None) -> bool:
    """The only account that may hold a session in the demo: the configured one, and never an administrator."""
    return user is not None and user.get("username") == username() and user.get("role") != "admin"


def credentials() -> dict | None:
    """What the sign-in page shows in the demo (public by design); None outside it."""
    if not enabled():
        return None
    return {"username": username(), "password": settings.text("PITANGUS_PUBLIC_DEMO_PASSWORD") or None}


class OutboundRefused(ConnectionRefusedError):
    pass


_seal = threading.Lock()
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_getaddrinfo = socket.getaddrinfo
_resolvable: frozenset[str] = frozenset()


def _local(sock: socket.socket) -> bool:
    return getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX


def _connect(sock: socket.socket, address):
    if not _local(sock):
        raise OutboundRefused("outbound connections are off in the public demo")
    return _original_connect(sock, address)


def _connect_ex(sock: socket.socket, address):
    if not _local(sock):
        raise OutboundRefused("outbound connections are off in the public demo")
    return _original_connect_ex(sock, address)


def _getaddrinfo(host, *args, **kwargs):
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    if name is None or str(name).lower() in _resolvable:
        return _original_getaddrinfo(host, *args, **kwargs)
    raise socket.gaierror(socket.EAI_NONAME, "name lookups are off in the public demo")


def _database_host() -> str | None:
    from sqlalchemy.engine import make_url
    try:
        return make_url(settings.text("PITANGUS_DATABASE_URL")).host
    except Exception:  # noqa: BLE001 — an unreadable URL fails later, where the database is opened
        return None


def seal_outbound() -> None:
    """From now on this process opens no network connection made from Python (urllib, http.client, httpx, the Docker
    SDK…): every TCP/UDP connect fails at once, and names resolve only for the database (psycopg looks it up in Python,
    then libpq connects in C, untouched), so nothing even asks DNS about another host."""
    global _resolvable
    with _seal:
        _resolvable = frozenset(host.lower() for host in ("localhost", _database_host()) if host)
        socket.getaddrinfo = _getaddrinfo
        socket.socket.connect = _connect  # type: ignore[method-assign,assignment]
        socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign,assignment]


def unseal_outbound() -> None:
    """For tests: back to normal."""
    with _seal:
        socket.getaddrinfo = _original_getaddrinfo
        socket.socket.connect = _original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _original_connect_ex  # type: ignore[method-assign]


def sealed() -> bool:
    return socket.socket.connect is _connect
