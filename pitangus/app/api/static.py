"""The panel (SPA) and its built assets, served without a session."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from pitangus.app.api.deps import ApiError, Policy, guard
from pitangus.shared.i18n import msg

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"  # pitangus/app/static
PUBLIC = Policy(public=True, enrolment=True)

router = APIRouter(tags=["static"], include_in_schema=False)


def _file(name: str) -> Response:
    target = STATIC_DIR / name
    if target.is_symlink() or not target.is_file():
        raise ApiError(404, msg("api.file_not_found"))
    # Exact content type, without the charset Starlette would add to text/*.
    return Response(target.read_bytes(), headers={"content-type": mimetypes.guess_type(name)[0] or "application/octet-stream"})


@router.get("/", dependencies=[Depends(guard(PUBLIC))])
def index() -> Response:
    return _file("index.html")


@router.get("/assets/{name:path}", dependencies=[Depends(guard(PUBLIC))])
def asset(request: Request) -> Response:
    # Only /assets/<file>: the decoded path can't climb out (no "..", no subfolders) or be absurdly long.
    path = request.url.path
    if len(path) >= 160 or path.count("/") != 2:
        raise ApiError(404, msg("api.not_found"))
    return _file(path.lstrip("/"))
