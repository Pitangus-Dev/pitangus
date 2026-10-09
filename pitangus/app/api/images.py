"""Container image scans (one, or several in a batch) and the read-only credentials of private registries."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from pitangus.shared import settings
from pitangus.app.api.deps import ApiError, Context, Policy, body, documented, guard, json_body
from pitangus.app.api.schemas import AS_RETURNED, MANY, Open
from pitangus.app.api.repositories import QUEUE_LIMIT, BatchSummary
from pitangus.app.api.deps import problem
from pitangus.app.api.compliance import AssetKey, BuiltFrom
from pitangus.app.api.paging import Paging, paging
from pitangus.modules.compliance import provenance
from pitangus.modules.runs import batches
from pitangus.modules.scanning.image import ImageError, check_registry_address, forget_registry, parse_reference, registries, save_registry
from pitangus.shared.i18n import msg, text

router = APIRouter(tags=["images"])


def _image(reference: str, *, in_batch: bool = False) -> dict:
    """The image a reference names, once its registry is checked (a public address unless private ones are allowed).
    `in_batch`: the error names the reference, one of several."""
    try:
        image = parse_reference(reference)
        check_registry_address(image["registry"])
    except ImageError as exc:
        raise ApiError(400, msg("api.image_error", reference=reference[:120], detail=problem(exc)) if in_batch else problem(exc)) from exc
    return image


class ImageLastScan(BaseModel):
    run_id: str
    created_at: str
    status: str


class AnalyzedImage(BaseModel):
    key: str
    name: str
    reference: str | None  # to scan it (again)
    last_scan: ImageLastScan | None
    last_complete: str | None
    analyzed: bool  # False: added by hand, not scanned yet (no findings)
    built_from: BuiltFrom | None


class ImageCounts(BaseModel):
    all: int
    unlinked: int
    label: int
    manual: int


class ImagePage(BaseModel):
    items: list[AnalyzedImage] = Field(max_length=100)
    total: int
    limit: int
    offset: int
    counts: ImageCounts
    repositories: dict[str, int] = Field(max_length=10_000)  # images built from each repository (its asset key)


@router.get("/api/images", response_model=ImagePage)
def analyzed_images(q: str = Query("", max_length=100), link: Literal["all", "unlinked", "label", "manual"] = "all",
                    repository: str = Query("", max_length=200), page: Paging = Depends(paging()), context: Context = Depends(guard())) -> dict:
    """Images (analyzed, or added by hand and not scanned yet) with where each is built from (OCI label or set by hand),
    filtered by name, by how it is linked or by the repository it is built from."""
    found = provenance.images(context.data_dir, query=q, link=link, repository=repository or None)
    return context.render({**page.slice(found["items"]), "counts": found["counts"], "repositories": found["repositories"]})


class ImageRegisterIn(BaseModel):
    """`repository` (an analyzed repository's asset key) links it right away: administrators only. `scan` also queues
    its scan."""
    model_config = ConfigDict(extra="forbid")
    reference: StrictStr = Field(max_length=300)
    repository: AssetKey | None = None
    scan: StrictBool = False


class RegisteredImage(BaseModel):
    key: str
    name: str
    reference: str
    created: bool  # False: it was already on the list (added before, or scanned)
    analyzed: bool
    built_from: BuiltFrom | None
    run: dict[str, Any] | None  # the queued scan, with `scan`


@router.post("/api/images", status_code=200, response_model=RegisteredImage, openapi_extra=documented(ImageRegisterIn))
def register_image(context: Context = Depends(guard(Policy(action="register-image", body=1024))),
                   data: ImageRegisterIn = Depends(body(ImageRegisterIn, msg("api.invalid_image")))) -> dict:
    """Adds a container image to the Images page without scanning it, so it can be linked to the repository it is
    built from and scanned later. Adding one already there (`created: false`) only updates the reference of one not
    scanned yet; `name` and `reference` are what the page shows for it."""
    if data.repository is not None and (context.user or {}).get("role") != "admin":
        raise ApiError(403, msg("api.admin_only"))
    image = _image(data.reference)
    if data.scan and context.state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    user = context.user["username"]
    try:
        result = provenance.register_image(context.data_dir, image, by=user, repository=data.repository)
    except provenance.ProvenanceError as exc:
        raise ApiError(400, exc.message) from exc
    run = context.state.jobs.enqueue_image_scan(image=image, context="", requested_by=user) if data.scan else None
    context.state.log.info("image_registered", extra={"user": user, "reason": f"{image['asset']}{' -> ' + data.repository if data.repository else ''}"})
    return context.render({"key": image["asset"], **result, "run": run})


class ImageRemoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: AssetKey


class RemovedImage(BaseModel):
    key: str


@router.post("/api/images/remove", response_model=RemovedImage, openapi_extra=documented(ImageRemoveIn))
def remove_image(context: Context = Depends(guard(Policy(admin=True, action="remove-image", body=1024))),
                 data: ImageRemoveIn = Depends(body(ImageRemoveIn, msg("api.invalid_image")))) -> dict:
    """Takes an image added by hand off the Images page. Only one never scanned: a scanned image keeps its history."""
    try:
        provenance.remove_image(context.data_dir, data.key)
    except provenance.ImageNotRegistered as exc:
        raise ApiError(404, exc.message) from exc
    except provenance.ImageAnalyzed as exc:
        raise ApiError(409, exc.message) from exc
    context.state.log.info("image_removed", extra={"user": context.user["username"], "reason": data.key})
    return {"key": data.key}


class ImageScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: StrictStr
    context: StrictStr = ""


class QueuedImageScan(BaseModel):
    run: dict[str, Any]
    image: dict[str, Any]


@router.post("/api/images/scans", status_code=202, response_model=QueuedImageScan, openapi_extra=documented(ImageScanIn))
def image_scan(context: Context = Depends(guard(Policy(action="scan-image", body=1024))),
               data: ImageScanIn = Depends(body(ImageScanIn, msg("api.invalid_image")))) -> dict:
    """Queues the scan of a container image, pulled from its registry."""
    image = _image(data.reference)
    if context.state.jobs.pending() >= QUEUE_LIMIT:
        raise ApiError(429, msg("api.queue_full"))
    queued = context.state.jobs.enqueue_image_scan(image=image, context=data.context, requested_by=context.user["username"])
    return context.render({"run": queued, "image": image})


class ImageBatchIn(BaseModel):
    """Blank and repeated references are dropped before counting."""
    model_config = ConfigDict(extra="forbid")
    references: list[str] = Field(max_length=batches.MAX_SELECTED)
    context: str = ""


@router.post("/api/images/batches", status_code=202, response_model=BatchSummary, openapi_extra=documented(ImageBatchIn))
def image_batch(context: Context = Depends(guard(Policy(action="scan-image-batch", body=64_000))),
                data: Any = Depends(json_body)) -> dict:
    """Several images at once (up to 100), in a batch that moves on when the server is free."""
    if (not isinstance(data, dict) or not set(data) <= set(ImageBatchIn.model_fields) or not isinstance(data.get("references"), list)
            or not isinstance(data.get("context", ""), str)):
        raise ApiError(400, msg("api.images_required"))
    if any(not isinstance(item, str) for item in data["references"]):
        raise ApiError(400, msg("api.invalid_image_reference"))
    references = list(dict.fromkeys(item.strip() for item in data["references"] if item.strip()))
    if not 1 <= len(references) <= batches.MAX_SELECTED:
        raise ApiError(400, msg("api.choose_images", max=batches.MAX_SELECTED))
    items = [{"kind": "image", "image": _image(reference, in_batch=True)} for reference in references]
    user = context.user
    label = text(msg("api.scope.images", count=len(items)), context.locale)
    try:
        batch = batches.create(context.data_dir, items, by=user["username"], label=label, context=data.get("context", ""))
    except batches.BatchError as exc:
        raise ApiError(409, problem(exc)) from exc
    context.state.log.info("scan_image_batch", extra={"user": user["username"], "reason": label})
    return context.render(batches.summary(context.data_dir, batch))


class RegistryRow(Open):
    """A registry's saved credentials: the user and the last four characters of the token, never the token."""
    registry: str
    username: str
    last4: str
    saved_at: str | None = None
    saved_by: str | None = None


class Registries(Open):
    registries: list[RegistryRow] = Field(max_length=MANY)
    allow_private: bool | None = None


@router.get("/api/registries", response_model=Registries, **AS_RETURNED)
def registry_list(context: Context = Depends(guard())) -> dict[str, Any]:
    """Registries with saved credentials (never the token), and whether private addresses are allowed."""
    return context.render({"registries": registries(), "allow_private": settings.flag("PITANGUS_ALLOW_PRIVATE_REGISTRIES")})


class RegistryIn(BaseModel):
    """`save` needs `username` and `token`; `remove` only the registry."""
    model_config = ConfigDict(extra="forbid")
    action: Literal["save", "remove"]
    registry: str = Field(max_length=200)
    username: str | None = Field(None, max_length=200)
    token: str | None = None


@router.post("/api/registries", openapi_extra=documented(RegistryIn), response_model=Registries, **AS_RETURNED)
def registry_save(context: Context = Depends(guard(Policy(admin=True, action="save-registry", body=6000))),
                  data: Any = Depends(json_body)) -> dict[str, Any]:
    """Read-only credentials of a private registry: stored encrypted, never sent back to the browser."""
    if not isinstance(data, dict) or data.get("action") not in ("save", "remove") or not isinstance(data.get("registry"), str):
        raise ApiError(400, msg("api.invalid_request"))
    try:
        if data["action"] == "remove":
            return context.render({"registries": forget_registry(data["registry"])})
        if set(data) != set(RegistryIn.model_fields):
            raise ApiError(400, msg("api.invalid_request"))
        return context.render({"registries": save_registry(data["registry"], data["username"], data["token"], by=context.user["username"])})
    except ImageError as exc:
        raise ApiError(400, problem(exc)) from exc
