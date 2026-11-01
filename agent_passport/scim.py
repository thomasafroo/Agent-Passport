"""A SCIM 2.0-shaped subset for provisioning and deprovisioning accountable owners.

This is a demo surface, not a conformant SCIM server. It covers /Users create, list (with an
optional `userName eq "..."` filter), read, PATCH replace of `active`, and DELETE as deprovision.
Authentication is the local console session header. SCIM bearer tokens, and agent passports,
are refused outright: nothing here is reachable with an Authorization header.
"""
from datetime import datetime, timezone
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .core import Denied

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
EXTENSION = "urn:agent-passport:scim:owner"
ACTOR = "SCIM (local console session)"
STATUS = {"OWNER_UNKNOWN": 404, "OWNER_CONFLICT": 409, "OWNER_INVALID": 400}
FILTER = re.compile(r'^userName eq "([^"\\]{1,100})"$')


class ScimUser(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schemas: list[Literal["urn:ietf:params:scim:schemas:core:2.0:User"]] = Field(min_length=1, max_length=1)
    userName: str = Field(min_length=1, max_length=100)
    displayName: str = Field(min_length=1, max_length=100)
    externalId: str | None = Field(default=None, min_length=1, max_length=100)
    # An owner is provisioned active. Deactivation is a separate, signed lifecycle change.
    active: Literal[True] = True


class ActiveValue(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    active: bool


class PatchOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    op: Literal["replace", "Replace"]
    path: Literal["active"] | None = None
    value: bool | ActiveValue

    @model_validator(mode="after")
    def shape(self):
        # Either {"path": "active", "value": false} or {"value": {"active": false}}.
        if (self.path is None) != isinstance(self.value, ActiveValue):
            raise ValueError("Use path 'active' with a boolean value, or no path with {'active': boolean}.")
        return self

    @property
    def active(self):
        return self.value.active if isinstance(self.value, ActiveValue) else self.value


class ScimPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schemas: list[Literal["urn:ietf:params:scim:api:messages:2.0:PatchOp"]] = Field(min_length=1, max_length=1)
    Operations: list[PatchOperation] = Field(min_length=1, max_length=1)


def iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def resource(owner):
    return {"schemas": [USER, EXTENSION], "id": owner["id"], "userName": owner["user_name"],
            "displayName": owner["display_name"], "externalId": owner["external_id"], "active": owner["active"],
            "meta": {"resourceType": "User", "created": iso(owner["created"]), "lastModified": iso(owner["updated"]),
                     "location": f"/scim/v2/Users/{owner['id']}"},
            EXTENSION: {"epoch": owner["epoch"], "runs": owner.get("runs", 0),
                        "deprovisionedAt": iso(owner["deprovisioned_at"]) if owner["deprovisioned_at"] else None}}


def scim(body, status=200, headers=None):
    return JSONResponse(body, status_code=status, media_type="application/scim+json", headers=headers)


def error(status, detail):
    return scim({"schemas": [ERROR], "status": str(status), "detail": detail}, status)


def router(passport, console):
    api = APIRouter(prefix="/scim/v2")

    def authorize(request):
        if "authorization" in request.headers:
            raise HTTPException(403, "SCIM bearer tokens and agent passports are not accepted. Use the local console session.")
        console(request)

    def denied(e):
        return error(STATUS.get(e.rule, 403), e.detail)

    def with_runs(owner_id):
        return next(o for o in passport.owners() if o["id"] == owner_id)

    @api.post("/Users")
    def create(body: ScimUser, request: Request):
        authorize(request)
        try:
            owner = passport.provision_owner(body.userName, body.displayName, body.externalId, ACTOR)["owner"]
        except Denied as e:
            return denied(e)
        return scim(resource(with_runs(owner["id"])), 201, {"Location": f"/scim/v2/Users/{owner['id']}"})

    @api.get("/Users")
    def search(request: Request, filter: str | None = None):
        authorize(request)
        owners = passport.owners()
        if filter is not None:
            match = FILTER.match(filter)
            if not match:
                return error(400, 'Only the filter userName eq "..." is supported.')
            owners = [o for o in owners if o["user_name"] == match.group(1)]
        return scim({"schemas": [LIST], "totalResults": len(owners), "startIndex": 1, "itemsPerPage": len(owners),
                     "Resources": [resource(o) for o in owners]})

    @api.get("/Users/{owner_id}")
    def read(owner_id: str, request: Request):
        authorize(request)
        try:
            passport.owner(owner_id)
        except Denied as e:
            return denied(e)
        return scim(resource(with_runs(owner_id)))

    @api.patch("/Users/{owner_id}")
    def patch(owner_id: str, body: ScimPatch, request: Request):
        authorize(request)
        try:
            passport.set_owner_active(owner_id, body.Operations[0].active, ACTOR)
        except Denied as e:
            return denied(e)
        return scim(resource(with_runs(owner_id)))

    @api.delete("/Users/{owner_id}")
    def delete(owner_id: str, request: Request):
        # Deprovision, not erase: the record stays so past authority remains attributable.
        authorize(request)
        try:
            passport.deprovision_owner(owner_id, ACTOR)
        except Denied as e:
            return denied(e)
        return Response(status_code=204)

    return api
