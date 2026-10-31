"""Loopback-only demo control plane plus bearer-authenticated agent API."""
import os
from pathlib import Path
import secrets

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .broker import Executor
from .core import Passport, Denied
from .demo import Demo
from .scim import router as scim_router


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)


class Delegation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=60)
    scopes: list[Scope] = Field(min_length=1, max_length=20)
    expires: float
    holder_key: str | None = Field(default=None, max_length=100)


class Operation(Scope):
    request_key: str = Field(min_length=1, max_length=100)


class Reconciliation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: str = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=1, max_length=500)


class RequestSizeLimit:
    """Bound the actual body, including chunked requests without Content-Length."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 16384:
                return await JSONResponse({"detail":"Request too large."}, status_code=413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type":"http.request", "body":bytes(body), "more_body":False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(directory=None):
    passport = Passport(directory or os.environ.get("PASSPORT_STATE_DIR", ".state"))
    executor = Executor.from_environment(passport)
    demo = Demo(passport, executor)
    session = secrets.token_urlsafe(32)
    app = FastAPI(title="Agent Passport", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    app.add_middleware(RequestSizeLimit)
    app.state.passport, app.state.demo, app.state.executor = passport, demo, executor

    @app.middleware("http")
    async def boundaries(request, call_next):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Cross-origin requests are not permitted."}, status_code=403)
        length = request.headers.get("content-length", "0")
        if not length.isdigit() or int(length) > 16384:
            return JSONResponse({"detail": "Request too large."}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.exception_handler(Denied)
    async def denied_handler(request, exc):
        return JSONResponse(exc.as_dict(), status_code=403)

    def console(request):
        if not secrets.compare_digest(request.headers.get("x-passport-console", ""), session):
            raise HTTPException(403, "The local console session is required.")

    def bearer(request):
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(401, "An agent passport is required.")
        return header[7:]

    def proof(request):
        # Required only for key-bound passports; the engine decides.
        return request.headers.get("x-passport-proof")

    @app.get("/api/session")
    def bootstrap():
        # Local console is a trusted operator. This is CSRF protection, not user auth.
        return {"console_token": session}

    @app.get("/api/state")
    def state(request: Request):
        console(request)
        return demo.snapshot()

    @app.post("/api/demo/{action}")
    def scenario(action: str, request: Request):
        console(request)
        if action == "reset":
            return demo.reset()
        if action == "step":
            return demo.step()
        if action == "fork":
            return demo.fork()
        raise HTTPException(404)

    @app.post("/api/grants/{gid}/revoke")
    def revoke(gid: str, request: Request):
        console(request)
        with demo.lock:
            if gid not in {g["id"] for g in demo.snapshot()["grants"]}:
                raise HTTPException(404)
            passport.revoke(gid)
            return demo.snapshot()

    @app.post("/api/owners/{owner_id}/deactivate")
    def deactivate_owner(owner_id: str, request: Request):
        # Operator offboarding from the console. Voids every grant issued for this owner, online.
        console(request)
        with demo.lock:
            if owner_id not in {o["id"] for o in passport.owners()}:
                raise HTTPException(404)
            passport.deprovision_owner(owner_id, "Local console")
            return demo.snapshot()

    # SCIM-shaped owner provisioning: console session only, never the agent API or a bearer token.
    app.include_router(scim_router(passport, console))

    @app.post("/api/live/issue")
    def issue_live(request: Request):
        console(request)
        return demo.issue_live()

    @app.get("/api/operations/unresolved")
    def unresolved(request: Request):
        console(request)
        return {"operations": passport.unresolved(demo.run_id)}

    @app.post("/api/operations/{oid}/reconcile")
    def reconcile(oid: str, body: Reconciliation, request: Request):
        # Operator decision only. There is deliberately no agent-API equivalent.
        console(request)
        if oid not in {o["id"] for o in passport.unresolved(demo.run_id)}:
            raise HTTPException(404)
        return passport.reconcile(oid, body.outcome, body.reason)

    @app.post("/api/operations/{oid}/lookup")
    def lookup(oid: str, request: Request):
        # Operator surface: reconcile from the upstream's effect record. No agent-API equivalent.
        console(request)
        if oid not in {o["id"] for o in passport.unresolved(demo.run_id)}:
            raise HTTPException(404)
        return executor.resolve(oid)

    @app.get("/api/evidence")
    def evidence(request: Request):
        console(request)
        with demo.lock:
            return {**passport.evidence(demo.run_id), "metrics": demo.metrics, "credential_mode": executor.provider.mode}

    @app.post("/api/checkpoint")
    def checkpoint(request: Request):
        # Operator surface. The checkpoint anchors nothing until a copy leaves this machine's state.
        console(request)
        with demo.lock:
            return {"checkpoint": passport.checkpoint(demo.run_id)}

    @app.post("/api/agent/delegate")
    def delegate(body: Delegation, request: Request):
        return passport.delegate(bearer(request), body.subject, [s.model_dump() for s in body.scopes], body.expires,
                                 body.holder_key, proof(request))

    @app.get("/api/agent/passport")
    def own_passport(request: Request):
        return passport.inspect(bearer(request), proof(request))

    @app.post("/api/agent/execute")
    def execute(body: Operation, request: Request):
        return executor.execute(bearer(request), body.resource, body.action, body.request_key, proof(request))

    @app.get("/health")
    def health():
        return {"status": "ok", "credential_mode": executor.provider.mode}

    web = Path(__file__).resolve().parent.parent / "web"

    @app.get("/")
    def index():
        return FileResponse(web / "index.html")

    app.mount("/assets", StaticFiles(directory=web), name="assets")
    return app
