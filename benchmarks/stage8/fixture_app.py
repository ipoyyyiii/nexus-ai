"""Local-only Stage 8 benchmark fixture application.

This app is intentionally deterministic and has no outbound network path. It is
used by benchmark tests and the optional ``benchmark-labs`` compose profile;
it must never be used as a production target.
"""
from __future__ import annotations

import copy
import html
import threading
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Nexus Stage 8 Local Benchmark Lab")
_lock = threading.RLock()
_INITIAL = {
    "balance": 100,
    "version": 1,
    "race_effects": 0,
    "callbacks": [],
    "coupon_uses": {},
    "entities": {
        "tenant-a-object-1": {"tenant": "tenant-a", "owner": "user-a", "value": "alpha"},
        "tenant-b-object-1": {"tenant": "tenant-b", "owner": "user-b", "value": "bravo"},
    },
}
_state: dict[str, Any] = copy.deepcopy(_INITIAL)


def _reset() -> None:
    global _state
    with _lock:
        _state = copy.deepcopy(_INITIAL)


class Mutation(BaseModel):
    value: str = Field(default="safe", max_length=200)
    tenant: str = Field(default="tenant-a", max_length=80)
    object_id: str = Field(default="tenant-a-object-1", max_length=120)
    amount: int = Field(default=1, ge=-1000, le=1000)
    idempotency_key: str = Field(default="", max_length=120)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "fixture": "stage8", "network": "local-only"}


@app.post("/reset")
def reset_fixture(x_stage8_reset: str = Header(default="")) -> dict[str, str]:
    if x_stage8_reset != "local-fixture-reset":
        raise HTTPException(status_code=403, detail="local reset header required")
    _reset()
    return {"status": "reset"}


@app.get("/state")
def state() -> dict[str, Any]:
    with _lock:
        return copy.deepcopy(_state)


@app.get("/api/sqli", response_class=PlainTextResponse)
def sqli_fixture(value: str = "safe", mode: str = Query("negative")) -> str:
    if mode == "positive" and "'" in value:
        return "SQLSTATE[42000] stage8 fixture error"
    if mode == "noisy":
        return "request completed with a generic warning"
    return "safe response"


@app.get("/api/xss", response_class=HTMLResponse)
def xss_fixture(value: str = "", mode: str = Query("negative")) -> str:
    rendered = value if mode == "positive" else html.escape(value)
    return f"<html><body><form><label>value<input name=\"value\"></label></form><output>{rendered}</output></body></html>"


@app.post("/api/oob")
def oob_fixture(body: Mutation, mode: str = Query("negative")) -> dict[str, Any]:
    callback = body.value if mode == "positive" else ""
    with _lock:
        if callback:
            _state["callbacks"].append(callback)
    return {"accepted": True, "callback_recorded": bool(callback), "correlation_id": callback}


@app.post("/api/race")
def race_fixture(body: Mutation, mode: str = Query("negative")) -> dict[str, Any]:
    with _lock:
        if mode == "positive":
            _state["race_effects"] += 2
            _state["balance"] -= body.amount
        else:
            _state["race_effects"] += 1
            _state["balance"] -= min(body.amount, 1)
        _state["version"] += 1
        return {"accepted": True, "effects": _state["race_effects"], "balance": _state["balance"], "version": _state["version"]}


@app.post("/api/coupon")
def coupon_fixture(body: Mutation, mode: str = Query("negative")) -> dict[str, Any]:
    key = body.idempotency_key or body.value
    with _lock:
        uses = int(_state["coupon_uses"].get(key, 0))
        if mode != "positive" and uses:
            return {"accepted": False, "reason": "single_use", "uses": uses}
        _state["coupon_uses"][key] = uses + 1
        return {"accepted": True, "uses": uses + 1}


@app.get("/api/tenant/{tenant}/objects/{object_id}")
def tenant_object(tenant: str, object_id: str, mode: str = Query("negative")) -> dict[str, Any]:
    with _lock:
        item = _state["entities"].get(object_id)
        if not item:
            raise HTTPException(status_code=404, detail="not found")
        if mode != "positive" and item["tenant"] != tenant:
            raise HTTPException(status_code=403, detail="tenant boundary")
        return {"object_id": object_id, **item}


@app.post("/api/mutation")
def mutation_fixture(body: Mutation, mode: str = Query("negative")) -> dict[str, Any]:
    accepted = mode == "positive" or body.amount >= 0
    return {"accepted": accepted, "server_value": body.value if accepted else "safe"}


@app.get("/browser/workflow", response_class=HTMLResponse)
def browser_workflow() -> str:
    return """<html><body><main data-tenant=tenant-a><h1>Stage 8 Workflow</h1>
    <form method=post action=/api/coupon><label>Coupon<input name=value></label>
    <button type=submit>Apply coupon</button></form></main></body></html>"""


@app.get("/redirect")
def redirect_fixture(next_url: str = "/", mode: str = Query("negative")):
    destination = next_url if mode == "positive" else "/browser/workflow"
    return RedirectResponse(destination, status_code=302)
