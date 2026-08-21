"""Tiny local-only fixture app for Stage 6 integration tests.

Run with ``uvicorn benchmarks.stage6.fixture_app:app``.  It intentionally
binds to localhost when launched by the optional benchmark compose profile.
The ``mode`` query parameter selects safe or vulnerable behavior; production
code never imports this module.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, Query
from fastapi.responses import PlainTextResponse, RedirectResponse

app = FastAPI(title="Nexus Stage 6 Fixture App")
_used_coupons: set[str] = set()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "fixture": "stage6"}


@app.get("/error", response_class=PlainTextResponse)
def error_fixture(value: str = "safe", mode: str = Query("safe")) -> str:
    if mode == "vulnerable" and "'" in value:
        return "SQLSTATE[42000] fixture error"
    return "safe response"


@app.get("/xss", response_class=PlainTextResponse)
def xss_fixture(value: str = "", mode: str = Query("safe")) -> str:
    if mode == "vulnerable":
        return f"<html><body>{value}</body></html>"
    escaped = value.replace("<", "&lt;").replace(">", "&gt;")
    return f"<html><body>{escaped}</body></html>"


@app.get("/redirect")
def redirect_fixture(next_url: str = "/", mode: str = Query("safe")):
    destination = next_url if mode == "vulnerable" else "/"
    return RedirectResponse(destination, status_code=302)


@app.get("/cors")
def cors_fixture(origin: str = Header(default=""), mode: str = Query("safe")):
    response = PlainTextResponse('{"fixture":"sensitive"}')
    if mode == "vulnerable":
        response.headers["access-control-allow-origin"] = origin or "*"
        response.headers["access-control-allow-credentials"] = "true"
    else:
        response.headers["access-control-allow-origin"] = "https://stage6.invalid"
    return response


@app.post("/business/coupon")
def coupon_fixture(coupon: str = "demo", mode: str = Query("safe")):
    if mode == "safe" and coupon in _used_coupons:
        return {"accepted": False, "reason": "single_use"}
    _used_coupons.add(coupon)
    return {"accepted": True, "coupon": coupon}


@app.post("/business/price")
def price_fixture(price: float = 100.0, mode: str = Query("safe")):
    return {"accepted": mode == "vulnerable" or price >= 0, "server_price": price if mode == "vulnerable" else 100.0}
