"""
AUTH STORE
==========
Thread-safe session storage per-domain for authenticated scanning.

Flow:
1. Tool detect login wall → trigger auth_checkpoint
2. User kasih credentials (auto-login) ATAU session cookies (manual)
3. Session saved di store
4. Semua tools can akses session that sama (share antar tools)
5. Session cleaned up otomatis pas job selesai

Structure:
    auth_store.get_session("target.com") → AuthSession atau None
    auth_store.save_session("target.com", session)
    auth_store.clear_session("target.com)
"""

import threading
import time
from core.tool_transport import guarded_requests as requests
from typing import Optional, Dict, Any, Set
from urllib.parse import urlparse
from datetime import datetime, timedelta

from core.identity_context import get_execution_context


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return url


class AuthSession:
    """Represents an authenticated session for a domain."""

    def __init__(
        self,
        domain: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_type: str = "cookie",  # "cookie" | "bearer" | "basic"
        source: str = "user",  # "user" (manual) | "auto_login" (Playwright)
        login_url: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
        expires_at: Optional[str] = None,
        identity_id: str = "anonymous",
        session_id: str = "",
        auth_context_id: str = "",
        secret_ref: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
    ):
        self.domain = domain
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.auth_type = auth_type
        self.source = source
        self.login_url = login_url
        # Never retain passwords or raw credential payloads in the process
        # object.  The vault stores secret material; this object only carries
        # the runtime auth material needed by the current request context.
        self.credentials = {"username": credentials.get("username", "")} if credentials else None
        self.identity_id = identity_id or "anonymous"
        self.session_id = session_id
        self.auth_context_id = auth_context_id
        self.secret_ref = secret_ref
        self.storage_state = storage_state or {}
        self.created_at = datetime.now().isoformat()
        self.expires_at = expires_at
        self.last_used = self.created_at
        self.request_count = 0

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now() > exp
        except Exception:
            return False

    def mark_used(self):
        self.last_used = datetime.now().isoformat()
        self.request_count += 1

    def get_request_kwargs(self) -> Dict[str, Any]:
        """Return kwargs that can langsung dipake di requests.get/post."""
        self.mark_used()
        kwargs = {}
        if self.cookies:
            kwargs["cookies"] = self.cookies
        if self.headers:
            kwargs["headers"] = self.headers
        return kwargs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "cookie_names": sorted(self.cookies.keys()),
            "header_names": sorted(self.headers.keys()),
            "auth_type": self.auth_type,
            "source": self.source,
            "login_url": self.login_url,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used": self.last_used,
            "request_count": self.request_count,
            "identity_id": self.identity_id,
            "session_id": self.session_id,
            "auth_context_id": self.auth_context_id,
            "secret_ref": self.secret_ref,
            "storage_state_present": bool(self.storage_state),
        }


class AuthStore:
    """Thread-safe session storage per-domain."""

    def __init__(self):
        self._lock = threading.Lock()
        # Include auth_context_id in the key.  A single identity can have
        # multiple concurrent contexts (for example, a browser context and
        # an API-token context); domain + identity alone would overwrite one
        # with the other and make differential testing unreliable.
        self._sessions: Dict[tuple[str, str, str, str], AuthSession] = {}
        self._legacy_sessions: Dict[str, AuthSession] = {}
        self._job_domains: Dict[str, Set[tuple[str, str, str, str]]] = {}

    @staticmethod
    def _context_values(session_id: str = "", identity_id: str = "") -> tuple[str, str]:
        context = get_execution_context()
        return (
            session_id or (context.session_id if context else ""),
            identity_id or (context.identity_id if context else ""),
        )

    @staticmethod
    def _context_auth_context_id(auth_context_id: str = "") -> str:
        """Resolve the exact auth context required by the active tool run."""
        context = get_execution_context()
        return auth_context_id or (context.auth_context_id if context else "")

    def save_session(self, domain: str, session: AuthSession, session_id: str = "", identity_id: str = ""):
        """Save an identity-scoped session; legacy domain storage is opt-in only."""
        context = get_execution_context()
        session_id, identity_id = self._context_values(session_id, identity_id)
        session.session_id = session_id or session.session_id
        session.identity_id = identity_id or session.identity_id or "anonymous"
        session.auth_context_id = session.auth_context_id or (
            context.auth_context_id if context else ""
        )
        with self._lock:
            if session_id:
                key = (
                    session_id,
                    session.identity_id,
                    session.auth_context_id,
                    domain,
                )
                self._sessions[key] = session
                if context and context.job_id:
                    self._job_domains.setdefault(context.job_id, set()).add(key)
            else:
                self._legacy_sessions[domain] = session

    def get_session(
        self,
        domain: str,
        session_id: str = "",
        identity_id: str = "",
        auth_context_id: str = "",
    ) -> Optional[AuthSession]:
        """Get the exact session selected by the current execution context.

        Identity isolation is not sufficient when one identity has multiple
        active sessions (for example, a refreshed browser context beside an
        API token). If an auth context is present, a session without the same
        context ID is rejected rather than silently reused.
        """
        session_id, identity_id = self._context_values(session_id, identity_id)
        auth_context_id = self._context_auth_context_id(auth_context_id)
        with self._lock:
            session = None
            if session_id:
                identity_key = identity_id or "anonymous"
                if auth_context_id:
                    session = self._sessions.get(
                        (session_id, identity_key, auth_context_id, domain)
                    )
                else:
                    # Without an explicit context, select only when there is
                    # exactly one candidate.  Arbitrarily choosing among
                    # multiple contexts would leak credentials across runs.
                    candidates = [
                        value
                        for (stored_session_id, stored_identity_id, _stored_context_id, stored_domain), value
                        in self._sessions.items()
                        if stored_session_id == session_id
                        and stored_identity_id == identity_key
                        and stored_domain == domain
                    ]
                    if len(candidates) == 1:
                        session = candidates[0]
            # Never fall back to a process-global domain session. This keeps
            # credentials isolated to the explicit session and identity.
            if session and session.is_expired():
                self._remove_session_locked(domain, session)
                return None
            if session and auth_context_id and session.auth_context_id != auth_context_id:
                return None
            return session

    def _remove_session_locked(self, domain: str, session: AuthSession) -> None:
        self._legacy_sessions.pop(domain, None)
        for key, value in list(self._sessions.items()):
            if key[3] == domain and value is session:
                self._sessions.pop(key, None)

    def has_session(self, domain: str, session_id: str = "", identity_id: str = "", auth_context_id: str = "") -> bool:
        """Cek apakah ada session aktif for domain."""
        return self.get_session(domain, session_id=session_id, identity_id=identity_id, auth_context_id=auth_context_id) is not None

    def clear_session(
        self,
        domain: str,
        session_id: str = "",
        identity_id: str = "",
        auth_context_id: str = "",
    ):
        """Delete one identity session, or all identities for a domain."""
        session_id, identity_id = self._context_values(session_id, identity_id)
        auth_context_id = self._context_auth_context_id(auth_context_id)
        with self._lock:
            if session_id:
                identity_key = identity_id or "anonymous"
                for key in list(self._sessions):
                    if (
                        key[0] == session_id
                        and key[1] == identity_key
                        and key[3] == domain
                        and (not auth_context_id or key[2] == auth_context_id)
                    ):
                        self._sessions.pop(key, None)
            else:
                self._legacy_sessions.pop(domain, None)
                for key in list(self._sessions):
                    if key[3] == domain:
                        self._sessions.pop(key, None)

    def track_job_domain(
        self,
        job_id: str,
        domain: str,
        session_id: str = "",
        identity_id: str = "",
        auth_context_id: str = "",
    ):
        session_id, identity_id = self._context_values(session_id, identity_id)
        auth_context_id = self._context_auth_context_id(auth_context_id)
        with self._lock:
            self._job_domains.setdefault(job_id, set()).add(
                (session_id, identity_id or "anonymous", auth_context_id, domain)
            )

    def clear_for_job(self, job_id: str):
        """Scoped cleanup: remove only domains touched by this job."""
        with self._lock:
            keys = self._job_domains.pop(job_id, set())
            for key in keys:
                self._sessions.pop(key, None)
            if not keys:
                # fallback if tracking missed: no-op instead of clear_all
                pass

    def clear_for_session(self, session_id: str) -> None:
        """Clear every runtime auth context belonging to one engagement."""
        if not session_id:
            return
        with self._lock:
            for key in list(self._sessions):
                if key[0] == session_id:
                    self._sessions.pop(key, None)

    def clear_all(self):
        """Delete all session (dipanggil pas job selesai)."""
        with self._lock:
            self._sessions.clear()
            self._legacy_sessions.clear()

    def list_sessions(self) -> Dict[str, Dict]:
        """List all session aktif."""
        with self._lock:
            return {
                f"{session.session_id}:{session.identity_id}:{session.auth_context_id}:{domain}": session.to_dict()
                for (_session_id, _identity_id, _auth_context_id, domain), session in self._sessions.items()
                if not session.is_expired()
            }

    def inject_into_kwargs(
        self,
        domain: str,
        kwargs: Dict,
        session_id: str = "",
        identity_id: str = "",
        auth_context_id: str = "",
    ) -> Dict:
        """
        Auto-inject session cookies/headers ke requests kwargs.
        Dipanggil from tools senot yet make request.
        """
        session = self.get_session(
            domain,
            session_id=session_id,
            identity_id=identity_id,
            auth_context_id=auth_context_id,
        )
        if not session:
            return kwargs

        # Inject cookies
        if session.cookies:
            existing_cookies = kwargs.get("cookies", {})
            if isinstance(existing_cookies, dict):
                existing_cookies.update(session.cookies)
                kwargs["cookies"] = existing_cookies
            else:
                kwargs["cookies"] = session.cookies

        # Inject headers
        if session.headers:
            existing_headers = kwargs.get("headers", {})
            if isinstance(existing_headers, dict):
                existing_headers.update(session.headers)
                kwargs["headers"] = existing_headers
            else:
                kwargs["headers"] = session.headers

        return kwargs


def inject_into_session(
    requests_session,
    domain: str,
    session_id: str = "",
    identity_id: str = "",
    auth_context_id: str = "",
):
    """
    Inject session cookies/headers ke requests.Session object.
    Used by tools that use shared SESSION object.

    Usage:
        from auth_store import inject_into_session
        inject_into_session(SESSION, "target.com")
    """
    auth_session = auth_store.get_session(
        domain,
        session_id=session_id,
        identity_id=identity_id,
        auth_context_id=auth_context_id,
    )
    if not auth_session:
        return

    if auth_session.cookies:
        for name, value in auth_session.cookies.items():
            requests_session.cookies.set(name, value)

    if auth_session.headers:
        requests_session.headers.update(auth_session.headers)


def authenticated_request(
    url: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    timeout: int = 10,
    exec_logger=None,
    **kwargs,
):
    """
    Helper function for make authenticated request with login wall detection.

    Flow:
    1. Cek auth_store for session
    2. Inject session ke request
    3. Make request
    4. Cek apakah response is login wall
    5. Kalau login wall → trigger auth checkpoint
    6. Return (response, login_wall_result)

    Returns:
        (response, login_wall_result)
        login_wall_result = None kalau gak ada login wall
    """
    from core.tool_transport import guarded_requests as requests
    from urllib.parse import urlparse
    from core.auth_detection import detect_login_wall
    from core.auth_checkpoint import request_auth

    def _domain_of(url: str) -> str:
        try:
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return url

    domain = _domain_of(url)
    context = get_execution_context()
    context_session_id = context.session_id if context else ""
    context_identity_id = context.identity_id if context else ""
    context_auth_context_id = context.auth_context_id if context else ""
    session = auth_store.get_session(
        domain,
        session_id=context_session_id,
        identity_id=context_identity_id,
        auth_context_id=context_auth_context_id,
    )

    # Build request kwargs
    request_kwargs = {
        "timeout": timeout,
        "verify": False,
        "allow_redirects": True,
    }

    if session:
        request_kwargs = session.get_request_kwargs()
        request_kwargs["timeout"] = timeout
        request_kwargs["verify"] = False
        request_kwargs["allow_redirects"] = True

    if headers:
        existing = request_kwargs.get("headers", {})
        existing.update(headers)
        request_kwargs["headers"] = existing

    if data:
        request_kwargs["data"] = data

    if json_data:
        request_kwargs["json"] = json_data

    # Make request
    try:
        if method.upper() == "GET":
            response = requests.get(url, **request_kwargs)
        elif method.upper() == "POST":
            response = requests.post(url, **request_kwargs)
        elif method.upper() == "PUT":
            response = requests.put(url, **request_kwargs)
        elif method.upper() == "DELETE":
            response = requests.delete(url, **request_kwargs)
        else:
            response = requests.request(method, url, **request_kwargs)
    except Exception as e:
        return None, None

    # ``detect_login_wall`` returns the typed result directly.  The older
    # helper returned ``(needs_auth, result)``; unpacking it here caused every
    # guarded request made by client-side/postMessage recon to fail with
    # ``cannot unpack non-iterable LoginWallResult``.
    login_wall = detect_login_wall(response, url)
    needs_auth_result = bool(login_wall.detected)
    if not needs_auth_result:
        login_wall = None

    if needs_auth_result and exec_logger:
        # Trigger auth checkpoint
        auth_data = request_auth(
            url=url,
            domain=domain,
            wall_type=login_wall.wall_type,
            evidence=login_wall.evidence,
            has_mfa=login_wall.has_mfa,
            exec_logger=exec_logger,
        )

        if auth_data:
            # Process auth response
            mode = auth_data.get("mode", "")

            if mode == "credentials":
                # Try auto-login
                try:
                    from tools.playwright_tools import login_automator
                    login_url = auth_data.get("login_url", url)
                    from core.tool_decorator import invoke_tool_compat
                    invoke_tool_compat(login_automator, {
                        "url": login_url,
                        "username": auth_data.get("username", ""),
                        "password": auth_data.get("password", ""),
                        "session_id": context_session_id,
                        "identity_id": context_identity_id,
                        "auth_context_id": context_auth_context_id,
                    })
                    # Retry request with new session
                    session = auth_store.get_session(
                        domain,
                        session_id=context_session_id,
                        identity_id=context_identity_id,
                        auth_context_id=context_auth_context_id,
                    )
                    if session:
                        retry_kwargs = session.get_request_kwargs()
                        retry_kwargs["timeout"] = timeout
                        retry_kwargs["verify"] = False
                        retry_kwargs["allow_redirects"] = True
                        if method.upper() == "GET":
                            response = requests.get(url, **retry_kwargs)
                        else:
                            response = requests.post(url, **retry_kwargs)
                except Exception as e:
                    if exec_logger:
                        exec_logger.add_log("AUTH", "ERROR", f"Auto-login failed: {e}")

            elif mode == "session":
                # Inject session cookies
                cookies_str = auth_data.get("cookies", "")
                headers_dict = auth_data.get("headers", {})

                if cookies_str:
                    from tools.playwright_tools import inject_session
                    from core.tool_decorator import invoke_tool_compat
                    invoke_tool_compat(inject_session, {
                        "url": url,
                        "cookies": cookies_str,
                        "headers": json.dumps(headers_dict) if headers_dict else "",
                        "session_id": context_session_id,
                        "identity_id": context_identity_id,
                        "auth_context_id": context_auth_context_id,
                    })
                    # Retry request with new session
                    session = auth_store.get_session(
                        domain,
                        session_id=context_session_id,
                        identity_id=context_identity_id,
                        auth_context_id=context_auth_context_id,
                    )
                    if session:
                        retry_kwargs = session.get_request_kwargs()
                        retry_kwargs["timeout"] = timeout
                        retry_kwargs["verify"] = False
                        retry_kwargs["allow_redirects"] = True
                        if method.upper() == "GET":
                            response = requests.get(url, **retry_kwargs)
                        else:
                            response = requests.post(url, **retry_kwargs)

    return response, login_wall


def get_auth_kwargs(
    domain: str,
    session_id: str = "",
    identity_id: str = "",
    auth_context_id: str = "",
) -> Dict:
    """
    Return kwargs dict (cookies + headers) for di-inject ke requests.get/post.
    Used by tools that do not have shared SESSION object.

    Usage:
        from auth_store import get_auth_kwargs
        r = requests.get(url, **get_auth_kwargs(domain), headers=HEADERS, timeout=5)
    """
    session = auth_store.get_session(
        domain,
        session_id=session_id,
        identity_id=identity_id,
        auth_context_id=auth_context_id,
    )
    if not session:
        return {}
    kwargs = {}
    if session.cookies:
        kwargs["cookies"] = session.cookies
    if session.headers:
        kwargs["headers"] = session.headers
    return kwargs


def auth_get(url: str, timeout: int = 10, exec_logger=None, **kwargs) -> requests.Response:
    """
    Drop-in replacement for requests.get() with auth handling.
    Automatic login wall detection + credential injection.
    """
    response, _ = authenticated_request(url, "GET", timeout=timeout, exec_logger=exec_logger, **kwargs)
    return response


def auth_post(url: str, data=None, json_data=None, timeout: int = 10, exec_logger=None, **kwargs) -> requests.Response:
    """
    Drop-in replacement for requests.post() with auth handling.
    Automatic login wall detection + credential injection.
    """
    response, _ = authenticated_request(url, "POST", data=data, json_data=json_data, timeout=timeout, exec_logger=exec_logger, **kwargs)
    return response


# Global instance
auth_store = AuthStore()
