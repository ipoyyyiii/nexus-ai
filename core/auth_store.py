"""
AUTH STORE
==========
Thread-safe session storage per-domain buat authenticated scanning.

Flow:
1. Tool detect login wall → trigger auth_checkpoint
2. User kasih credentials (auto-login) ATAU session cookies (manual)
3. Session saved di store
4. Semua tools bisa akses session yang sama (share antar tools)
5. Session di-cleanup otomatis pas job selesai

Structure:
    auth_store.get_session("target.com") → AuthSession atau None
    auth_store.save_session("target.com", session)
    auth_store.clear_session("target.com)
"""

import threading
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from datetime import datetime, timedelta


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
    ):
        self.domain = domain
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.auth_type = auth_type
        self.source = source
        self.login_url = login_url
        self.credentials = credentials
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
        """Return kwargs yang bisa langsung dipake di requests.get/post."""
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
            "cookies": self.cookies,
            "headers": self.headers,
            "auth_type": self.auth_type,
            "source": self.source,
            "login_url": self.login_url,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used": self.last_used,
            "request_count": self.request_count,
        }


class AuthStore:
    """Thread-safe session storage per-domain."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, AuthSession] = {}

    def save_session(self, domain: str, session: AuthSession):
        """Simpan session untuk domain."""
        with self._lock:
            self._sessions[domain] = session

    def get_session(self, domain: str) -> Optional[AuthSession]:
        """Ambil session untuk domain. Return None kalau gak ada atau expired."""
        with self._lock:
            session = self._sessions.get(domain)
            if session and session.is_expired():
                del self._sessions[domain]
                return None
            return session

    def has_session(self, domain: str) -> bool:
        """Cek apakah ada session aktif untuk domain."""
        return self.get_session(domain) is not None

    def clear_session(self, domain: str):
        """Hapus session untuk domain."""
        with self._lock:
            self._sessions.pop(domain, None)

    def clear_all(self):
        """Hapus semua session (dipanggil pas job selesai)."""
        with self._lock:
            self._sessions.clear()

    def list_sessions(self) -> Dict[str, Dict]:
        """List semua session aktif."""
        with self._lock:
            return {
                domain: session.to_dict()
                for domain, session in self._sessions.items()
                if not session.is_expired()
            }

    def inject_into_kwargs(self, domain: str, kwargs: Dict) -> Dict:
        """
        Auto-inject session cookies/headers ke requests kwargs.
        Dipanggil dari tools senot yet make request.
        """
        session = self.get_session(domain)
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


def inject_into_session(requests_session, domain: str):
    """
    Inject session cookies/headers ke requests.Session object.
    Dipakai oleh tools yang pakai shared SESSION object.

    Usage:
        from auth_store import inject_into_session
        inject_into_session(SESSION, "target.com")
    """
    auth_session = auth_store.get_session(domain)
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
    Helper function buat make authenticated request dengan login wall detection.

    Flow:
    1. Cek auth_store untuk session
    2. Inject session ke request
    3. Make request
    4. Cek apakah response adalah login wall
    5. Kalau login wall → trigger auth checkpoint
    6. Return (response, login_wall_result)

    Returns:
        (response, login_wall_result)
        login_wall_result = None kalau gak ada login wall
    """
    import requests
    from urllib.parse import urlparse
    from auth_detection import detect_login_wall
    from auth_checkpoint import request_auth

    def _domain_of(url: str) -> str:
        try:
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return url

    domain = _domain_of(url)
    session = auth_store.get_session(domain)

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

    # Check for login wall
    needs_auth_result, login_wall = detect_login_wall(response, url)

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
                    from playwright_tools import login_automator
                    login_url = auth_data.get("login_url", url)
                    login_automator.invoke({
                        "url": login_url,
                        "username": auth_data.get("username", ""),
                        "password": auth_data.get("password", ""),
                    })
                    # Retry request with new session
                    session = auth_store.get_session(domain)
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
                    from playwright_tools import inject_session
                    inject_session.invoke({
                        "url": url,
                        "cookies": cookies_str,
                        "headers": json.dumps(headers_dict) if headers_dict else "",
                    })
                    # Retry request with new session
                    session = auth_store.get_session(domain)
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


def get_auth_kwargs(domain: str) -> Dict:
    """
    Return kwargs dict (cookies + headers) buat di-inject ke requests.get/post.
    Dipakai oleh tools yang gak punya shared SESSION object.

    Usage:
        from auth_store import get_auth_kwargs
        r = requests.get(url, **get_auth_kwargs(domain), headers=HEADERS, timeout=5)
    """
    session = auth_store.get_session(domain)
    if not session:
        return {}
    kwargs = {}
    if session.cookies:
        kwargs["cookies"] = session.cookies
    if session.headers:
        kwargs["headers"] = session.headers
    return kwargs


# Global instance
auth_store = AuthStore()
