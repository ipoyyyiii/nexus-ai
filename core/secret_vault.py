"""Engagement-scoped encrypted secret storage.

The vault never returns secret material through API/UI models.  Supabase is
used only for encrypted ciphertext when a client is supplied; the process
cache keeps the decrypted value available for the current worker lifetime.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _key_from_env() -> bytes:
    raw = os.environ.get("NEXUS_AUTH_VAULT_KEY", "").strip()
    if not raw:
        raise RuntimeError("NEXUS_AUTH_VAULT_KEY is required for encrypted auth storage.")
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:
        key = b""
    if len(key) not in {16, 24, 32}:
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = b""
    if len(key) not in {16, 24, 32}:
        key = hashlib.sha256(raw.encode()).digest()
    return key


class SecretVault:
    def __init__(self, supabase_client: Any = None, default_ttl_minutes: int = 240):
        self.sb = supabase_client
        self.default_ttl_minutes = max(5, default_ttl_minutes)
        self._lock = threading.RLock()
        self._memory: Dict[str, Dict[str, Any]] = {}

    def put(self, session_id: str, identity_id: str, purpose: str, value: Any, ttl_minutes: Optional[int] = None) -> Dict[str, Any]:
        if not session_id or not identity_id:
            raise ValueError("session_id and identity_id are required for secret storage.")
        secret_ref = f"secret_{uuid.uuid4().hex}"
        nonce = os.urandom(12)
        aad = f"{session_id}:{identity_id}:{purpose}".encode()
        plaintext = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        ciphertext = AESGCM(_key_from_env()).encrypt(nonce, plaintext, aad)
        expires_at = _now() + timedelta(minutes=ttl_minutes or self.default_ttl_minutes)
        row = {
            "secret_ref": secret_ref,
            "session_id": session_id,
            "identity_id": identity_id,
            "purpose": purpose[:200],
            "algorithm": "AES-256-GCM",
            "nonce_b64": base64.urlsafe_b64encode(nonce).decode(),
            "ciphertext_b64": base64.urlsafe_b64encode(ciphertext).decode(),
            "secret_fingerprint": hashlib.sha256(plaintext).hexdigest()[:32],
            "expires_at": expires_at.isoformat(),
        }
        with self._lock:
            self._memory[secret_ref] = {**row, "value": value}
        if self.sb:
            self.sb.table("auth_secret_blobs").upsert({k: v for k, v in row.items() if k != "value"}).execute()
        return {k: row[k] for k in ("secret_ref", "secret_fingerprint", "expires_at", "algorithm")}

    def get(self, secret_ref: str, session_id: str, identity_id: str) -> Any:
        with self._lock:
            row = self._memory.get(secret_ref)
        if not row and self.sb:
            rows = self.sb.table("auth_secret_blobs").select("*").eq("secret_ref", secret_ref).eq("session_id", session_id).eq("identity_id", identity_id).limit(1).execute().data or []
            row = rows[0] if rows else None
        if not row:
            raise KeyError("Secret reference not found.")
        if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= _now():
            self.delete(secret_ref, session_id, identity_id)
            raise PermissionError("Secret reference expired.")
        if "value" in row:
            return row["value"]
        nonce = base64.urlsafe_b64decode(row["nonce_b64"])
        ciphertext = base64.urlsafe_b64decode(row["ciphertext_b64"])
        aad = f"{session_id}:{identity_id}:{row['purpose']}".encode()
        plaintext = AESGCM(_key_from_env()).decrypt(nonce, ciphertext, aad)
        value = json.loads(plaintext.decode())
        with self._lock:
            self._memory[secret_ref] = {**row, "value": value}
        return value

    def delete(self, secret_ref: str, session_id: str = "", identity_id: str = "") -> None:
        with self._lock:
            self._memory.pop(secret_ref, None)
        if self.sb:
            query = self.sb.table("auth_secret_blobs").delete().eq("secret_ref", secret_ref)
            if session_id:
                query = query.eq("session_id", session_id)
            if identity_id:
                query = query.eq("identity_id", identity_id)
            query.execute()

    def purge_expired(self) -> int:
        expired = []
        now = _now()
        with self._lock:
            for ref, row in self._memory.items():
                try:
                    if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= now:
                        expired.append((ref, row.get("session_id", ""), row.get("identity_id", "")))
                except Exception:
                    expired.append((ref, "", ""))
        for ref, session_id, identity_id in expired:
            self.delete(ref, session_id, identity_id)
        if self.sb:
            self.sb.table("auth_secret_blobs").delete().lt("expires_at", now.isoformat()).execute()
        return len(expired)

    def delete_for_session(self, session_id: str) -> int:
        refs = []
        with self._lock:
            refs = [
                (ref, row.get("identity_id", ""))
                for ref, row in self._memory.items()
                if row.get("session_id") == session_id
            ]
        for ref, identity_id in refs:
            self.delete(ref, session_id, identity_id)
        if self.sb:
            self.sb.table("auth_secret_blobs").delete().eq("session_id", session_id).execute()
        return len(refs)
