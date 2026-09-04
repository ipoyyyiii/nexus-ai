"""Private artifact storage boundary for browser evidence."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from core.config_loader import get_config
from core.structured_contract import ArtifactV1
from core.production_contract import ArtifactSweepV1


class ArtifactStorageError(RuntimeError):
    pass


class ArtifactStore:
    def __init__(self, supabase: Any = None, bucket: str = ""):
        self.supabase = supabase
        config = get_config().get("browser_workflow", {})
        storage = get_config().get("artifact_storage", {})
        self.bucket = bucket or storage.get("bucket") or config.get("artifact_bucket", "nexus-evidence")
        self.local_fallback_enabled = bool(storage.get("local_fallback_enabled", True))
        self.local_root = Path(
            os.environ.get("NEXUS_ARTIFACT_LOCAL_ROOT")
            or storage.get("local_root")
            or "/app/reports/browser-artifacts"
        )
        self.retention_days = max(1, int(storage.get("retention_days", 30)))
        self.signed_url_ttl = max(60, int(storage.get("signed_url_ttl_seconds", 300)))

    def put_bytes(
        self,
        session_id: str,
        data: bytes,
        kind: str,
        mime_type: str,
        extension: str = "bin",
        metadata: Optional[dict] = None,
    ) -> ArtifactV1:
        payload = bytes(data or b"")
        digest = hashlib.sha256(payload).hexdigest()
        artifact_id = f"art_{uuid.uuid4().hex}"
        path = f"{session_id}/browser/{digest}.{extension.lstrip('.')}"
        retention = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        storage_backend = "supabase"
        if self.supabase is not None:
            try:
                storage = self.supabase.storage.from_(self.bucket)
                options = {"content-type": mime_type, "upsert": "true"}
                try:
                    storage.upload(path, payload, options)
                except TypeError:
                    storage.upload(path, payload, file_options=options)
                uri = f"supabase://{self.bucket}/{path}"
            except Exception as exc:
                if not self.local_fallback_enabled:
                    raise ArtifactStorageError(f"Private artifact upload failed: {exc}") from exc
                uri = self._put_local(path, payload)
                storage_backend = "local_fallback"
        else:
            if not self.local_fallback_enabled:
                raise ArtifactStorageError("No private artifact storage backend is configured.")
            uri = self._put_local(path, payload)
            storage_backend = "local_fallback"
        artifact_metadata = {"storage_backend": storage_backend, **(metadata or {})}
        return ArtifactV1(
            artifact_id=artifact_id,
            kind=kind,
            mime_type=mime_type,
            sha256=digest,
            size_bytes=len(payload),
            excerpt="",
            storage_uri=uri,
            redacted=True,
            retention_until=retention.isoformat(),
            metadata=artifact_metadata,
        )

    def _put_local(self, relative_path: str, payload: bytes) -> str:
        """Persist a private fallback artifact on the shared reports volume.

        The URI deliberately contains only a bucket-relative key. The API
        resolves it beneath the configured root and rejects traversal, so a
        database row can never turn into an arbitrary filesystem read.
        """
        safe_parts = [
            re.sub(r"[^A-Za-z0-9_.-]", "_", part)
            for part in str(relative_path).split("/")
            if part not in {"", ".", ".."}
        ]
        if not safe_parts:
            raise ArtifactStorageError("Invalid local artifact path.")
        root = self.local_root.resolve()
        destination = (root.joinpath(*safe_parts)).resolve()
        if root not in destination.parents:
            raise ArtifactStorageError("Local artifact path escaped its storage root.")
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        except Exception as exc:
            raise ArtifactStorageError(f"Local artifact write failed: {type(exc).__name__}") from exc
        return f"local://{self.bucket}/{'/'.join(safe_parts)}"

    def signed_url(self, storage_uri: str, expires_in: Optional[int] = None) -> str:
        if not storage_uri.startswith("supabase://") or self.supabase is None:
            return ""
        _, rest = storage_uri.split("supabase://", 1)
        bucket, path = rest.split("/", 1)
        result = self.supabase.storage.from_(bucket).create_signed_url(
            path, int(expires_in or self.signed_url_ttl)
        )
        if isinstance(result, dict):
            return str(result.get("signedURL") or result.get("signedUrl") or result.get("signed_url") or "")
        return ""

    def sweep_expired(self, *, dry_run: bool = True, limit: int = 500) -> ArtifactSweepV1:
        """Remove only expired private objects whose metadata is already known.

        Database evidence metadata is append-only, so the sweep removes the
        object bytes but never erases the audit record.  It is dry-run by
        default and always constrained to this configured bucket.
        """
        sweep = ArtifactSweepV1(bucket=self.bucket, dry_run=dry_run)
        if self.supabase is None:
            sweep.finished_at = datetime.now(timezone.utc).isoformat()
            return sweep
        try:
            result = (self.supabase.table("evidence_artifacts").select("storage_uri,retention_until")
                      .not_.is_("retention_until", "null")
                      .lte("retention_until", datetime.now(timezone.utc).isoformat())
                      .limit(max(1, min(int(limit), 2000))).execute())
            rows = result.data or []
            sweep.scanned = len(rows)
            sweep.expired = len(rows)
            if not dry_run:
                for row in rows:
                    uri = str(row.get("storage_uri", ""))
                    prefix = f"supabase://{self.bucket}/"
                    if not uri.startswith(prefix):
                        sweep.errors += 1
                        continue
                    path = uri[len(prefix):]
                    try:
                        self.supabase.storage.from_(self.bucket).remove([path])
                        sweep.deleted += 1
                    except Exception:
                        sweep.errors += 1
        except Exception:
            sweep.errors += 1
        sweep.finished_at = datetime.now(timezone.utc).isoformat()
        return sweep
