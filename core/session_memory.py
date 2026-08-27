"""
SESSION MEMORY
===============
Agent can "ingat" findings from session-session senot yetnya terhadap target
that sama. Waktu lo mulai pentest target X lagi besok, agent load dulu
all that udah found senot yetnya — subdomain, vuln, endpoint, tech stack.

Saved di Supabase tabel `session_memory`:

    create table if not exists session_memory (
        id uuid primary key default gen_random_uuid(),
        target_domain text not null,
        memory_type text not null,
        content jsonb not null,
        session_id uuid references sessions(id),
        created_at timestamptz default now(),
        updated_at timestamptz default now()
    );
    create index if not exists idx_memory_domain on session_memory(target_domain);

memory_type values:
- "subdomain"    — subdomain that udah found
- "tech_stack"   — tech stack that terdeteksi
- "vuln"         — vulnerability that udah found/dicoba
- "endpoint"     — endpoint/parameter that udah found
- "finding"      — confirmed finding (for reference di session baru)
"""

import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from core.knowledge_graph_contract import TargetMemoryRecordV1
from core.knowledge_graph_engine import TargetKnowledgeGraphEngine
from core.redact import redact


def _domain_of(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return url


class SessionMemory:
    def __init__(self, supabase_client, knowledge_repository=None):
        self.sb = supabase_client
        self.knowledge_repository = knowledge_repository

    def save(
        self,
        target: str,
        memory_type: str,
        content: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Simpan satu memory entry. Kalau udah ada entry that sama
        (domain + type + content key utama), update instead of insert.
        """
        domain = _domain_of(target)
        content = redact(content)
        try:
            self.sb.table("session_memory").insert({
                "target_domain": domain,
                "memory_type": memory_type,
                "content": content,
                "session_id": session_id,
                "updated_at": datetime.now().isoformat(),
            }).execute()
            return True
        except Exception as e:
            print(f"[MEMORY] Save failed: {e}")
            return False

    def save_knowledge(self, record: TargetMemoryRecordV1) -> bool:
        """Persist provenance-aware memory; this never overwrites old memory."""
        try:
            self.sb.table("target_memory_records").insert(redact(record.model_dump(mode="json"))).execute()
            return True
        except Exception as exc:
            # Memory is advisory.  A failed advisory write must not become
            # permission to use an unpersisted fact as current evidence.
            print(f"[MEMORY] Knowledge save failed: {redact(str(exc))[:300]}")
            return False

    def load_knowledge(
        self,
        target: str,
        *,
        session_id: str = "",
        scope: Any = None,
        include_historical: bool = True,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        target_fp = TargetKnowledgeGraphEngine.target_fingerprint(target)
        scope_fp = TargetKnowledgeGraphEngine.scope_fingerprint(scope)
        try:
            query = self.sb.table("target_memory_records").select("*").eq("target_fingerprint", target_fp)
            if scope_fp:
                query = query.eq("scope_fingerprint", scope_fp)
            if session_id:
                query = query.or_(f"session_id.eq.{session_id},source_session_id.eq.{session_id}")
            if not include_historical:
                query = query.eq("status", "current")
            return redact(query.order("created_at", desc=True).limit(min(1000, max(1, limit))).execute().data or [])
        except Exception as exc:
            print(f"[MEMORY] Knowledge load failed: {redact(str(exc))[:300]}")
            return []

    def load(self, target: str, memory_type: Optional[str] = None) -> List[Dict]:
        """
        Load all memory for domain target tertentu.
        Kalau memory_type di-specify, filter by type.
        """
        domain = _domain_of(target)
        try:
            query = self.sb.table("session_memory").select("*").eq("target_domain", domain)
            if memory_type:
                query = query.eq("memory_type", memory_type)
            res = query.order("updated_at", desc=True).limit(200).execute()
            return res.data or []
        except Exception as e:
            print(f"[MEMORY] Load failed: {e}")
            return []

    def build_context(self, target: str) -> str:
        """
        Build context string from all memory for di-inject ke agent prompt.
        Return string that siap dipaste sebagai backstory tambahan agent.
        """
        all_memories = self.load(target)
        knowledge = self.load_knowledge(target, include_historical=True, limit=200)
        if not all_memories:
            if not knowledge:
                return ""

        domain = _domain_of(target)
        context_parts = [f"\n## Previous Intelligence on {domain}\n"]

        if knowledge:
            context_parts.append("**Knowledge graph memory (historical until revalidated):**")
            for item in knowledge[:20]:
                content = item.get("content") or {}
                context_parts.append(f"  - [{item.get('status', 'historical')}] {item.get('memory_type', 'unknown')}: {redact(str(content))[:300]}")
            context_parts.append("Do not treat historical memory as live evidence without a current structured observation.")

        # Group by type
        by_type: Dict[str, List] = {}
        for m in all_memories:
            t = m.get("memory_type", "unknown")
            by_type.setdefault(t, []).append(m["content"])

        if "tech_stack" in by_type:
            techs = [c.get("tech", str(c)) for c in by_type["tech_stack"][:5]]
            context_parts.append(f"**Tech Stack**: {', '.join(techs)}")

        if "subdomain" in by_type:
            subs = [c.get("subdomain", str(c)) for c in by_type["subdomain"][:20]]
            context_parts.append(f"**Known Subdomains** ({len(subs)}): {', '.join(subs)}")

        if "endpoint" in by_type:
            eps = [c.get("endpoint", str(c)) for c in by_type["endpoint"][:15]]
            context_parts.append(f"**Discovered Endpoints** ({len(eps)}): {', '.join(eps)}")

        if "vuln" in by_type:
            context_parts.append(f"\n**Previously Tested Vulnerabilities:**")
            for v in by_type["vuln"][:10]:
                status = v.get("status", "tested")
                vuln_type = v.get("type", "unknown")
                param = v.get("parameter", "")
                context_parts.append(f"  - {vuln_type} on {param}: {status}")

        if "finding" in by_type:
            context_parts.append(f"\n**Historical finding claims (must be revalidated):**")
            for f in by_type["finding"][:10]:
                context_parts.append(f"  - [{f.get('severity', '?')}] {f.get('title', str(f))}")

        if "legacy_report_observation" in by_type:
            context_parts.append("\n**Legacy report observations (diagnostic only; not canonical evidence):**")
            for item in by_type["legacy_report_observation"][:10]:
                context_parts.append(f"  - {redact(str(item))[:300]}")

        if "tested_params" in by_type:
            context_parts.append(f"\n**Already Tested Parameters (skip these):**")
            for tp in by_type["tested_params"][:20]:
                context_parts.append(f"  - {tp.get('tool', '?')}: {tp.get('param', '?')} → {tp.get('result', 'tested')}")

        context_parts.append(
            "\n*Use this intelligence to skip already-tested vectors and focus on new attack surfaces.*"
        )
        return "\n".join(context_parts)

    def save_findings_from_report(
        self,
        target: str,
        report: str,
        session_id: Optional[str] = None,
    ):
        """
        Parse report teks from assessor dan extract findings for disimpen ke memory.
        Dipanggil otomatis di akhir run_pentest_job sealready job selesai.
        """
        import re
        domain = _domain_of(target)

        # Extract severity mentions
        severity_pattern = re.compile(
            r'(CRITICAL|HIGH|MEDIUM|LOW)[^\n]*?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*(?:Injection|XSS|SSRF|IDOR|Inclusion|Redirect|Exposure|Bypass|Vulnerability))',
            re.IGNORECASE
        )
        for match in severity_pattern.finditer(report):
            # Compatibility-only parser.  A regex over narrative/report text
            # is never admitted to the canonical knowledge graph or treated
            # as a validated finding; retain it as historical diagnostics.
            self.save(target, "legacy_report_observation", {
                "kind": "finding_claim",
                "severity": match.group(1).upper(),
                "title": match.group(2),
                "session_id": session_id,
                "found_at": datetime.now().isoformat(),
            }, session_id)

        # Extract subdomain mentions
        subdomain_pattern = re.compile(
            rf'([a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.{re.escape(domain)})',
            re.IGNORECASE
        )
        for match in subdomain_pattern.finditer(report):
            self.save(target, "legacy_report_observation", {
                "kind": "subdomain_claim",
                "subdomain": match.group(1).lower(),
            }, session_id)

    def save_tested_params(
        self,
        target: str,
        tool_name: str,
        params: list,
        result: str = "tested",
        session_id: Optional[str] = None,
    ):
        """
        Simpan parameter that udah di-test supaya gak di-test lagi di scan berikutnya.
        """
        domain = _domain_of(target)
        for param in params:
            self.save(target, "tested_params", {
                "tool": tool_name,
                "param": param,
                "result": result,
                "session_id": session_id,
            }, session_id)

    def get_tested_params(
        self,
        target: str,
        tool_name: str = "",
    ) -> list:
        """
        Ambil list parameter that udah di-test.
        """
        memory_type = "tested_params"
        all_memories = self.load(target, memory_type)
        tested = []
        for m in all_memories:
            content = m.get("content", {})
            if tool_name and content.get("tool") != tool_name:
                continue
            tested.append(content.get("param", ""))
        return list(set(tested))

MEMORY_TABLE_SQL = """
create table if not exists session_memory (
    id uuid primary key default gen_random_uuid(),
    target_domain text not null,
    memory_type text not null,
    content jsonb not null,
    session_id uuid,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);
create index if not exists idx_memory_domain on session_memory(target_domain);
create index if not exists idx_memory_type on session_memory(memory_type);
"""
