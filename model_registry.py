import os
from typing import List, Optional
from langchain_openai import ChatOpenAI

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
OPENROUTER_HEADERS = {
    "HTTP-Referer": "http://localhost:3000",
    "X-Title": "Nexus Pentest AI",
}

def _or(model_slug: str, temperature: float = 0.2) -> ChatOpenAI:
    """Helper bikin ChatOpenAI instance via OpenRouter."""
    return ChatOpenAI(
        model=model_slug,
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        base_url=OPENROUTER_BASE,
        temperature=temperature,
        default_headers=OPENROUTER_HEADERS,
    )


# ============================================================
# DAFTAR MODEL
# Urutan di sini = urutan di dropdown frontend + urutan fallback default
# ============================================================
MODEL_REGISTRY = [
    # ── PAID ──────────────────────────────────────────────────
    {
        "id": "claude-opus-4.8",
        "label": "Claude Opus 4.8",
        "provider": "Anthropic",
        "tier": "paid",
        "slug": "anthropic/claude-opus-4-8",
        "description": "Most capable. Best for analysis & reports.",
    },
    {
        "id": "gpt-5.5",
        "label": "GPT-5.5",
        "provider": "OpenAI",
        "tier": "paid",
        "slug": "openai/gpt-5.5",
        "description": "Frontier reasoning. Strong tool use.",
    },
    {
        "id": "glm-5.2",
        "label": "GLM 5.2",
        "provider": "Z.ai",
        "tier": "paid",
        "slug": "z-ai/glm-5.2",
        "description": "1M context. 5–7× cheaper than Opus. Agent workflows.",
    },
    # ── FREE ──────────────────────────────────────────────────
    {
        "id": "gpt-oss-120b-free",
        "label": "GPT-OSS 120B",
        "provider": "OpenAI (OSS)",
        "tier": "free",
        "slug": "openai/gpt-oss-120b:free",
        "description": "Strongest free model. Apache 2.0. Great tool use.",
    },
    {
        "id": "gpt-oss-20b-free",
        "label": "GPT-OSS 20B",
        "provider": "OpenAI (OSS)",
        "tier": "free",
        "slug": "openai/gpt-oss-20b:free",
        "description": "Faster than 120B. Matches o3-mini on code.",
    },
    {
        "id": "nemotron-ultra-free",
        "label": "NVIDIA Nemotron 3 Ultra",
        "provider": "NVIDIA",
        "tier": "free",
        "slug": "nvidia/nemotron-3-ultra:free",
        "description": "550B MoE. 1M context. Long-horizon agent tasks.",
    },
    {
        "id": "laguna-m1-free",
        "label": "Poolside Laguna M.1",
        "provider": "Poolside",
        "tier": "free",
        "slug": "poolside/laguna-m.1:free",
        "description": "Built for agentic tool-calling workflows.",
    },
    {
        "id": "north-mini-code-free",
        "label": "Cohere North Mini Code",
        "provider": "Cohere",
        "tier": "free",
        "slug": "cohere/north-mini-code:free",
        "description": "Fast (69 tok/s). Structured output. Recon tasks.",
    },
    {
        "id": "mimo-v2.5-free",
        "label": "MiMo V2.5",
        "provider": "Xiaomi",
        "tier": "free",
        "slug": "xiaomi/mimo-v2.5:free",
        "description": "1M context. Solid agentic performance.",
    },
    {
        "id": "glm-4.5-air-free",
        "label": "GLM 4.5 Air",
        "provider": "Z.ai",
        "tier": "free",
        "slug": "z-ai/glm-4.5-air:free",
        "description": "Lightest. Good for simple summarization tasks.",
    },
    {
        "id": "llama-3.3-70b-free",
        "label": "Llama 3.3 70B",
        "provider": "Meta",
        "tier": "free",
        "slug": "meta-llama/llama-3.3-70b:free",
        "description": "Classic reliable fallback. Sometimes rate-limited upstream.",
    },
]


def list_available_models() -> List[dict]:
    """
    Return semua model kalau OPENROUTER_API_KEY ke-set.
    Kalau key gak ada, return empty list (frontend bakal nampilin error).
    """
    if not os.environ.get("OPENROUTER_API_KEY"):
        return []
    return [
        {
            "id": m["id"],
            "label": m["label"],
            "provider": m["provider"],
            "tier": m["tier"],
            "description": m["description"],
        }
        for m in MODEL_REGISTRY
    ]


def _find(model_id: str) -> Optional[dict]:
    return next((m for m in MODEL_REGISTRY if m["id"] == model_id), None)


def build_llm(preferred_model_id: Optional[str] = None):
    """
    Return LangChain Runnable dengan fallback chain otomatis.

    Urutan chain:
    1. Model pilihan user (preferred_model_id) — kalau ada & valid
    2. Sisa paid model
    3. Semua free model (dari yang paling capable ke paling ringan)

    .with_fallbacks() otomatis nyoba next model di chain kalau yang
    sebelumnya throw exception (termasuk quota habis, 402, 429).
    """
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise RuntimeError("OPENROUTER_API_KEY belum di-set di .env backend.")

    ordered: List[dict] = []

    # 1. Model pilihan user
    if preferred_model_id:
        preferred = _find(preferred_model_id)
        if preferred:
            ordered.append(preferred)

    # 2. Sisa paid
    for m in MODEL_REGISTRY:
        if m["tier"] == "paid" and m not in ordered:
            ordered.append(m)

    # 3. Free pool
    for m in MODEL_REGISTRY:
        if m["tier"] == "free" and m not in ordered:
            ordered.append(m)

    # Dedup
    seen, final_chain = set(), []
    for m in ordered:
        if m["id"] not in seen:
            final_chain.append(m)
            seen.add(m["id"])

    instances = [_or(m["slug"]) for m in final_chain]

    if len(instances) == 1:
        return instances[0]

    primary, *fallbacks = instances
    return primary.with_fallbacks(fallbacks)


def chain_summary(preferred_model_id: Optional[str] = None) -> List[str]:
    """Return urutan model di chain — buat logging di api.py."""
    ordered: List[dict] = []
    if preferred_model_id:
        preferred = _find(preferred_model_id)
        if preferred:
            ordered.append(preferred)
    for m in MODEL_REGISTRY:
        if m["tier"] == "paid" and m not in ordered:
            ordered.append(m)
    for m in MODEL_REGISTRY:
        if m["tier"] == "free" and m not in ordered:
            ordered.append(m)
    seen, result = set(), []
    for m in ordered:
        if m["id"] not in seen:
            result.append(m["label"])
            seen.add(m["id"])
    return result