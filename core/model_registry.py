import os
import re
from typing import List, Optional
from langchain_openai import ChatOpenAI
from crewai import LLM

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
# ============================================================
MODEL_REGISTRY = [
    # ── PAID ──────────────────────────────────────────────────
    {
        "id": "claude-opus-4.8",
        "label": "Claude Opus 4.8",
        "provider": "Anthropic",
        "tier": "paid",
        "slug": "openrouter/anthropic/claude-opus-4-8",
        "description": "Most capable. Best for analysis & reports.",
    },
    {
        "id": "gpt-5.5",
        "label": "GPT-5.5",
        "provider": "OpenAI",
        "tier": "paid",
        "slug": "openrouter/openai/gpt-5.5", 
        "description": "Frontier reasoning. Strong tool use.",
    },
    {
        "id": "glm-5.2",
        "label": "GLM 5.2",
        "provider": "Z.ai",
        "tier": "paid",
        "slug": "openrouter/z-ai/glm-5.2", 
        "description": "1M context. 5–7× cheaper than Opus. Agent workflows.",
    },
    {
        "id": "deepseek-v4-pro",
        "label": "DeepSeek V4 Pro",
        "provider": "DeepSeek",
        "tier": "paid",
        "slug": "openrouter/deepseek/deepseek-v4-pro",
        "description": "Raja reasoning dan coding. Sangat tajam for analisis vulnerability dan patuh 100% on parameter tool-calling.",
    },
    {
        "id": "mimo-v2.5-pro",
        "label": "MiMo V2.5 Pro",
        "provider": "Xiaomi",
        "tier": "paid",
        "slug": "openrouter/xiaomi/mimo-v2.5-pro",
        "description": "Ultra long-context. Sangat pas kalau lo butuh agen that bertugas membaca tumpukan dokumentasi kode atau log pentest raksasa.",
    },
    {
        "id": "minimax-m3",
        "label": "MiniMax M3",
        "provider": "MiniMax",
        "tier": "paid",
        "slug": "openrouter/minimax/minimax-m3",
        "description": "Super cepat dan responsif. Good for live-streaming chat interface di dashboard, tapi perlu guardrail ketat di prompt tools.",
    },
    {
        "id": "qwen-3.7-max",
        "label": "Qwen 3.7 Max",
        "provider": "Qwen",
        "tier": "paid",
        "slug": "openrouter/qwen/qwen3.7-max",
        "description": "The Agent Frontier. Flagship model terbaik for multi-step long workflow, rajanya terminal execution dan anti-hallucination.",
    },
    {
        "id": "tokenhub-glm-5v-turbo",
        "label": "GLM 5V Turbo (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/glm-5v-turbo",  
        "description": "1M Free Tokens. Model coding multimodal from Zhipu via Tencent Cloud. Anti rate-limit!",
    },
    {
        "id": "tokenhub-glm-5.2",
        "label": "GLM 5.2 (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/glm-5.2", 
        "description": "1M context. Versi TokenHub via Tencent Cloud. Sangat efisien for Agent workflows.",
    },
    {
        "id": "tokenhub-deepseek-v4-pro",
        "label": "DeepSeek V4 Pro (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/deepseek-v4-pro-202606",  
        "description": "Raja reasoning dan coding versi TokenHub. Sangat tajam for analisis vulnerability dan patuh parameter tool-calling.",
    },
    {
        "id": "tokenhub-minimax-m3",
        "label": "MiniMax M3 (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/minimax-m3",  
        "description": "Super cepat dan responsif versi TokenHub. Good for live-streaming chat interface di dashboard.",
    },
    {
        "id": "tokenhub-mimo-v2.5-pro",
        "label": "Mimo v2.5 Pro (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/mimo-v2.5-pro",  
        "description": "Super cepat dan responsif versi TokenHub. Good for live-streaming chat interface di dashboard.",
    },

    # ── FREE ──────────────────────────────────────────────────
    {
        "id": "qwen3-coder-free",
        "label": "Qwen3 Coder 480B",
        "provider": "Qwen",
        "tier": "free",
        "slug": "openrouter/qwen/qwen3-coder:free",
        "description": "Raja coding tier gratisan. 480B parameter MoE, sangat disiplin for structured JSON dan tool-calling.",
    },
    {
        "id": "tencent-hy3-free",
        "label": "Tencent Hy3",
        "provider": "Tencent",
        "tier": "free",
        "slug": "openrouter/tencent/hy3:free",
        "description": "295B MoE. Sangat kuat di reasoning, punya grounded behavior tinggi for nekan halusinasi.",
    },
    {
        "id": "llama-3.3-70b-free",
        "label": "Llama 3.3 70B Instruct",
        "provider": "Meta",
        "tier": "free",
        "slug": "openrouter/meta-llama/llama-3.3-70b-instruct:free", 
        "description": "Sangat tertib urusan stop-token. Pengendali eror parsing paling aman dan patuh format.",
    },
    {
        "id": "hermes-3-405b-free",
        "label": "Hermes 3 405B Instruct",
        "provider": "Nous Research",
        "tier": "free",
        "slug": "openrouter/nousresearch/hermes-3-llama-3.1-405b:free",
        "description": " Giant model 405B versi uncensored. Good for pentesting scenarios without guardrail rejection barriers.",
    },
    {
        "id": "nemotron-3-ultra-free",
        "label": "NVIDIA Nemotron 3 Ultra",
        "provider": "NVIDIA",
        "tier": "free",
        "slug": "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", 
        "description": "550B MoE with 1M context window. Didesain kuat for multi-step planning agen.",
    },
    {
        "id": "gpt-oss-120b-free",
        "label": "GPT-OSS 120B",
        "provider": "OpenAI (OSS)",
        "tier": "free",
        "slug": "openrouter/openai/gpt-oss-120b:free", 
        "description": "Model andalan OpenAI open-weight. Kapasitas nalar tinggi tapi rawan rate-limit upstream.",
    },
    {
        "id": "gpt-oss-20b-free",
        "label": "GPT-OSS 20B",
        "provider": "OpenAI (OSS)",
        "tier": "free",
        "slug": "openrouter/openai/gpt-oss-20b:free",
        "description": "Varian ringan from gpt-oss, gesit for pengetesan format awal.",
    },
    {
        "id": "glm-4.5-air-free",
        "label": "GLM 4.5 Air",
        "provider": "Z.ai",
        "tier": "free",
        "slug": "openrouter/z-ai/glm-4.5-air:free", 
        "description": "Ringan dan responsif for tugas ringkasan teks cepat.",
    },
]


def _is_local_enabled() -> bool:
    return os.environ.get("NEXUS_LOCAL_LLM_ENABLED", "").lower() in ("1", "true", "yes", "on")


def _local_base_url() -> str:
    raw = os.environ.get("NEXUS_LOCAL_LLM_BASE_URL", "")
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return ""
    if not raw.rstrip("/").endswith("/v1"):
        raw = raw.rstrip("/") + "/v1"
    return raw


def _local_api_key() -> str:
    return os.environ.get("NEXUS_LOCAL_LLM_API_KEY") or "EMPTY"


def _local_model_ids() -> List[str]:
    raw = os.environ.get("NEXUS_LOCAL_LLM_MODELS", "")
    return [m.strip() for m in raw.split(",") if m.strip()]


def _local_registry() -> List[dict]:
    if not _is_local_enabled():
        return []
    ids = _local_model_ids()
    if not ids:
        return []
    out = []
    for mid in ids:
        slug = mid.strip()
        id_clean = "local-" + re.sub(r"[^a-z0-9-]", "-", slug.lower().replace("/", "-").replace("_", "-"))
        label_base = slug.split("/")[-1] if "/" in slug else slug
        out.append({
            "id": id_clean,
            "label": f"{label_base} (Local)",
            "provider": "Local",
            "tier": "local",
            "slug": slug,
            "description": "Local model via Kaggle/Colab ngrok - pilih manual saat credit habis.",
        })
    return out


def _all_models() -> List[dict]:
    return MODEL_REGISTRY + _local_registry()


def list_available_models() -> List[dict]:
    has_openrouter = bool(os.environ.get("OPENROUTER_API_KEY"))
    has_local = _is_local_enabled() and bool(_local_base_url())
    has_tokenhub = bool(os.environ.get("TOKENHUB_API_KEY") and os.environ.get("TOKENHUB_API_BASE"))
    if not has_openrouter and not has_local and not has_tokenhub:
        return []

    models = []
    for m in _all_models():
        if m["id"].startswith("local-") and not has_local:
            continue
        if m["id"].startswith("tokenhub-") and not has_tokenhub:
            continue
        if not m["id"].startswith("local-") and not m["id"].startswith("tokenhub-") and not has_openrouter:
            continue
        models.append({
            "id": m["id"],
            "label": m["label"],
            "provider": m["provider"],
            "tier": m["tier"],
            "description": m["description"],
        })
    return models


def _local_preference_id(model_id: Optional[str]) -> Optional[str]:
    """Resolve both UI IDs and provider model IDs to the local registry ID.

    The UI advertises ``local-ravenx-cyberagent`` while OpenAI-compatible
    clients naturally send ``ravenx-cyberagent``.  Treating the latter as an
    unknown model used to silently select the OpenRouter fallback chain, which
    is unsafe when the operator explicitly configured a local provider.
    """
    candidate = str(model_id or "").strip()
    if not candidate:
        return None
    for item in _local_registry():
        aliases = {
            item["id"],
            item["slug"],
            item["slug"].split("/")[-1],
            item["id"][len("local-"):],
        }
        if candidate in aliases:
            return item["id"]
    return None


def _find(model_id: str) -> Optional[dict]:
    exact = next((m for m in _all_models() if m["id"] == model_id), None)
    if exact:
        return exact
    local_id = _local_preference_id(model_id)
    if local_id:
        return next((m for m in _local_registry() if m["id"] == local_id), None)
    return None


def build_llm(preferred_model_id: Optional[str] = None):
    """
    Return CrewAI LLM instance with fallback chain.

    CrewAI's LLM class properly passes api_key & base_url ke litellm,
    solving the issue where ChatOpenAI's credentials were ignored.
    """
    if not os.environ.get("OPENROUTER_API_KEY") and not _is_local_enabled():
        raise RuntimeError("OPENROUTER_API_KEY / NEXUS_LOCAL_LLM_BASE_URL not set di .env.")

    # Direct local path - no fallback mixing.  Accept the raw provider model
    # ID as a backwards-compatible alias for the UI's local-* ID.
    local_preference = _local_preference_id(preferred_model_id)
    if local_preference:
        base_url = _local_base_url()
        if not base_url:
            raise RuntimeError("NEXUS_LOCAL_LLM_BASE_URL belum diisi untuk model local.")
        info = _find(local_preference)
        slug = info["slug"] if info else local_preference.replace("local-", "")
        return LLM(
            model=slug,
            api_key=_local_api_key(),
            base_url=base_url,
            temperature=0.2,
            max_tokens=4096,
            # CrewAI forwards unknown keyword arguments into the provider
            # constructor. Passing a nested ``additional_params`` mapping
            # makes it leak into OpenAI's completion request as an unsupported
            # request field. ``default_headers`` is a provider-level option
            # and keeps the ngrok header out of the JSON payload.
            default_headers={"ngrok-skip-browser-warning": "true"},
        )

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

    # ── ROUTING ENGINE: CREWAI LLM CLASS ──

    is_tokenhub = final_chain[0]["id"].startswith("tokenhub-") if final_chain else False

    if is_tokenhub:
        # TokenHub: return langsung TANPA fallback ke OpenRouter
        return LLM(
            model=final_chain[0]["slug"],
            api_key=os.getenv("TOKENHUB_API_KEY"),
            base_url=os.getenv("TOKENHUB_API_BASE"),
            temperature=0.2,
            max_tokens=4096,
        )

    # Untuk OpenRouter: pass only OpenRouter models to fallback list
    instances: List[LLM] = []
    fallback_names: List[str] = []
    for m in final_chain:
        if m["id"].startswith("local-") or m["id"].startswith("tokenhub-"):
            continue
        instances.append(
            LLM(
                model=m["slug"],
                api_key=os.environ.get("OPENROUTER_API_KEY"),
                base_url="https://openrouter.ai/api/v1",
                temperature=0.2,
                max_tokens=4096,
            )
        )
        fallback_names.append(m["slug"])

    if not instances:
        raise RuntimeError("No available OpenRouter models configured.")

    if len(instances) == 1:
        return instances[0]

    # Fallback antar OpenRouter models - pass model names, not LLM objects
    primary = instances[0]
    return LLM(
        model=primary.model,
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
        temperature=0.2,
        max_tokens=4096,
        fallbacks=fallback_names[1:],
    )


def build_chat_llm(preferred_model_id: Optional[str] = None):
    """Return a chat model instance (OpenRouter, TokenHub, or Local)."""
    # Local prefix takes priority - direct routing
    local_preference = _local_preference_id(preferred_model_id)
    if local_preference:
        base_url = _local_base_url()
        if not base_url:
            raise RuntimeError("NEXUS_LOCAL_LLM_BASE_URL belum diisi untuk model local.")
        info = _find(local_preference)
        slug = info["slug"] if info else local_preference.replace("local-", "")
        return ChatOpenAI(
            model=slug,
            api_key=_local_api_key(),
            base_url=base_url,
            temperature=0.3,
            default_headers={"ngrok-skip-browser-warning": "true"},
        )

    selected = _find(preferred_model_id) if preferred_model_id else None
    model = selected or next((item for item in _all_models() if item["tier"] in ("free", "local")), MODEL_REGISTRY[0])

    if model["id"].startswith("local-"):
        base_url = _local_base_url()
        if not base_url:
            raise RuntimeError("NEXUS_LOCAL_LLM_BASE_URL belum diisi untuk model local.")
        return ChatOpenAI(
            model=model["slug"],
            api_key=_local_api_key(),
            base_url=base_url,
            temperature=0.3,
            default_headers={"ngrok-skip-browser-warning": "true"},
        )

    if model["id"].startswith("tokenhub-"):
        return ChatOpenAI(
            model=model["slug"],
            api_key=os.environ.get("TOKENHUB_API_KEY"),
            base_url=os.environ.get("TOKENHUB_API_BASE"),
            temperature=0.3,
        )

    if not os.environ.get("OPENROUTER_API_KEY"):
        # Jika tidak ada key OpenRouter tapi local aktif, pakai local
        if _is_local_enabled() and _local_base_url():
            local_models = _local_registry()
            if local_models:
                m = local_models[0]
                return ChatOpenAI(
                    model=m["slug"],
                    api_key=_local_api_key(),
                    base_url=_local_base_url(),
                    temperature=0.3,
                    default_headers={"ngrok-skip-browser-warning": "true"},
                )
        raise RuntimeError("OPENROUTER_API_KEY not set in the backend environment.")

    return ChatOpenAI(
        model=model["slug"],
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        base_url=OPENROUTER_BASE,
        temperature=0.3,
        default_headers=OPENROUTER_HEADERS,
    )


def chain_summary(preferred_model_id: Optional[str] = None) -> List[str]:
    """Return urutan model di chain - for logging di api.py."""
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
    for m in _local_registry():
        if m not in ordered:
            ordered.append(m)
    seen, result = set(), []
    for m in ordered:
        if m["id"] not in seen:
            result.append(m["label"])
            seen.add(m["id"])
    return result
