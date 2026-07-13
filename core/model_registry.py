import os
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
        "description": "Raja reasoning dan coding. Sangat tajam untuk analisis vulnerability dan patuh 100% pada parameter tool-calling.",
    },
    {
        "id": "mimo-v2.5-pro",
        "label": "MiMo V2.5 Pro",
        "provider": "Xiaomi",
        "tier": "paid",
        "slug": "openrouter/xiaomi/mimo-v2.5-pro",
        "description": "Ultra long-context. Sangat pas kalau lo butuh agen yang bertugas membaca tumpukan dokumentasi kode atau log pentest raksasa.",
    },
    {
        "id": "minimax-m3",
        "label": "MiniMax M3",
        "provider": "MiniMax",
        "tier": "paid",
        "slug": "openrouter/minimax/minimax-m3",
        "description": "Super cepat dan responsif. Bagus untuk live-streaming chat interface di dashboard, tapi perlu guardrail ketat di prompt tools.",
    },
    {
        "id": "qwen-3.7-max",
        "label": "Qwen 3.7 Max",
        "provider": "Qwen",
        "tier": "paid",
        "slug": "openrouter/qwen/qwen3.7-max",
        "description": "The Agent Frontier. Flagship model terbaik untuk multi-step long workflow, rajanya terminal execution dan anti-hallucination.",
    },
    {
        "id": "tokenhub-glm-5v-turbo",
        "label": "GLM 5V Turbo (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/glm-5v-turbo",  
        "description": "1M Free Tokens. Model coding multimodal dari Zhipu via Tencent Cloud. Anti rate-limit!",
    },
    {
        "id": "tokenhub-glm-5.2",
        "label": "GLM 5.2 (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/glm-5.2", 
        "description": "1M context. Versi TokenHub via Tencent Cloud. Sangat efisien untuk Agent workflows.",
    },
    {
        "id": "tokenhub-deepseek-v4-pro",
        "label": "DeepSeek V4 Pro (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/deepseek-v4-pro-202606",  
        "description": "Raja reasoning dan coding versi TokenHub. Sangat tajam untuk analisis vulnerability dan patuh parameter tool-calling.",
    },
    {
        "id": "tokenhub-minimax-m3",
        "label": "MiniMax M3 (TokenHub)",
        "provider": "Tencent-TokenHub",
        "tier": "paid",
        "slug": "openai/minimax-m3",  
        "description": "Super cepat dan responsif versi TokenHub. Bagus untuk live-streaming chat interface di dashboard.",
    },

    # ── FREE ──────────────────────────────────────────────────
    {
        "id": "qwen3-coder-free",
        "label": "Qwen3 Coder 480B",
        "provider": "Qwen",
        "tier": "free",
        "slug": "openrouter/qwen/qwen3-coder:free",
        "description": "Raja coding tier gratisan. 480B parameter MoE, sangat disiplin untuk structured JSON dan tool-calling.",
    },
    {
        "id": "tencent-hy3-free",
        "label": "Tencent Hy3",
        "provider": "Tencent",
        "tier": "free",
        "slug": "openrouter/tencent/hy3:free",
        "description": "295B MoE. Sangat kuat di reasoning, punya grounded behavior tinggi buat nekan halusinasi.",
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
        "description": "Model raksasa 405B versi uncensored. Bagus untuk skenario pentesting tanpa halangan guardrail penolakan.",
    },
    {
        "id": "nemotron-3-ultra-free",
        "label": "NVIDIA Nemotron 3 Ultra",
        "provider": "NVIDIA",
        "tier": "free",
        "slug": "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", 
        "description": "550B MoE dengan 1M context window. Didesain kuat untuk multi-step planning agen.",
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
        "description": "Varian ringan dari gpt-oss, gesit buat pengetesan format awal.",
    },
    {
        "id": "glm-4.5-air-free",
        "label": "GLM 4.5 Air",
        "provider": "Z.ai",
        "tier": "free",
        "slug": "openrouter/z-ai/glm-4.5-air:free", 
        "description": "Ringan dan responsif untuk tugas ringkasan teks cepat.",
    },
]


def list_available_models() -> List[dict]:
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
    Return CrewAI LLM instance dengan fallback chain.

    CrewAI's LLM class properly passes api_key & base_url ke litellm,
    solving the issue where ChatOpenAI's credentials were ignored.
    """
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise RuntimeError("OPENROUTER_API_KEY not yet di-set di .env backend.")

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

    # Cek apakah model pertama adalah TokenHub
    is_tokenhub = final_chain[0]["id"].startswith("tokenhub-")

    if is_tokenhub:
        # TokenHub: return langsung TANPA fallback ke OpenRouter
        # (credentials berbeda, gak bisa fallback)
        return LLM(
            model=final_chain[0]["slug"],
            api_key=os.getenv("TOKENHUB_API_KEY"),
            base_url=os.getenv("TOKENHUB_API_BASE"),
            temperature=0.2,
            max_tokens=4096,
        )

    # Untuk OpenRouter: bisa pake fallback antar OpenRouter models
    instances: List[LLM] = []
    for m in final_chain:
        instances.append(
            LLM(
                model=m["slug"],
                api_key=os.environ.get("OPENROUTER_API_KEY"),
                base_url="https://openrouter.ai/api/v1",
                temperature=0.2,
                max_tokens=4096,
            )
        )

    if len(instances) == 1:
        return instances[0]

    # Fallback antar OpenRouter models — pass model names, not LLM objects
    primary = instances[0]
    fallback_names = [m["slug"] for m in final_chain[1:]]
    return LLM(
        model=primary.model,
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
        temperature=0.2,
        max_tokens=4096,
        fallbacks=fallback_names,
    )


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