"""Page snapshot for human-like recon."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PageSnapshot:
    url: str
    title: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    buttons: List[Dict[str, Any]] = field(default_factory=list)
    xhr: List[Dict[str, Any]] = field(default_factory=list)
    js_secrets: Dict[str, Any] = field(default_factory=dict)
    storage: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    text_preview: str = ""
