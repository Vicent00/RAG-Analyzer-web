from dataclasses import dataclass
from typing import List, Optional
import json

@dataclass
class KnowledgeEntry:
    """Esquema universal para toda la información del RAG"""
    id: str
    source_url: str
    source_type: str  # "swc_registry", "audit_report", "blog_post", etc.
    title: str
    content_text: str
    category: str
    tags: List[str]
    severity: Optional[str] = None
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_url": self.source_url,
            "source_type": self.source_type,
            "title": self.title,
            "content_text": self.content_text,
            "category": self.category,
            "tags": self.tags,
            "severity": self.severity,
            "cwe_id": self.cwe_id
        }
    
    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)
