"""
Memory layer — two-tier persistence.

Long-term:  ChromaDB vector store at output/chroma_db/
            Semantic similarity search across all past threat reports.

Short-term: Handled by MemorySaver checkpointer in agent/agent.py.
            This module only manages the cross-run vector store.
"""
import json
from datetime import datetime
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

_CHROMA_PATH = Path(__file__).parent.parent / "output" / "chroma_db"
_JSON_PATH   = Path(__file__).parent.parent / "output" / "threat_history.json"

_client     = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _CHROMA_PATH.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(_CHROMA_PATH))
        _collection = _client.get_or_create_collection(
            name="threat_history",
            embedding_function=DefaultEmbeddingFunction(),
        )
    return _collection


def save_threat(scenario_name: str, threat_level: str, confidence: float,
                techniques: list, reasoning: str, analysis: str) -> None:
    """Persist a threat record to Chroma and to JSON (human-readable backup)."""
    ts     = datetime.now().isoformat()
    doc_id = f"threat_{ts.replace(':', '-').replace('.', '-')}"

    document = (
        f"Scenario: {scenario_name}\n"
        f"Threat level: {threat_level}\n"
        f"Techniques: {', '.join(techniques)}\n"
        f"Reasoning: {reasoning}\n"
        f"Analysis: {analysis}"
    )
    _get_collection().add(
        documents=[document],
        metadatas=[{
            "timestamp":    ts,
            "scenario":     scenario_name,
            "threat_level": threat_level,
            "confidence":   confidence,
            "techniques":   json.dumps(techniques),
        }],
        ids=[doc_id],
    )

    _JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    history = _load_json()
    history.append({
        "id":           doc_id,
        "timestamp":    ts,
        "scenario":     scenario_name,
        "threat_level": threat_level,
        "confidence":   confidence,
        "techniques":   techniques,
        "reasoning":    reasoning,
    })
    _JSON_PATH.write_text(json.dumps(history, indent=2))


def search_similar_threats(query: str, n_results: int = 3) -> list:
    """Return up to n_results past threats semantically similar to query."""
    col = _get_collection()
    if col.count() == 0:
        return []
    results = col.query(
        query_texts=[query],
        n_results=min(n_results, col.count()),
    )
    records = []
    for i, doc in enumerate(results["documents"][0]):
        meta = results["metadatas"][0][i]
        records.append({
            "document":     doc,
            "threat_level": meta.get("threat_level", "?"),
            "scenario":     meta.get("scenario", "?"),
            "timestamp":    meta.get("timestamp", "?"),
            "confidence":   meta.get("confidence", 0.0),
            "techniques":   json.loads(meta.get("techniques", "[]")),
            "distance":     results["distances"][0][i] if "distances" in results else None,
        })
    return records


def _load_json() -> list:
    if not _JSON_PATH.exists():
        return []
    try:
        return json.loads(_JSON_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []
