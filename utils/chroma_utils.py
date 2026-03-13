"""
utils/chroma_utils.py
---------------------
Helper module providing a single entry-point function to obtain a
ready-to-use ChromaDB collection for the WATCHDOG attack-pattern
knowledge base.

Usage
-----
    from utils.chroma_utils import get_chroma_collection

    collection = get_chroma_collection()
    results = collection.query(query_texts=["socket connection at install time"], n_results=3)
"""

from __future__ import annotations

import os
from functools import lru_cache

import chromadb
from chromadb.utils import embedding_functions

# ── Configuration ─────────────────────────────────────────────────────────────
# Resolve the chroma_db directory relative to the project root.
# This module lives at watchdog/utils/chroma_utils.py, so the project root
# is two levels up.
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_MODULE_DIR, ".."))

CHROMA_DB_PATH: str = os.environ.get(
    "WATCHDOG_CHROMA_PATH",
    os.path.join(_PROJECT_ROOT, "chroma_db"),
)
COLLECTION_NAME: str = "attack_patterns"
EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"


@lru_cache(maxsize=1)
def _get_client() -> chromadb.PersistentClient:
    """
    Return a singleton ChromaDB persistent client.

    The client is created once and cached for the lifetime of the process
    to avoid repeated disk I/O from re-initialising the database connection.
    """
    return chromadb.PersistentClient(path=CHROMA_DB_PATH)


@lru_cache(maxsize=1)
def _get_embedding_function() -> embedding_functions.SentenceTransformerEmbeddingFunction:
    """Return a cached sentence-transformer embedding function."""
    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )


def get_chroma_collection(
    collection_name: str = COLLECTION_NAME,
) -> chromadb.Collection:
    """
    Return the ChromaDB collection, creating it (empty) if it does not yet exist.

    If the collection is empty (i.e. the seed script has not been run yet),
    a warning is printed so the developer knows to run ``data/seed_chromadb.py``.

    Parameters
    ----------
    collection_name : str
        Name of the ChromaDB collection to retrieve.  Defaults to
        ``"attack_patterns"``.

    Returns
    -------
    chromadb.Collection
        The requested collection, ready for querying.

    Raises
    ------
    RuntimeError
        If the ChromaDB path exists but the collection cannot be retrieved
        due to a schema or version mismatch.
    """
    client = _get_client()
    embed_fn = _get_embedding_function()

    try:
        collection = client.get_collection(
            name=collection_name,
            embedding_function=embed_fn,
        )
    except Exception:
        # Collection doesn't exist yet — create an empty one.
        collection = client.create_collection(
            name=collection_name,
            embedding_function=embed_fn,
            metadata={"description": "Historical supply chain attack behavioral fingerprints"},
        )

    doc_count = collection.count()
    if doc_count == 0:
        print(
            f"[chroma_utils] WARNING: Collection '{collection_name}' is empty. "
            "Run `python data/seed_chromadb.py` to populate it with attack patterns."
        )
    else:
        print(f"[chroma_utils] Collection '{collection_name}' loaded ({doc_count} documents).")

    return collection


def query_attack_patterns(
    capability_description: str,
    n_results: int = 3,
) -> list[dict]:
    """
    Convenience wrapper: embed a capability description and return the
    top-N most similar attack patterns from ChromaDB.

    Parameters
    ----------
    capability_description : str
        Free-text description of the observed package capability fingerprint.
    n_results : int
        Number of results to return (default: 3).

    Returns
    -------
    list[dict]
        Each dict contains keys: ``id``, ``document``, ``metadata``, ``distance``.
    """
    collection = get_chroma_collection()

    raw = collection.query(
        query_texts=[capability_description],
        n_results=min(n_results, collection.count() or 1),
        include=["documents", "metadatas", "distances"],
    )

    results: list[dict] = []
    for idx in range(len(raw["ids"][0])):
        results.append(
            {
                "id": raw["ids"][0][idx],
                "document": raw["documents"][0][idx],
                "metadata": raw["metadatas"][0][idx],
                "distance": raw["distances"][0][idx],
            }
        )
    return results
