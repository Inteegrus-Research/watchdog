"""
data/seed_chromadb.py
---------------------
Seed script for the WATCHDOG ChromaDB attack-pattern knowledge base.

Run from the project root:
    python data/seed_chromadb.py

What this script does:
  1. Initialises a persistent ChromaDB client at ../chroma_db (relative to this file).
  2. Creates (or resets) the 'attack_patterns' collection.
  3. Reads the two attack-pattern text files from this directory.
  4. Embeds them with sentence-transformers/all-MiniLM-L6-v2.
  5. Inserts both documents with rich metadata.
  6. Runs a smoke-test query and prints the top result.
"""

from __future__ import annotations

import os
import sys

# ── Ensure we can import from the project root when run directly ──────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import chromadb
from chromadb.utils import embedding_functions

# ── Paths ─────────────────────────────────────────────────────────────────────
CHROMA_DB_PATH = os.path.join(PROJECT_ROOT, "chroma_db")
ATTACK_PATTERNS_DIR = os.path.join(os.path.dirname(__file__), "attack_patterns")

ATTACK_FILES: list[dict] = [
    {
        "filename": "xz_utils_2024.txt",
        "id": "xz_utils_2024",
        "metadata": {
            "attack_name": "XZ Utils Supply Chain Compromise",
            "year": 2024,
            "severity": "CRITICAL",
            "category": "build_system_backdoor",
            "cve": "CVE-2024-3094",
            "keywords": "compression library backdoor maintainer takeover base64 socket",
        },
    },
    {
        "filename": "pytorch_2022.txt",
        "id": "pytorch_2022",
        "metadata": {
            "attack_name": "PyTorch-nightly Dependency Confusion",
            "year": 2022,
            "severity": "HIGH",
            "category": "dependency_confusion",
            "cve": "N/A",
            "keywords": "dependency confusion PyPI SSH exfiltration install hook setup.py",
        },
    },
]


def _load_text(filename: str) -> str:
    """Read and return the content of an attack pattern file."""
    path = os.path.join(ATTACK_PATTERNS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Attack pattern file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def seed_chromadb() -> chromadb.Collection:
    """
    Initialise the ChromaDB client, create the attack_patterns collection,
    embed the attack pattern documents, and insert them.

    Returns the populated collection.
    """
    print(f"[WATCHDOG Seed] ChromaDB path: {CHROMA_DB_PATH}")

    # ── 1. Create persistent client ────────────────────────────────────────────
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)

    # ── 2. Embedding function (sentence-transformers) ──────────────────────────
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )

    # ── 3. Create (or replace) the collection ─────────────────────────────────
    # Delete if already exists so we can re-seed idempotently.
    try:
        client.delete_collection("attack_patterns")
        print("[WATCHDOG Seed] Existing 'attack_patterns' collection deleted.")
    except Exception:
        pass  # Collection did not exist — that's fine.

    collection = client.create_collection(
        name="attack_patterns",
        embedding_function=embed_fn,
        metadata={"description": "Historical supply chain attack behavioral fingerprints"},
    )
    print("[WATCHDOG Seed] Collection 'attack_patterns' created.")

    # ── 4. Load, embed, and insert attack pattern documents ───────────────────
    documents: list[str] = []
    ids: list[str] = []
    metadatas: list[dict] = []

    for entry in ATTACK_FILES:
        text = _load_text(entry["filename"])
        documents.append(text)
        ids.append(entry["id"])
        metadatas.append(entry["metadata"])
        print(f"[WATCHDOG Seed] Loaded: {entry['filename']} ({len(text)} chars)")

    collection.add(documents=documents, ids=ids, metadatas=metadatas)
    print(f"[WATCHDOG Seed] Inserted {len(documents)} documents into ChromaDB.")

    return collection


def smoke_test(collection: chromadb.Collection) -> None:
    """
    Run a test semantic query against the seeded collection and print the result.
    This validates that embedding + retrieval is working end-to-end.
    """
    query = "compression library backdoor with base64 payload and new maintainer account"
    print(f"\n[WATCHDOG Seed] Smoke-test query: '{query}'")

    results = collection.query(
        query_texts=[query],
        n_results=1,
        include=["documents", "metadatas", "distances"],
    )

    top_id = results["ids"][0][0]
    top_meta = results["metadatas"][0][0]
    top_distance = results["distances"][0][0]
    top_doc_preview = results["documents"][0][0][:300].replace("\n", " ")

    print(f"  ✓ Top result ID   : {top_id}")
    print(f"  ✓ Attack name     : {top_meta['attack_name']} ({top_meta['year']})")
    print(f"  ✓ Distance score  : {top_distance:.4f}  (lower = more similar)")
    print(f"  ✓ Document preview: {top_doc_preview}...")
    print("\n[WATCHDOG Seed] ChromaDB seeding complete ✓")


if __name__ == "__main__":
    collection = seed_chromadb()
    smoke_test(collection)
