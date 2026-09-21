import re
from dataclasses import dataclass
from pathlib import Path

from sentinelgate.models import DataClassification, TrustLevel
from sentinelgate.security import injection_signals
from sentinelgate.taint import highest_classification, least_trusted

LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


@dataclass(frozen=True)
class KnowledgeDocument:
    source: str
    title: str
    content: str
    classification: DataClassification
    trust: TrustLevel
    labels: frozenset[str]


class KnowledgeBase:
    """Bounded, read-only search over operator-controlled text documents."""

    def __init__(self, root: Path, max_file_bytes: int = 256_000):
        self.root = root.resolve()
        self.max_file_bytes = max_file_bytes

    def search(self, arguments: dict):
        # Imported lazily to avoid an executor/knowledge import cycle.
        from sentinelgate.executor import ToolResult

        query = str(arguments["query"]).strip()
        terms = {term.casefold() for term in re.findall(r"[a-zA-Z0-9_-]+", query)}
        ranked: list[tuple[int, KnowledgeDocument]] = []
        for document in self._documents():
            haystack = f"{document.title}\n{document.content}".casefold()
            score = sum(haystack.count(term) for term in terms)
            if score:
                ranked.append((score, document))
        ranked.sort(key=lambda item: (-item[0], item[1].source))
        selected = [document for _, document in ranked[:5]]
        output = {
            "query": query,
            "matches": [
                {
                    "source": item.source,
                    "title": item.title,
                    "classification": item.classification.value,
                    "snippet": self._snippet(item.content, terms),
                }
                for item in selected
            ],
        }
        classifications = [item.classification for item in selected]
        trusts = [item.trust for item in selected]
        labels = {"knowledge_base"}
        for item in selected:
            labels.update(item.labels)
            labels.add(f"classification:{item.classification.value}")
            if injection_signals(item.content):
                labels.add("prompt_injection")
        return ToolResult(
            output=output,
            classification=highest_classification(classifications),
            labels=frozenset(labels),
            trust=least_trusted(trusts),
            sources=tuple(item.source for item in selected),
        )

    def _documents(self) -> list[KnowledgeDocument]:
        if not self.root.is_dir():
            return []
        documents = []
        for path in sorted(self.root.rglob("*")):
            if path.suffix.casefold() not in {".md", ".txt"} or path.is_symlink():
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(self.root):
                continue
            try:
                if resolved.stat().st_size > self.max_file_bytes:
                    continue
                raw = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            metadata, content = self._parse_document(raw)
            try:
                classification = DataClassification(
                    metadata.get("classification", "internal").casefold()
                )
                trust = TrustLevel(metadata.get("trust", "mixed").casefold())
            except ValueError:
                # Invalid labels fail closed to the strongest restrictions.
                classification = DataClassification.RESTRICTED
                trust = TrustLevel.UNTRUSTED
            raw_labels = {
                item.strip().casefold()
                for item in metadata.get("labels", "").split(",")
                if item.strip()
            }
            invalid_labels = {item for item in raw_labels if not LABEL_PATTERN.fullmatch(item)}
            if invalid_labels:
                # Connector metadata becomes signed provenance, so malformed labels
                # must never pass through as an unvalidated token claim.
                classification = DataClassification.RESTRICTED
                trust = TrustLevel.UNTRUSTED
                labels = frozenset({"invalid_connector_metadata"})
            else:
                labels = frozenset(raw_labels)
            documents.append(
                KnowledgeDocument(
                    source=resolved.relative_to(self.root).as_posix(),
                    title=metadata.get("title", resolved.stem.replace("-", " ").title()),
                    content=content,
                    classification=classification,
                    trust=trust,
                    labels=labels,
                )
            )
        return documents

    @staticmethod
    def _parse_document(raw: str) -> tuple[dict[str, str], str]:
        if not raw.startswith("---\n"):
            return {}, raw
        end = raw.find("\n---\n", 4)
        if end == -1:
            return {}, raw
        metadata: dict[str, str] = {}
        for line in raw[4:end].splitlines():
            key, separator, value = line.partition(":")
            if separator:
                metadata[key.strip().casefold()] = value.strip()
        return metadata, raw[end + 5 :]

    @staticmethod
    def _snippet(content: str, terms: set[str], limit: int = 800) -> str:
        folded = content.casefold()
        positions = [folded.find(term) for term in terms if folded.find(term) >= 0]
        start = max(0, min(positions, default=0) - 120)
        snippet = " ".join(content[start : start + limit].split())
        return snippet + ("…" if start + limit < len(content) else "")
