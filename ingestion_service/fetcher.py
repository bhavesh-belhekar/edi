"""Incremental OpenSearch fetch logic."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional

from checkpoint import CheckpointStore
from config import IngestionSettings
from opensearch_client import OpenSearchClient


class IncrementalFetcher:
    """Fetch only synthetic telemetry events newer than the checkpoint."""

    def __init__(self, client: OpenSearchClient, settings: IngestionSettings) -> None:
        self.client = client
        self.settings = settings

    def _base_filter(self, last_timestamp: Optional[str]) -> Dict[str, Any]:
        filters: List[Dict[str, Any]] = [{"term": {"rule.groups": "synthetic_telemetry"}}]
        if last_timestamp:
            filters.append({"range": {"@timestamp": {"gt": last_timestamp}}})
        return {"bool": {"filter": filters}}

    def latest_matching_hit(self) -> Optional[Dict[str, Any]]:
        """Return the newest synthetic telemetry document, if any exist."""

        response = self.client.search(
            index=self.settings.opensearch_index_pattern,
            body={
                "size": 1,
                "sort": [
                    {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
                    {"_id": {"order": "desc"}},
                ],
                "query": self._base_filter(None),
            },
        )
        hits = response.get("hits", {}).get("hits", [])
        return hits[0] if hits else None

    def iter_batches(self, checkpoint: CheckpointStore) -> Iterator[List[Dict[str, Any]]]:
        """Yield paginated batches of matching OpenSearch hits."""

        base_timestamp = checkpoint.state.last_timestamp
        search_after: Optional[List[Any]] = None

        while True:
            body: Dict[str, Any] = {
                "size": self.settings.batch_size,
                "sort": [
                    {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                    {"_id": {"order": "asc"}},
                ],
                "query": self._base_filter(base_timestamp),
            }
            if search_after:
                body["search_after"] = search_after

            response = self.client.search(index=self.settings.opensearch_index_pattern, body=body)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break

            yield hits
            if len(hits) < self.settings.batch_size:
                break

            search_after = hits[-1].get("sort")
