"""Checkpoint persistence for restart-safe incremental ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Sequence

from models import IngestionCheckpoint


class CheckpointStore:
    """Load, update, and persist ingestion checkpoints."""

    def __init__(self, path: Path, max_processed_ids: int = 5000) -> None:
        self.path = Path(path)
        self.max_processed_ids = max_processed_ids
        self.state = self.load()

    def load(self) -> IngestionCheckpoint:
        """Load checkpoint from disk or create a fresh state."""

        if not self.path.exists():
            return IngestionCheckpoint()

        try:
            with self.path.open("r", encoding="utf-8") as checkpoint_file:
                raw_state = json.load(checkpoint_file)
            return IngestionCheckpoint.model_validate(raw_state)
        except Exception:
            return IngestionCheckpoint()

    def save(self) -> None:
        """Persist the current checkpoint state to disk."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as checkpoint_file:
            json.dump(self.state.model_dump(mode="json", exclude_none=False), checkpoint_file, indent=2)

    def mark_seen(self, event_id: str) -> None:
        """Record an event identifier so restarts can avoid duplicates."""

        if event_id in self.state.processed_ids:
            return

        self.state.processed_ids.append(event_id)
        if len(self.state.processed_ids) > self.max_processed_ids:
            self.state.processed_ids = self.state.processed_ids[-self.max_processed_ids:]

    def has_seen(self, event_id: str) -> bool:
        """Return True when the event identifier has already been ingested."""

        return event_id in self.state.processed_ids

    def advance(self, timestamp: str, sort_values: Optional[Sequence[object]], event_id: str) -> None:
        """Move the checkpoint forward after a successful write."""

        self.state.last_timestamp = timestamp
        self.state.last_sort = list(sort_values) if sort_values is not None else None
        self.mark_seen(event_id)

    def is_duplicate(self, event_id: str) -> bool:
        """Return True if the event has already been written."""

        return self.has_seen(event_id)
