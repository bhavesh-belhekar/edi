"""NDJSON writer for normalized events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from models import NormalizedEvent


class NDJSONWriter:
    """Append-only writer for normalized security events."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, events: Iterable[NormalizedEvent]) -> int:
        """Append normalized events to the output file and return the count."""

        count = 0
        with self.output_path.open("a", encoding="utf-8") as output_file:
            for event in events:
                payload = event.model_dump(mode="json", exclude_none=False)
                output_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
                count += 1
        return count
