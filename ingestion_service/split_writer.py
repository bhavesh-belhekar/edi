"""Split writers to output enriched events by type to separate NDJSON files."""

import json
import logging
from pathlib import Path
from typing import Dict, Optional

from models import NormalizedEvent

LOGGER = logging.getLogger("ingestion_service.writers")


class SplitEventWriter:
    """Write enriched events to separate files based on event type."""
    
    # Map event types to output files
    _TYPE_MAPPING = {
        "auth_success": "processed_auth.ndjson",
        "auth_failed": "processed_auth.ndjson",
        "failed_login": "processed_auth.ndjson",
        "successful_login": "processed_auth.ndjson",
        "session_started": "processed_auth.ndjson",
        "session_closed": "processed_auth.ndjson",
        
        "dns_query": "processed_dns.ndjson",
        "dns_response": "processed_dns.ndjson",
        
        "process_start": "processed_endpoint.ndjson",
        "process_stop": "processed_endpoint.ndjson",
        "process_created": "processed_endpoint.ndjson",
        "file_created": "processed_endpoint.ndjson",
        "file_deleted": "processed_endpoint.ndjson",
        
        "firewall_allow": "processed_firewall.ndjson",
        "firewall_deny": "processed_firewall.ndjson",
        "network_allow": "processed_firewall.ndjson",
        "network_deny": "processed_firewall.ndjson",
        
        "proxy_request": "processed_proxy.ndjson",
        "proxy_response": "processed_proxy.ndjson",
        "web_request": "processed_proxy.ndjson",
    }
    
    def __init__(self, output_dir: str):
        """Initialize split writer with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._file_handles: Dict[str, object] = {}
        LOGGER.info("split_writer initialized output_dir=%s", output_dir)
    
    def _get_output_file(self, event_type: str) -> str:
        """Get output filename for event type."""
        # Try exact match first
        if event_type in self._TYPE_MAPPING:
            return self._TYPE_MAPPING[event_type]
        
        # Try substring match
        event_type_lower = event_type.lower()
        for pattern, filename in self._TYPE_MAPPING.items():
            if pattern in event_type_lower or event_type_lower in pattern:
                return filename
        
        # Default to generic processed_events.ndjson
        return "processed_events.ndjson"
    
    def write(self, events: list[NormalizedEvent]) -> int:
        """Write events to split NDJSON files by type."""
        if not events:
            return 0
        
        # Group events by output file
        grouped: Dict[str, list[NormalizedEvent]] = {}
        for event in events:
            output_file = self._get_output_file(event.event_type)
            if output_file not in grouped:
                grouped[output_file] = []
            grouped[output_file].append(event)
        
        # Write each group to its file
        total_written = 0
        for filename, group in grouped.items():
            filepath = self.output_dir / filename
            try:
                with open(filepath, "a") as f:
                    for event in group:
                        event_json = json.dumps(event.model_dump(mode="json", exclude_none=True))
                        f.write(event_json + "\n")
                
                total_written += len(group)
                LOGGER.debug("written file=%s count=%d", filename, len(group))
            except Exception as e:
                LOGGER.error("error writing to file=%s error=%s", filename, e)
        
        return total_written
    
    def close(self) -> None:
        """Close all open file handles."""
        for f in self._file_handles.values():
            try:
                f.close()
            except:
                pass
        self._file_handles.clear()
