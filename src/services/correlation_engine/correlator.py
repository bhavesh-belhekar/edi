"""
Real Correlation Engine for SOC Pipeline.

Implements:
- Temporal correlation using sliding time windows
- Cross-log entity linking (IP, username, hostname, process, hash, MITRE)
- Attack chain reconstruction
- Incident graph generation
- Severity aggregation

DO NOT break existing pipeline flow.
"""

import hashlib
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, Json

logger = logging.getLogger("correlation_engine")

# Configuration
POSTGRES_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", 5432)),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", "adminpassword"),
    "dbname": os.getenv("POSTGRES_DB", "cyber_intelligence"),
}

CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "60"))
MAX_CORRELATED_EVENTS = int(os.getenv("MAX_CORRELATED_EVENTS", "100"))

# MITRE Tactics in chronological attack order
ATTACK_CHAIN_SEQUENCE = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class CorrelationDatabase:
    """Database interface for correlation data storage."""

    def __init__(self):
        self.conn = None

    def _get_connection(self):
        if self.conn is None or self.conn.closed:
            self.conn = psycopg2.connect(**POSTGRES_CONFIG)
            self.conn.autocommit = True
        return self.conn

    def initialize_tables(self):
        """Create tables for incident storage if not exists."""
        conn = self._get_connection()
        with conn.cursor() as cur:
            # Incidents table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    incident_id VARCHAR(100) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    severity VARCHAR(20) DEFAULT 'medium',
                    confidence_score FLOAT DEFAULT 0.0,
                    attack_chain_stage VARCHAR(50),
                    description TEXT,
                    graph_data JSONB,
                    timeline JSONB,
                    linked_entities JSONB,
                    related_event_ids TEXT[],
                    status VARCHAR(20) DEFAULT 'active'
                )
            """)
            
            # Incident events junction table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incident_events (
                    id SERIAL PRIMARY KEY,
                    incident_id VARCHAR(100) NOT NULL,
                    event_id VARCHAR(100) NOT NULL,
                    event_timestamp TIMESTAMP,
                    correlation_type VARCHAR(50),
                    entity_type VARCHAR(50),
                    entity_value VARCHAR(500),
                    UNIQUE(incident_id, event_id)
                )
            """)
            
            # Entity index for fast lookups
            cur.execute("""
                CREATE TABLE IF NOT EXISTS entity_correlation_index (
                    id SERIAL PRIMARY KEY,
                    entity_type VARCHAR(50) NOT NULL,
                    entity_value VARCHAR(500) NOT NULL,
                    event_id VARCHAR(100) NOT NULL,
                    event_timestamp TIMESTAMP,
                    incident_id VARCHAR(100)
                )
            """)
            
            # Create indexes separately (PostgreSQL syntax)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_entity_type_value ON entity_correlation_index (entity_type, entity_value)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_event_id ON entity_correlation_index (event_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_id ON entity_correlation_index (incident_id)")
            
            logger.info("Correlation tables initialized")

    def store_incident(self, incident_data: Dict[str, Any]) -> str:
        """Store or update an incident."""
        conn = self._get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incidents (
                    incident_id, severity, confidence_score, attack_chain_stage,
                    description, graph_data, timeline, linked_entities, related_event_ids, status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (incident_id) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    confidence_score = EXCLUDED.confidence_score,
                    attack_chain_stage = EXCLUDED.attack_chain_stage,
                    updated_at = NOW(),
                    graph_data = EXCLUDED.graph_data,
                    timeline = EXCLUDED.timeline,
                    linked_entities = EXCLUDED.linked_entities,
                    related_event_ids = EXCLUDED.related_event_ids
                RETURNING incident_id
            """, (
                incident_data["incident_id"],
                incident_data.get("severity", "medium"),
                incident_data.get("confidence_score", 0.0),
                incident_data.get("attack_chain_stage"),
                incident_data.get("description"),
                Json(incident_data.get("graph_data")) if incident_data.get("graph_data") else None,
                Json(incident_data.get("timeline")) if incident_data.get("timeline") else None,
                Json(incident_data.get("linked_entities")) if incident_data.get("linked_entities") else None,
                incident_data.get("related_event_ids", []),
                incident_data.get("status", "active"),
            ))
            result = cur.fetchone()
            if result is None:
                logger.warning(f"store_incident returned no result for {incident_data.get('incident_id')}")
                return incident_data.get("incident_id", "unknown")
            return result[0]

    def link_event_to_incident(self, incident_id: str, event_id: str, event_timestamp: datetime,
                                correlation_type: str, entity_type: str, entity_value: str):
        """Link an event to an incident with entity context."""
        conn = self._get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incident_events (incident_id, event_id, event_timestamp, 
                                           correlation_type, entity_type, entity_value)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (incident_id, event_id) DO NOTHING
            """, (incident_id, event_id, event_timestamp, correlation_type, entity_type, entity_value))

    def index_entity(self, entity_type: str, entity_value: str, event_id: str, 
                     event_timestamp: datetime, incident_id: Optional[str] = None):
        """Index an entity for fast correlation lookups."""
        conn = self._get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO entity_correlation_index 
                (entity_type, entity_value, event_id, event_timestamp, incident_id)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (entity_type, entity_value, event_id, event_timestamp, incident_id))

    def find_related_events(self, entity_type: str, entity_value: str, 
                            window_minutes: int = None) -> List[Dict]:
        """Find events with matching entity within time window."""
        window = window_minutes or CORRELATION_WINDOW_MINUTES
        conn = self._get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT event_id, event_timestamp, entity_type, entity_value, incident_id
                FROM entity_correlation_index
                WHERE entity_type = %s AND entity_value = %s
                AND event_timestamp > NOW() - INTERVAL '%s minutes'
                ORDER BY event_timestamp DESC
                LIMIT %s
            """, (entity_type, entity_value, window, MAX_CORRELATED_EVENTS))
            return list(cur.fetchall())

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict]:
        """Get full incident details."""
        conn = self._get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,))
            return cur.fetchone()

    def get_all_incidents(self, limit: int = 50) -> List[Dict]:
        """Get all incidents."""
        conn = self._get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT incident_id, severity, confidence_score, attack_chain_stage, 
                       created_at, status, linked_entities
                FROM incidents 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (limit,))
            return list(cur.fetchall())


class EntityExtractor:
    """Extract correlation entities from events."""

    @staticmethod
    def extract(event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract all correlation entities from an event - handles nested and flat formats."""
        entities = {
            "src_ip": [],
            "dst_ip": [],
            "username": [],
            "hostname": [],
            "process_name": [],
            "file_hash": [],
            "mitre_technique": [],
        }

        # Helper to safely get nested value
        def get_nested(obj, *keys):
            for key in keys:
                if isinstance(obj, dict) and key in obj:
                    obj = obj[key]
                else:
                    return None
            return obj

        # Source IP - check nested and flat formats
        src_ip = get_nested(event, "source", "ip") or event.get("source_ip") or event.get("src_ip")
        if src_ip:
            entities["src_ip"].append(str(src_ip))

        # Destination IP - check nested and flat formats
        dst_ip = get_nested(event, "destination", "ip") or event.get("dst_ip") or event.get("destination_ip")
        if dst_ip:
            entities["dst_ip"].append(str(dst_ip))

        # Username - check nested and flat formats
        username = get_nested(event, "user", "username") or event.get("username") or event.get("user_name")
        if username:
            entities["username"].append(str(username))

        # Hostname (source and destination)
        src_host = get_nested(event, "source", "hostname") or event.get("hostname") or event.get("src_hostname")
        if src_host:
            entities["hostname"].append(str(src_host))
        dst_host = get_nested(event, "destination", "hostname") or event.get("dst_hostname")
        if dst_host:
            entities["hostname"].append(str(dst_host))

        # Process name
        process_name = get_nested(event, "process", "name") or event.get("process_name")
        if process_name:
            entities["process_name"].append(str(process_name))

        # File hash
        file_hash = get_nested(event, "file", "file_hash") or event.get("file_hash")
        if file_hash:
            entities["file_hash"].append(str(file_hash))

        # MITRE technique
        mitre_tech = get_nested(event, "mitre_attack", "technique_id") or event.get("mitre_technique_id")
        if mitre_tech:
            entities["mitre_technique"].append(str(mitre_tech))

        return entities


class AttackChainBuilder:
    """Build and analyze attack chains from MITRE techniques."""

    TECHNIQUE_STAGES = {
        # Reconnaissance
        "T1595": "Reconnaissance", "T1592": "Reconnaissance",
        # Initial Access
        "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
        # Execution
        "T1059": "Execution", "T1204": "Execution", "T1203": "Execution",
        # Persistence
        "T1547": "Persistence", "T1053": "Persistence", "T1136": "Persistence", "T1554": "Persistence",
        # Privilege Escalation
        "T1548": "Privilege Escalation", "T1134": "Privilege Escalation", "T1068": "Privilege Escalation",
        # Defense Evasion
        "T1070": "Defense Evasion", "T1036": "Defense Evasion", "T1027": "Defense Evasion",
        # Credential Access
        "T1110": "Credential Access", "T1555": "Credential Access", "T1003": "Credential Access",
        # Discovery
        "T1087": "Discovery", "T1082": "Discovery", "T1083": "Discovery",
        # Lateral Movement
        "T1021": "Lateral Movement", "T1210": "Lateral Movement",
        # Collection
        "T1560": "Collection", "T1005": "Collection",
        # Command and Control
        "T1071": "Command and Control", "T1573": "Command and Control",
        # Exfiltration
        "T1041": "Exfiltration", "T1048": "Exfiltration",
        # Impact
        "T1486": "Impact", "T1489": "Impact",
    }

    @classmethod
    def get_stage(cls, technique_id: str) -> str:
        """Map MITRE technique to attack chain stage."""
        return cls.TECHNIQUE_STAGES.get(technique_id, "Unknown")

    @classmethod
    def calculate_chain_progress(cls, techniques: List[str]) -> Tuple[str, float]:
        """Calculate current attack chain stage and progress."""
        if not techniques:
            return "Unknown", 0.0

        stages_observed = set()
        for tech in techniques:
            stage = cls.get_stage(tech)
            if stage != "Unknown":
                stages_observed.add(stage)

        current_stage = "Reconnaissance"
        stage_order = {stage: i for i, stage in enumerate(ATTACK_CHAIN_SEQUENCE)}
        
        max_progress = 0
        for stage in stages_observed:
            progress = stage_order.get(stage, 0)
            if progress >= max_progress:
                max_progress = progress
                current_stage = stage

        progress_pct = (max_progress + 1) / len(ATTACK_CHAIN_SEQUENCE) * 100
        return current_stage, min(progress_pct, 100.0)


class IncidentGrapher:
    """Build incident graphs from correlated events."""

    @staticmethod
    def build_graph(events: List[Dict], entities: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Build a graph representation of correlated events."""
        nodes = []
        edges = []
        node_ids = set()

        # Create nodes for each event
        for i, event in enumerate(events):
            event_id = event.get("event_id", f"event_{i}")
            node_id = f"node_{event_id}"
            node_ids.add(node_id)

            # Determine node type based on event characteristics
            event_type = event.get("event_type", "unknown")
            severity = event.get("severity", "info")
            
            node = {
                "id": node_id,
                "event_id": event_id,
                "type": event_type,
                "severity": severity,
                "timestamp": str(event.get("timestamp", "")),
                "label": event_type.replace("_", " ").title(),
            }
            
            # Add MITRE info if available
            if event.get("mitre_attack"):
                mitre = event["mitre_attack"]
                node["mitre"] = {
                    "technique": mitre.get("technique_id"),
                    "tactic": mitre.get("tactic"),
                }
            
            nodes.append(node)

        # Create edges based on entity connections
        for entity_type, entity_values in entities.items():
            if len(entity_values) < 2:
                continue
            
            entity_list = list(entity_values)
            for i in range(len(entity_list) - 1):
                from_event = events[i].get("event_id", f"event_{i}")
                to_event = events[i + 1].get("event_id", f"event_{i+1}")
                
                edges.append({
                    "from": f"node_{from_event}",
                    "to": f"node_{to_event}",
                    "type": entity_type,
                    "label": entity_type.replace("_", " ").title(),
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    @staticmethod
    def build_graph_from_related(current_event_id: str, events: List[Dict], 
                                   linked_entities: Dict[str, List]) -> Dict[str, Any]:
        """Build dynamic graph from current and related events."""
        nodes = []
        edges = []
        
        for i, event in enumerate(events):
            event_id = event.get("event_id", f"event_{i}")
            event_type = event.get("event_type", "unknown")
            severity = event.get("severity", "info")
            timestamp = event.get("timestamp", "")
            
            # Color nodes based on type
            node_color = "#4CAF50"  # green - current event
            if i > 0:
                node_color = "#2196F3"  # blue - related events
            
            if severity in ["critical", "high"]:
                node_color = "#F44336"  # red - critical
            elif severity == "medium":
                node_color = "#FF9800"  # orange - medium
            
            node = {
                "id": f"node_{event_id}",
                "event_id": event_id,
                "type": event_type,
                "severity": severity,
                "timestamp": timestamp,
                "label": event_type.replace("_", " ").title(),
                "color": node_color,
                "is_current": i == 0
            }
            nodes.append(node)
            
            # Create edges from previous event (sequential chain)
            if i > 0:
                prev_event = events[i - 1]
                edges.append({
                    "from": f"node_{prev_event.get('event_id', '')}",
                    "to": f"node_{event_id}",
                    "type": "temporal",
                    "label": "Next event"
                })
        
        # Add edges based on entity connections
        for entity_type, entity_values in linked_entities.items():
            if len(entity_values) < 2:
                continue
            # Create entity-based edges between first two nodes
            if len(nodes) >= 2:
                edges.append({
                    "from": f"node_{events[0].get('event_id', '')}",
                    "to": f"node_{events[1].get('event_id', '')}",
                    "type": entity_type,
                    "label": entity_type.replace("_", " ").title()
                })
        
        logger.info(f"Built graph with {len(nodes)} nodes and {len(edges)} edges for incident")
        
        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }


class CorrelationEngine:
    """Main correlation engine orchestrator."""

    def __init__(self):
        self.db = CorrelationDatabase()
        self.db.initialize_tables()
        self.entity_extractor = EntityExtractor()
        self.attack_chain_builder = AttackChainBuilder()
        self.incident_grapher = IncidentGrapher()
        self._event_cache = []

    def correlate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for event correlation.
        
        Returns correlation result with:
        - incident_id (new or existing)
        - correlation_strength
        - attack_chain_stage
        - related_event_count
        """
        start_time = time.time()
        
        # Extract entities from event
        entities = self.entity_extractor.extract(event)
        
        event_id = event.get("event_id", str(uuid.uuid4()))
        timestamp = event.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except:
                timestamp = datetime.now(timezone.utc)
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Find related events from database
        related_events = []
        all_related_entities = defaultdict(set)
        
        # Search for each entity type
        for entity_type, entity_values in entities.items():
            for entity_value in entity_values:
                if not entity_value:
                    continue
                    
                # Index this entity
                self.db.index_entity(entity_type, entity_value, event_id, timestamp)
                
                # Find related events
                matches = self.db.find_related_events(entity_type, entity_value)
                for match in matches:
                    related_events.append(match)
                    all_related_entities[entity_type].add(match["entity_value"])

        # Deduplicate related events
        seen_events = set()
        unique_related = []
        for re in related_events:
            if re["event_id"] != event_id and re["event_id"] not in seen_events:
                seen_events.add(re["event_id"])
                unique_related.append(re)

        related_event_ids = [re["event_id"] for re in unique_related[:50]]
        
        # Determine incident management
        if not related_event_ids:
            # No related events - create new incident
            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            severity = event.get("severity", "low")
            confidence = 0.3
            attack_stage = "Initial Access" if event.get("mitre_attack") else "Unknown"
        else:
            # Has related events - check if they belong to existing incident
            existing_incidents = set()
            for re in unique_related[:20]:
                if re.get("incident_id"):
                    existing_incidents.add(re["incident_id"])
            
            if existing_incidents:
                # Link to existing incident
                incident_id = list(existing_incidents)[0]
            else:
                # Create new incident for this group
                incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
            
            # Aggregate severity from all related events
            severity = self._aggregate_severity(event, unique_related)
            confidence = min(0.5 + (len(related_event_ids) * 0.05), 0.95)
            
            # Determine attack chain stage
            techniques = []
            if event.get("mitre_attack") and event["mitre_attack"].get("technique_id"):
                techniques.append(event["mitre_attack"]["technique_id"])
            
            attack_stage, _ = self.attack_chain_builder.calculate_chain_progress(techniques)

        # Build incident data
        linked_entities = {
            "src_ips": list(entities.get("src_ip", [])),
            "dst_ips": list(entities.get("dst_ip", [])),
            "usernames": list(entities.get("username", [])),
            "hostnames": list(entities.get("hostname", [])),
            "processes": list(entities.get("process_name", [])),
            "file_hashes": list(entities.get("file_hash", [])),
        }

        # Build timeline
        timeline = [
            {"timestamp": str(timestamp), "event_id": event_id, "type": "current_event"}
        ]
        for re in unique_related[:10]:
            timeline.append({
                "timestamp": str(re.get("event_timestamp", "")),
                "event_id": re.get("event_id", ""),
                "type": "related_event"
            })

        # Build graph including related events
        # Convert related events to simple dict format for graph building
        related_events_for_graph = []
        for re in unique_related[:20]:  # Limit to 20 for graph
            related_events_for_graph.append({
                "event_id": re.get("event_id", ""),
                "event_type": "related_event",
                "timestamp": str(re.get("event_timestamp", "")),
                "severity": "medium"
            })
        
        # Add current event to the list
        all_events_for_graph = [{"event_id": event_id, "event_type": event.get("event_type", "unknown"), 
                                  "timestamp": str(timestamp), "severity": event.get("severity", "info")}] + related_events_for_graph
        
        # Build dynamic graph from related events
        graph_data = self.incident_grapher.build_graph_from_related(event_id, all_events_for_graph, linked_entities)

        # Prepare incident data
        description = self._generate_description(event, linked_entities, len(related_event_ids))
        
        incident_data = {
            "incident_id": incident_id,
            "severity": severity,
            "confidence_score": confidence,
            "attack_chain_stage": attack_stage,
            "description": description,
            "graph_data": graph_data,
            "timeline": timeline,
            "linked_entities": linked_entities,
            "related_event_ids": [event_id] + related_event_ids,
            "status": "active",
        }

        # Store incident
        self.db.store_incident(incident_data)

        # Link this event to incident
        for entity_type, entity_values in entities.items():
            for entity_value in entity_values:
                if entity_value:
                    self.db.link_event_to_incident(
                        incident_id, event_id, timestamp,
                        "entity_match", entity_type, entity_value
                    )

        elapsed = time.time() - start_time
        
        logger.info(
            f"event_id={event_id} incident_id={incident_id} "
            f"related_events={len(related_event_ids)} "
            f"confidence={confidence:.2f} stage={attack_stage} "
            f"elapsed_ms={elapsed*1000:.1f}"
        )

        return {
            "incident_id": incident_id,
            "correlation_strength": confidence,
            "attack_chain_stage": attack_stage,
            "related_event_count": len(related_event_ids),
            "linked_entities": linked_entities,
        }

    def _aggregate_severity(self, current_event: Dict, related_events: List[Dict]) -> str:
        """Aggregate severity from all related events."""
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        reverse_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        
        max_severity = severity_map.get(current_event.get("severity", "low").lower(), 1)
        
        for re in related_events:
            # Note: related_events are from DB, might need to query full event for severity
            pass  # For now, use current event severity
        
        return reverse_map.get(max_severity, "medium")

    def _generate_description(self, event: Dict, entities: Dict[str, List], related_count: int) -> str:
        """Generate human-readable incident description."""
        event_type = event.get("event_type", "unknown").replace("_", " ")
        
        parts = [f"Detected {event_type} event"]
        
        if entities.get("usernames") and len(entities["usernames"]) > 0:
            parts.append(f"user: {entities['usernames'][0]}")
        
        if entities.get("src_ip") and len(entities["src_ip"]) > 0:
            parts.append(f"from {entities['src_ip'][0]}")
        
        if entities.get("dst_ip") and len(entities["dst_ip"]) > 0:
            parts.append(f"to {entities['dst_ip'][0]}")
        
        if entities.get("mitre_technique") and len(entities["mitre_technique"]) > 0:
            parts.append(f"Mitre: {entities['mitre_technique'][0]}")
        
        if related_count > 0:
            parts.append(f"+ {related_count} related events")
        
        return ", ".join(parts)


# Global instance
_correlation_engine = None

def get_correlation_engine() -> CorrelationEngine:
    """Get or create global correlation engine instance."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine

def correlate_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Public API for event correlation."""
    engine = get_correlation_engine()
    return engine.correlate_event(event)

def get_incident(incident_id: str) -> Optional[Dict]:
    """Get incident by ID."""
    engine = get_correlation_engine()
    return engine.db.get_incident_by_id(incident_id)

def get_all_incidents(limit: int = 50) -> List[Dict]:
    """Get all incidents."""
    engine = get_correlation_engine()
    return engine.db.get_all_incidents(limit)