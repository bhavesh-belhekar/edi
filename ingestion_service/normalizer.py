"""Normalize OpenSearch Wazuh alerts into the unified ingestion schema."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from dateutil import parser as date_parser
from pydantic import BaseModel

from models import (
    NormalizedEvent,
    NullableBehavioralFeatures,
    NullableCorrelationInfo,
    NullableDNSInfo,
    NullableDetectionInfo,
    NullableDestinationInfo,
    NullableFileInfo,
    NullableFirewallInfo,
    NullableHTTPInfo,
    NullableMitreAttackInfo,
    NullablePlaybookInfo,
    NullableProcessInfo,
    NullableProxyInfo,
    NullableSourceInfo,
    NullableSystemInfo,
    NullableUserInfo,
)


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "":
            continue
        if isinstance(value, (list, dict, tuple, set)) and len(value) == 0:
            continue
        return value
    return None


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return str(value)


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class EventNormalizer:
    """Transform Wazuh/OpenSearch documents into normalized event records."""

    _AUTH_RE = re.compile(r"failed password|accepted publickey|sshd|session closed|failed login", re.IGNORECASE)
    _DNS_RE = re.compile(r"dns_|named\[|query:", re.IGNORECASE)
    _PROXY_RE = re.compile(r"proxy|https?://|category=", re.IGNORECASE)
    _FIREWALL_RE = re.compile(r"\bFW\b|action=allow|action=deny|firewall", re.IGNORECASE)
    _ENDPOINT_RE = re.compile(r"sysmon|eventid 4688|process_start|process_stop|file_audit|powershell", re.IGNORECASE)

    def extract_event_id(self, hit: Mapping[str, Any]) -> str:
        source_doc = hit.get("_source", {}) if isinstance(hit.get("_source", {}), Mapping) else {}
        return _as_str(_first_non_empty(source_doc.get("event_id"), hit.get("_id"))) or "unknown-event"

    def infer_event_type(self, source_doc: Mapping[str, Any], raw_log: Optional[str]) -> str:
        explicit = _as_str(_first_non_empty(source_doc.get("event_type"), source_doc.get("event_type_name")))
        if explicit:
            return explicit

        rule_block = source_doc.get("rule") if isinstance(source_doc.get("rule"), Mapping) else {}
        rule_description = _as_str(rule_block.get("description") if isinstance(rule_block, Mapping) else None)
        if rule_description:
            return rule_description

        haystack = f"{raw_log or ''} {json.dumps(source_doc, default=str)}"
        if self._AUTH_RE.search(haystack):
            lower_haystack = haystack.lower()
            if "failed password" in lower_haystack or "failed login" in lower_haystack:
                return "failed_login"
            if "accepted publickey" in lower_haystack:
                return "successful_login"
            if "session closed" in lower_haystack:
                return "logout"
            return "auth_event"
        if self._DNS_RE.search(haystack):
            return "dns_query"
        if self._PROXY_RE.search(haystack):
            return "proxy_request"
        if self._FIREWALL_RE.search(haystack):
            if "deny" in haystack.lower():
                return "firewall_deny"
            return "firewall_allow"
        if self._ENDPOINT_RE.search(haystack):
            return "endpoint_event"
        return "unknown_event"

    def _build_source(self, source_doc: Mapping[str, Any]) -> Optional[NullableSourceInfo]:
        source_block = source_doc.get("source") if isinstance(source_doc.get("source"), Mapping) else {}
        agent_block = source_doc.get("agent") if isinstance(source_doc.get("agent"), Mapping) else {}
        value = NullableSourceInfo(
            ip=_as_str(
                _first_non_empty(
                    source_block.get("ip") if isinstance(source_block, Mapping) else None,
                    source_doc.get("srcip"),
                    source_doc.get("src_ip"),
                    agent_block.get("ip") if isinstance(agent_block, Mapping) else None,
                )
            ),
            port=_as_int(
                _first_non_empty(
                    source_block.get("port") if isinstance(source_block, Mapping) else None,
                    source_doc.get("srcport"),
                )
            ),
            hostname=_as_str(
                _first_non_empty(
                    source_block.get("hostname") if isinstance(source_block, Mapping) else None,
                    source_doc.get("src_host"),
                    source_doc.get("hostname"),
                    agent_block.get("name") if isinstance(agent_block, Mapping) else None,
                )
            ),
            geo=_as_str(source_block.get("geo") if isinstance(source_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_destination(self, source_doc: Mapping[str, Any]) -> Optional[NullableDestinationInfo]:
        destination_block = source_doc.get("destination") if isinstance(source_doc.get("destination"), Mapping) else {}
        value = NullableDestinationInfo(
            ip=_as_str(
                _first_non_empty(
                    destination_block.get("ip") if isinstance(destination_block, Mapping) else None,
                    source_doc.get("dstip"),
                    source_doc.get("dst_ip"),
                )
            ),
            port=_as_int(
                _first_non_empty(
                    destination_block.get("port") if isinstance(destination_block, Mapping) else None,
                    source_doc.get("dstport"),
                )
            ),
            hostname=_as_str(destination_block.get("hostname") if isinstance(destination_block, Mapping) else None),
            geo=_as_str(destination_block.get("geo") if isinstance(destination_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_user(self, source_doc: Mapping[str, Any]) -> Optional[NullableUserInfo]:
        user_block = source_doc.get("user") if isinstance(source_doc.get("user"), Mapping) else {}
        value = NullableUserInfo(
            username=_as_str(
                _first_non_empty(
                    user_block.get("username") if isinstance(user_block, Mapping) else None,
                    source_doc.get("username"),
                    source_doc.get("srcuser"),
                )
            ),
            role=_as_str(user_block.get("role") if isinstance(user_block, Mapping) else None),
            department=_as_str(user_block.get("department") if isinstance(user_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_process(self, source_doc: Mapping[str, Any]) -> Optional[NullableProcessInfo]:
        process_block = source_doc.get("process") if isinstance(source_doc.get("process"), Mapping) else {}
        value = NullableProcessInfo(
            name=_as_str(
                _first_non_empty(
                    process_block.get("name") if isinstance(process_block, Mapping) else None,
                    source_doc.get("process_name"),
                )
            ),
            pid=_as_int(process_block.get("pid") if isinstance(process_block, Mapping) else None),
            parent_process_name=_as_str(
                process_block.get("parent_process_name") if isinstance(process_block, Mapping) else None
            ),
            command_line=_as_str(process_block.get("command_line") if isinstance(process_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_file(self, source_doc: Mapping[str, Any]) -> Optional[NullableFileInfo]:
        file_block = source_doc.get("file") if isinstance(source_doc.get("file"), Mapping) else {}
        value = NullableFileInfo(
            file_path=_as_str(file_block.get("file_path") if isinstance(file_block, Mapping) else None),
            file_name=_as_str(file_block.get("file_name") if isinstance(file_block, Mapping) else None),
            file_hash=_as_str(file_block.get("file_hash") if isinstance(file_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_http(self, source_doc: Mapping[str, Any]) -> Optional[NullableHTTPInfo]:
        http_block = source_doc.get("http") if isinstance(source_doc.get("http"), Mapping) else {}
        value = NullableHTTPInfo(
            method=_as_str(http_block.get("method") if isinstance(http_block, Mapping) else None),
            endpoint=_as_str(http_block.get("endpoint") if isinstance(http_block, Mapping) else None),
            status_code=_as_int(http_block.get("status_code") if isinstance(http_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_system(self, source_doc: Mapping[str, Any]) -> Optional[NullableSystemInfo]:
        system_block = source_doc.get("system") if isinstance(source_doc.get("system"), Mapping) else {}
        agent_block = source_doc.get("agent") if isinstance(source_doc.get("agent"), Mapping) else {}
        value = NullableSystemInfo(
            os=_as_str(
                _first_non_empty(
                    system_block.get("os") if isinstance(system_block, Mapping) else None,
                    source_doc.get("os"),
                )
            ),
            container_id=_as_str(
                _first_non_empty(
                    system_block.get("container_id") if isinstance(system_block, Mapping) else None,
                    agent_block.get("id") if isinstance(agent_block, Mapping) else None,
                )
            ),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_dns(self, source_doc: Mapping[str, Any]) -> Optional[NullableDNSInfo]:
        dns_block = source_doc.get("dns") if isinstance(source_doc.get("dns"), Mapping) else {}
        value = NullableDNSInfo(
            queried_domain=_as_str(dns_block.get("queried_domain") if isinstance(dns_block, Mapping) else None),
            query_type=_as_str(dns_block.get("query_type") if isinstance(dns_block, Mapping) else None),
            resolved_ip=_as_str(dns_block.get("resolved_ip") if isinstance(dns_block, Mapping) else None),
            response_code=_as_str(dns_block.get("response_code") if isinstance(dns_block, Mapping) else None),
            ttl=_as_int(dns_block.get("ttl") if isinstance(dns_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_firewall(self, source_doc: Mapping[str, Any]) -> Optional[NullableFirewallInfo]:
        firewall_block = source_doc.get("firewall") if isinstance(source_doc.get("firewall"), Mapping) else {}
        value = NullableFirewallInfo(
            action=_as_str(firewall_block.get("action") if isinstance(firewall_block, Mapping) else None),
            protocol=_as_str(firewall_block.get("protocol") if isinstance(firewall_block, Mapping) else None),
            bytes_sent=_as_int(firewall_block.get("bytes_sent") if isinstance(firewall_block, Mapping) else None),
            bytes_received=_as_int(
                firewall_block.get("bytes_received") if isinstance(firewall_block, Mapping) else None
            ),
            session_duration_ms=_as_int(
                firewall_block.get("session_duration_ms") if isinstance(firewall_block, Mapping) else None
            ),
            rule_id=_as_str(firewall_block.get("rule_id") if isinstance(firewall_block, Mapping) else None),
            direction=_as_str(firewall_block.get("direction") if isinstance(firewall_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_proxy(self, source_doc: Mapping[str, Any]) -> Optional[NullableProxyInfo]:
        proxy_block = source_doc.get("proxy") if isinstance(source_doc.get("proxy"), Mapping) else {}
        value = NullableProxyInfo(
            url=_as_str(proxy_block.get("url") if isinstance(proxy_block, Mapping) else None),
            method=_as_str(proxy_block.get("method") if isinstance(proxy_block, Mapping) else None),
            status_code=_as_int(proxy_block.get("status_code") if isinstance(proxy_block, Mapping) else None),
            user_agent=_as_str(proxy_block.get("user_agent") if isinstance(proxy_block, Mapping) else None),
            domain=_as_str(proxy_block.get("domain") if isinstance(proxy_block, Mapping) else None),
            content_type=_as_str(proxy_block.get("content_type") if isinstance(proxy_block, Mapping) else None),
            bytes_transferred=_as_int(
                proxy_block.get("bytes_transferred") if isinstance(proxy_block, Mapping) else None
            ),
            referrer=_as_str(proxy_block.get("referrer") if isinstance(proxy_block, Mapping) else None),
            category=_as_str(proxy_block.get("category") if isinstance(proxy_block, Mapping) else None),
        )
        return value if any(field is not None for field in value.model_dump().values()) else None

    def _build_generic_block(
        self,
        model_cls: type[BaseModel],
        source_doc: Mapping[str, Any],
        key: str,
    ) -> Optional[BaseModel]:
        raw_block = source_doc.get(key)
        if not isinstance(raw_block, Mapping) or not raw_block:
            return None
        try:
            return model_cls.model_validate(raw_block)
        except Exception:
            return None

    def normalize(self, hit: Mapping[str, Any]) -> NormalizedEvent:
        """Normalize a single OpenSearch hit into a schema-compliant record."""

        source_doc = hit.get("_source", {}) if isinstance(hit.get("_source", {}), Mapping) else {}
        payload = source_doc.get("data") if isinstance(source_doc.get("data"), Mapping) else {}

        timestamp = date_parser.parse(
            str(
                _first_non_empty(
                    source_doc.get("@timestamp"),
                    source_doc.get("timestamp"),
                    payload.get("timestamp"),
                )
                or datetime.now(timezone.utc).isoformat()
            )
        )
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc)

        raw_log = _as_str(
            _first_non_empty(
                source_doc.get("raw_log"),
                source_doc.get("full_log"),
                source_doc.get("message"),
                payload.get("raw_log"),
                payload.get("message"),
            )
        )
        
        # Parse raw_log as JSON if possible - it contains the enriched source data
        raw_log_parsed = None
        if raw_log:
            try:
                raw_log_parsed = json.loads(raw_log)
            except (json.JSONDecodeError, TypeError):
                raw_log_parsed = None
        
        # Merge raw_log_parsed into source_doc for field extraction
        if isinstance(raw_log_parsed, Mapping):
            source_doc = {**raw_log_parsed, **source_doc}  # source_doc takes precedence
        
        event_type = self.infer_event_type(source_doc, raw_log)
        event_id = self.extract_event_id(hit)

        severity_value = _as_str(
            _first_non_empty(
                source_doc.get("severity"),
                source_doc.get("rule", {}).get("level")
                if isinstance(source_doc.get("rule"), Mapping)
                else None,
            )
        )

        normalized = NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity_value,
            source=self._build_source(source_doc),
            destination=self._build_destination(source_doc),
            user=self._build_user(source_doc),
            process=self._build_process(source_doc),
            file=self._build_file(source_doc),
            http=self._build_http(source_doc),
            system=self._build_system(source_doc),
            dns=self._build_dns(source_doc),
            firewall=self._build_firewall(source_doc),
            proxy=self._build_proxy(source_doc),
            behavioral_features=self._build_generic_block(
                NullableBehavioralFeatures,
                source_doc,
                "behavioral_features",
            ),
            detection=self._build_generic_block(NullableDetectionInfo, source_doc, "detection"),
            correlation=self._build_generic_block(NullableCorrelationInfo, source_doc, "correlation"),
            mitre_attack=self._build_generic_block(NullableMitreAttackInfo, source_doc, "mitre_attack"),
            playbook=self._build_generic_block(NullablePlaybookInfo, source_doc, "playbook"),
            raw_log=raw_log,
        )
        return NormalizedEvent.model_validate(normalized.model_dump(mode="json", exclude_none=False))
