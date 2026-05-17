"""OpenSearch client wrapper for the ingestion service."""

from __future__ import annotations

from typing import Any

from config import IngestionSettings

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection
except Exception as import_error:  # pragma: no cover - handled at runtime
    OpenSearch = None  # type: ignore[assignment]
    RequestsHttpConnection = None  # type: ignore[assignment]
    _IMPORT_ERROR = import_error
else:
    _IMPORT_ERROR = None


class OpenSearchClient:
    """Thin wrapper that centralizes OpenSearch connection handling."""

    def __init__(self, settings: IngestionSettings) -> None:
        self.settings = settings
        self.client = self._build_client()

    def _build_client(self) -> Any:
        if OpenSearch is None or RequestsHttpConnection is None:
            raise RuntimeError("opensearch-py is not installed") from _IMPORT_ERROR

        return OpenSearch(
            hosts=[{"host": self.settings.opensearch_host, "port": self.settings.opensearch_port}],
            http_auth=(self.settings.opensearch_username, self.settings.opensearch_password),
            connection_class=RequestsHttpConnection,
            use_ssl=False,
            verify_certs=False,
            http_compress=True,
            timeout=self.settings.request_timeout_seconds,
            max_retries=3,
            retry_on_timeout=True,
        )

    def ping(self) -> bool:
        """Check whether the OpenSearch cluster responds."""

        return bool(self.client.ping())

    def search(self, **kwargs: Any) -> dict[str, Any]:
        """Execute a search query against OpenSearch."""

        return self.client.search(**kwargs)
