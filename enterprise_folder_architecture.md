====================================================
🔷 CYBER INCIDENT RESPONSE SYSTEM
🔷 ENTERPRISE FOLDER ARCHITECTURE & ENGINEERING DESIGN
====================================================

This document outlines the final, scalable, enterprise-grade folder structure for the fully offline AI-powered Cyber Incident Response Platform. It defines service boundaries, shared infrastructure, dockerization strategy, testing structure, and the development flow.

---

# 1️⃣ COMPLETE ROOT PROJECT STRUCTURE

```text
CyberIncidentResponse/
│
├── .github/                      # CI/CD workflows and issue templates
├── deployments/                  # Global deployment configurations
│   ├── docker-compose.yml        # Main orchestration for all services
│   ├── docker-compose.dev.yml    # Overrides for local development
│   └── .env.example              # Environment variables template
│
├── docs/                         # Project Documentation
│   ├── architecture/             # Architecture, data flow, contracts (this file belongs here)
│   ├── api/                      # OpenAPI/Swagger specs
│   └── playbooks/                # SOC playbook research and standards
│
├── src/                          # Root logic directory
│   │
│   ├── core/                     # CROSS-CUTTING CONCERNS (Shared Infrastructure)
│   │   ├── schemas/              # Pydantic models (UnifiedEvent is here)
│   │   ├── config/               # Global configuration management
│   │   ├── exceptions/           # Standardized error handling
│   │   ├── logging/              # Centralized structured logging setup
│   │   └── security/             # Generic security utilities
│   │
│   ├── infra/                    # CORE INFRASTRUCTURE CLIENTS
│   │   ├── opensearch/           # OS connection and query logic
│   │   ├── postgres/             # PG connection, ORM (SQLAlchemy) setup
│   │   ├── rabbitmq/             # RMQ publishers, consumers, connection logic
│   │   └── ollama/               # Ollama specific client logic
│   │
│   ├── services/                 # INDEPENDENT MICROSERVICES
│   │   │
│   │   ├── ingestion_engine/     # Fetches from OpenSearch, normalizes, passes to enrichment
│   │   │   ├── Dockerfile
│   │   │   ├── main.py           # Entrypoint service daemon
│   │   │   └── logic/
│   │   │
│   │   ├── enrichment_engine/    # Adds context (IP, User, Time)
│   │   │   ├── Dockerfile
│   │   │   ├── main.py
│   │   │   ├── ip_lookups.py
│   │   │   └── time_analytics.py
│   │   │
│   │   ├── signature_engine/     # Fast Path detection (routing to DB or RMQ)
│   │   │   ├── Dockerfile
│   │   │   ├── main.py
│   │   │   └── hashing.py
│   │   │
│   │   ├── ml_workers/           # The Slow Path (RabbitMQ Consumers)
│   │   │   ├── Dockerfile        # Single scalable worker image
│   │   │   ├── main.py           # Worker entrypoint
│   │   │   ├── preprocessing/    # Cleaning, encoding
│   │   │   ├── features/         # tsfresh extraction
│   │   │   ├── anomaly/          # PyOD inference
│   │   │   └── ueba/             # Baseline deviation checks
│   │   │
│   │   ├── correlation_engine/   # Graph construction and chain building
│   │   │   ├── Dockerfile
│   │   │   ├── main.py
│   │   │   └── graph.py          # NetworkX logic
│   │   │
│   │   ├── mitre_mapper/         # TTP assignment
│   │   │   ├── Dockerfile
│   │   │   └── main.py
│   │   │
│   │   ├── fidelity_engine/      # Final risk scoring
│   │   │   ├── Dockerfile
│   │   │   └── main.py
│   │   │
│   │   ├── playbook_engine/      # Deterministic remediation + LLM enhancement
│   │   │   ├── Dockerfile
│   │   │   ├── main.py
│   │   │   ├── templates/
│   │   │   └── enhancement.py    # Calls core/infra/ollama
│   │   │
│   │   └── api_gateway/          # FastAPI user-facing interface
│   │       ├── Dockerfile
│   │       ├── main.py
│   │       ├── routers/
│   │       ├── dependencies.py
│   │       └── responses/
│   │
│   └── scripts/                  # Ad-hoc / offline scripts
│       ├── db_migrations/        # Alembic or raw SQL updates
│       └── model_training/       # Scripts to build PyOD base models
│
├── tools/                        # EXTERNAL SYSTEM MOCKING & LOG GENERATION
│   ├── synthetic_generator/      # Generates unified fake logs
│   │   ├── attacker/
│   │   └── normal_user/
│   └── dummy_banking_app/        # Future Phase 2 applications
│
├── tests/                        # TESTING FRAMEWORK
│   ├── unit/                     # Isolated logic tests
│   ├── integration/              # Real DB/RMQ tests
│   ├── e2e/                      # Full pipeline data tests
│   └── fixtures/                 # Mock logs and events
│
├── requirements.txt              # Global requirements for local development
└── Makefile                      # Easy helper commands (make test, make up)
```

---

# 2️⃣ EXPLAIN EACH FOLDER

*   **`src/core/` (Ownership: Architect/DevOps)**
    *   **Purpose:** Houses all logic that multiple completely independent services need to share.
    *   **Belongs here:** Pydantic `UnifiedEvent` schema, global environment variable loading, custom log formatters (e.g., ensuring all microservices output JSON logs), custom error definitions.
    *   **Does NOT belong here:** Business logic, machine learning inference, database queries.
*   **`src/infra/` (Ownership: Platform Engineering)**
    *   **Purpose:** Standardizes how the system speaks to external components (Postgres, RabbitMQ, OpenSearch, Ollama).
    *   **Belongs here:** SQLAlchemy engine configuration, Pika/aio-pika connection pooling, retry and circuit-breaker logic for OpenSearch queries.
    *   **Does NOT belong here:** The actual logic of deciding *what* to query. This folder only cares about *how* to query.
*   **`src/services/` (Ownership: Domain Specialists)**
    *   **Purpose:** The actual business logic of the SOC. Each folder inside here represents a standalone process (microservice).
    *   **Belongs here:** The step-by-step logic defined in the Module Contracts.
    *   **Does NOT belong here:** Database connection string parsing (use `core`), shared Data Transfer Objects (use `core`).
*   **`tests/` (Ownership: QA/Security Analysts)**
    *   **Purpose:** Ensures the pipeline reliably detects threats without failing.
*   **`tools/` (Ownership: Simulation/Red Team)**
    *   **Purpose:** Generates the raw material the pipeline ingests. Isolated from `src` to ensure production code never accidentally imports fake generation code.

---

# 3️⃣ DEFINE SERVICE BOUNDARIES

1.  **Independent Docker Containers:** Every folder inside `src/services/` gets its own `Dockerfile` and runs as an isolated container in the Compose network.
2.  **Internal Libraries:** `src/core/` and `src/infra/` are not containers. They act as library code imported by the `services/`.
3.  **RabbitMQ Communication:** Events classified as "New Attacks" by the `signature_engine` are published to a RabbitMQ queue.
4.  **CPU Intensive Modules:**
    *   `src/services/ml_workers/` (requires significant CPU for PyOD/tsfresh).
    *   `src/services/correlation_engine/` (NetworkX graph traversals can become CPU bound over large datasets).
5.  **Scalability:**
    *   `ml_workers/` is designed as a RabbitMQ consumer. To scale, we simply deploy `worker-2`, `worker-3`, etc., via Docker Compose `scale` properties to pull from the same queue asynchronously.

---

# 4️⃣ DEFINE SHARED INFRASTRUCTURE

To prevent code duplication, we centralize shared infrastructure inside `src/core/` and `src/infra/`:

*   **Schemas (`src/core/schemas/`):** The `UnifiedEvent` Pydantic model lives here. All services import it: `from src.core.schemas.unified_event import UnifiedEvent`.
*   **Configs (`src/core/config/`):** Uses Pydantic `BaseSettings` to load everything from the `.env` file once, providing a type-safe config object to all services.
*   **Logging (`src/core/logging/`):** A custom Python logger that forces all modules to emit structured JSON logs, easily read by future observability tools.
*   **Secrets & Env variables:** managed entirely by `.env` (excluded via `.gitignore`) and injected by Docker Compose into the containers.

---

# 5️⃣ DEFINE TESTING STRUCTURE

Testing is crucial for an engineering project of this magnitude.

*   **`tests/unit/`:** Fast, completely mocked tests. Tests Pydantic validations, URL parsers, string matching logic, mathematical formulas in fidelity ranking without touching a database.
*   **`tests/integration/`:** Tests the `src/infra/` folder. Ensures the PostgreSQL CRUD operations work, RabbitMQ messages are successfully published/consumed, and OpenSearch queries return correct counts.
*   **`tests/e2e/ (Pipeline Validation)`:** Takes a raw JSON file from `tests/fixtures/brute_force.json`, shoves it into the edge of the ingestion service, and asserts that a Playbook eventually appears in the PostgreSQL database.

---

# 6️⃣ DEFINE DOCKERIZATION STRATEGY

*   **Separate Dockerfiles:** Every service in `src/services/` gets a Dockerfile. They all use the same base Python image (e.g., `python:3.11-slim`).
*   **Docker Compose Orchestration:** A single `deployments/docker-compose.yml` ties it all together, defining the network bridge.
*   **Service Startup Dependencies:** Docker's `depends_on` will map relationships:
    *   `ingestion_engine` depends on `opensearch`.
    *   `api_gateway` depends on `postgres`.
    *   `ml_workers` depends on `rabbitmq`.
*   **Persistent Volumes:**
    *   `pgdata` (PostgreSQL)
    *   `osdata` (OpenSearch)
    *   `ollama_models` (Ensures we don't re-download LLMs every restart).
*   **Container Networking:** All containers sit on a custom bridge network (e.g., `soc_net`). They address each other by container name (e.g., `http://postgres:5432`). External host access is only allowed for the FastAPI gateway and OpenSearch Dashboards (if used).

---

# 7️⃣ DEFINE FUTURE SCALABILITY

*   **Adding more ML models:** Drop a new Python file into `src/services/ml_workers/anomaly/`.
*   **Adding more workers:** Update `docker-compose.yml` to specify `deploy: replicas: 3` for the `ml_workers` container.
*   **Adding more attack techniques:** Update the JSON mappings in the `mitre_mapper` service.
*   **Scaling RabbitMQ Consumers:** Pika/aio-pika consumers in `ml_workers` automatically round-robin pull from queues. More containers = more throughput.
*   **Future Cloud Migration:** The architecture is cloud-agnostic. Because it is purely Dockerized, you could literally run this locally, or eventually deploy these containers directly into AWS ECS, EKS, or a Kubernetes cluster without fundamentally changing the Python code.

---

# 8️⃣ DEFINE DEVELOPMENT FLOW

To safely build this system without creating a tangled mess, we follow a strict implementation progression:

1.  **Phase 1: Shared Core & Data Models.**
    *   *First:* Build `src/core/schemas/` and `src/core/config/`.
    *   *Then:* Deploy supporting infrastructure (Postgres, RabbitMQ, OpenSearch) via `docker-compose.yml`.
2.  **Phase 2: Simulation & Ingestion (The Head of the Snake).**
    *   *First:* Build `tools/synthetic_generator/` to give ourselves data to work with.
    *   *Then:* Build `src/services/ingestion_engine/` and `src/infra/opensearch/` to successfully pipe data into our Unified Event model.
3.  **Phase 3: The Fast Path (Signatures & Enrichment).**
    *   *First:* Build `src/services/enrichment_engine/`.
    *   *Then:* Build `src/services/signature_engine/` to hash the data and store it in Postgres (`src/infra/postgres/`).
4.  **Phase 4: The Slow Path (ML & Graph).**
    *   *First:* Implement RabbitMQ logic in `src/infra/rabbitmq/`.
    *   *Then:* Build `src/services/ml_workers/` and `src/services/correlation_engine/`.
5.  **Phase 5: Scoring & AI Response (The Tail).**
    *   *First:* Build `src/services/mitre_mapper/` and `src/services/fidelity_engine/`.
    *   *Then:* Build `src/services/playbook_engine/` accessing local LLMs via `src/infra/ollama/`.
6.  **Phase 6: Gateway & Testing.**
    *   *Finally:* Build the `api_gateway` to expose data, and write E2E tests to validate the complete flow.

====================================================
END OF ENTERPRISE FOLDER ARCHITECTURE
====================================================