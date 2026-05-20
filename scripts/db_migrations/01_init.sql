-- PostgreSQL init script for embedded SOC Intelligence DB

CREATE TABLE IF NOT EXISTS fingerprints (
    id SERIAL PRIMARY KEY,
    fingerprint_hash VARCHAR(64) UNIQUE NOT NULL,
    fingerprint_string TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    match_count INTEGER DEFAULT 1,
    known_attack BOOLEAN DEFAULT FALSE,
    mitre_technique_id VARCHAR(32),
    risk_level VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    fingerprint_id INTEGER REFERENCES fingerprints(id),
    incident_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    id SERIAL PRIMARY KEY,
    fingerprint_id INTEGER REFERENCES fingerprints(id),
    technique_id VARCHAR(32),
    tactic VARCHAR(64),
    confidence FLOAT
);

CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    fingerprint_id INTEGER REFERENCES fingerprints(id),
    remediation_steps JSONB,
    analyst_guidance TEXT
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id SERIAL PRIMARY KEY,
    fingerprint_id INTEGER REFERENCES fingerprints(id),
    anomaly_score FLOAT,
    ueba_score FLOAT,
    final_risk_score FLOAT
);
