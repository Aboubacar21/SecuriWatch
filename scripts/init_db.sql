-- Script d'initialisation de la base de données SecuriWatch
-- Crée les tables principales pour stocker les logs et incidents

-- Extension pour UUID
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table des utilisateurs de l'application
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des logs collectés
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    hostname VARCHAR(255),
    process VARCHAR(100),
    pid INTEGER,
    event_type VARCHAR(50) NOT NULL,
    user_name VARCHAR(100),
    ip_address INET,
    message TEXT,
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 10),
    raw_log TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_timestamp_event_type UNIQUE (timestamp, event_type, message)
);

-- Index pour améliorer les performances
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX idx_logs_event_type ON logs(event_type);
CREATE INDEX idx_logs_risk_score ON logs(risk_score DESC);
CREATE INDEX idx_logs_user ON logs(user_name);
CREATE INDEX idx_logs_ip ON logs(ip_address);

-- Table des incidents de sécurité détectés
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')) DEFAULT 'OPEN',
    event_type VARCHAR(50),
    affected_user VARCHAR(100),
    source_ip INET,
    detection_method VARCHAR(50),
    confidence_score FLOAT CHECK (confidence_score >= 0 AND confidence_score <= 1),
    related_logs_count INTEGER DEFAULT 0,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    assigned_to UUID REFERENCES users(id),
    notes TEXT
);

-- Index pour les incidents
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_detected_at ON incidents(detected_at DESC);

-- Table de liaison logs <-> incidents
CREATE TABLE IF NOT EXISTS incident_logs (
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    log_id BIGINT REFERENCES logs(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, log_id)
);

-- Table des alertes envoyées
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents(id),
    alert_type VARCHAR(50) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'SENT', 'FAILED')) DEFAULT 'PENDING',
    sent_at TIMESTAMP,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des règles de détection configurables
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id)
);

-- Table pour stocker les statistiques quotidiennes
CREATE TABLE IF NOT EXISTS daily_stats (
    date DATE PRIMARY KEY,
    total_logs INTEGER DEFAULT 0,
    total_incidents INTEGER DEFAULT 0,
    high_risk_events INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    avg_risk_score FLOAT,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fonction pour mettre à jour le timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger pour auto-update des timestamps
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_detection_rules_updated_at BEFORE UPDATE ON detection_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Créer un utilisateur admin par défaut
INSERT INTO users (email, username, hashed_password, is_superuser) 
VALUES (
    'admin@securiwatch.local',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzpLaOBzLO',
    true
) ON CONFLICT (email) DO NOTHING;

-- Afficher un message de succès
DO $$
BEGIN
    RAISE NOTICE 'Base de données SecuriWatch initialisée avec succès!';
    RAISE NOTICE 'Tables créées: users, logs, incidents, alerts, detection_rules';
    RAISE NOTICE 'Utilisateur admin créé: admin@securiwatch.local / admin123';
END $$;
