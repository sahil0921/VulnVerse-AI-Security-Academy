-- Capstone scenario: NimbleTech research portal database
-- Simulates MSSQL xp_cmdshell-style RCE via unvalidated AI tool access
CREATE TABLE IF NOT EXISTS research_papers (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200),
    author VARCHAR(100),
    abstract TEXT,
    published_date DATE
);
INSERT INTO research_papers (title, author, abstract, published_date) VALUES
('LLM Security in Enterprise', 'Dr. Anita Rao', 'Survey of prompt injection defenses across Fortune 500.', '2026-01-15'),
('Adversarial ML in Production', 'Prof. Karthik Iyer', 'Real-world case studies of model evasion.', '2026-02-08'),
('RAG Pipeline Threats', 'Dr. Meera Shah', 'Indirect injection via retrieved context.', '2026-03-22'),
('Agentic AI Risk Surface', 'Dr. Vikram Desai', 'Tool-using LLMs and unvalidated execution.', '2026-04-10');
-- The juicy table — simulates "OS command execution surface"
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE
);
INSERT INTO system_config (config_key, config_value, is_sensitive) VALUES
('app_version', '4.2.1', FALSE),
('maintenance_window', 'Sundays 02:00-04:00 UTC', FALSE),
('dmz_service_account', 'DMZ\dmzsvc:FelonPrizeTuttle33@', TRUE),
('rd_gateway_host', 'CONNECT02.dmz.nimbletech.ai', TRUE),
('gitlab_pat_hint', 'glpat-U16O5MaQLgJp_yyZMQUuPm86MQp1OjMH.01.0w1255sqp', TRUE),
('dev_db_creds', 'devdbsvc:RecedingSimsCasts3@ on db01.dev.nimbletech.ai', TRUE),
('rag_kb_creds', 'NIMBLETECH\rag_kb:Corrupt44!Plow', TRUE),
('admin_passphrase_hint', 'Check PSReadLine history on FILESERVER01', TRUE);
-- Capstone narrative trail
CREATE TABLE IF NOT EXISTS engagement_notes (
    id SERIAL PRIMARY KEY,
    phase VARCHAR(50),
    note TEXT
);
INSERT INTO engagement_notes (phase, note) VALUES
('Phase 1', 'Public chatbot at nimbletech.ai exposes SQL tool with no validation.'),
('Phase 2', 'DMZ\dmzsvc has GenericWrite on VPN Users group — lateral pivot.'),
('Phase 6', 'RAG agent on FILESERVER01 has unrestricted read_file tool.');
