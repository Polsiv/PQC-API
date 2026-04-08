-- scripts/init.sql
-- Runs once when the PostgreSQL container first starts.

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast username lookups during login
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
