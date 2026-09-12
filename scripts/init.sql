-- this script should run once when the container first starts

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role INTEGER NOT NULL DEFAULT 0
);

-- index for fast username lookups during login
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- seed the default admin account (role = 1). password_hash is Argon2id
-- (libsodium crypto_pwhash) of the bootstrap password. ON CONFLICT keeps
-- this idempotent if the user already exists.
INSERT INTO users (username, password_hash, role)
VALUES ('paulsiv', '$argon2id$v=19$m=65536,t=2,p=1$ZGw5YmM1MmRsRmRZTVg3ag$fRXa53KJ9wptwX0WmQ7/Lg5+dS+LXqIkZzPzK4eG1ak', 1)
ON CONFLICT (username) DO NOTHING;

CREATE TABLE IF NOT EXISTS documents (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename    VARCHAR(255) NOT NULL,
    pdf_data    TEXT NOT NULL,
    signature   TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    signed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- index for listing a user's documents
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
