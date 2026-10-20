CREATE TABLE secrets (
    id                  TEXT    PRIMARY KEY,
    ciphertext          BLOB    NOT NULL,
    nonce               BLOB    NOT NULL,
    salt                BLOB,
    requires_passphrase INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL
);

CREATE INDEX idx_secrets_expires_at ON secrets (expires_at);
