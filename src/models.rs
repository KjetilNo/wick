use serde::{Deserialize, Serialize};

/// Body posted by the browser after it has already encrypted the secret client-side.
/// Every field here is ciphertext, a nonce, or an (optional) KDF salt -- the server
/// never sees plaintext and never sees the decryption key.
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    /// base64url(AES-256-GCM ciphertext, tag included)
    pub ciphertext: String,
    /// base64url(96-bit GCM nonce)
    pub nonce: String,
    /// base64url(PBKDF2 salt) -- present only when a passphrase was used
    pub salt: Option<String>,
    pub requires_passphrase: bool,
    /// requested time-to-live, in seconds; server clamps to the allowed set
    pub ttl_secs: i64,
}

#[derive(Debug, Serialize)]
pub struct CreateSecretResponse {
    pub id: String,
}

/// Returned exactly once, by the atomic consume endpoint, then the row is gone.
#[derive(Debug, Serialize)]
pub struct ConsumeResponse {
    pub ciphertext: String,
    pub nonce: String,
    pub salt: Option<String>,
    pub requires_passphrase: bool,
}
