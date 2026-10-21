# wick

A zero-knowledge, one-time secret sharer. Paste a secret, get a link. The link works
**exactly once** (or until it expires) — then it's gone, like a wick burning down.

The server never sees your secret, and never sees the decryption key. Encryption happens in
the browser with the Web Crypto API; the key lives in the URL `#fragment`, which browsers
never send over HTTP. The server stores ciphertext only — even with full database access,
it cannot read what you shared.

## How it works

1. **Create** — your browser generates a random AES-256-GCM key, encrypts the secret
   (and, optionally, an attached file — name, type, and bytes all encrypted together)
   locally, and uploads only ciphertext. The server hands back an id; your browser builds
   the link as `https://host/s/<id>#<key>`.
2. **Share** the link. Optionally protect it with a passphrase (PBKDF2-derived, binds
   decryption to both the link and the passphrase).
3. **View** — the recipient opens the link, sees a "Reveal" button (so chat apps
   unfurling the link don't accidentally burn it), and clicks it. That click atomically
   fetches and deletes the ciphertext server-side, then decrypts it locally in the browser.
4. Open the link again: it's gone.

Secrets also expire on a TTL (5 min / 1 hour / 1 day / 1 week) even if never viewed, via a
background reaper.

## Running locally

Requires [Nix](https://nixos.org) (no global Rust toolchain needed — `flake.nix` provides one):

```bash
nix develop
cargo run
# open http://localhost:8080
```

Config is via environment variables (all optional):

| Var                      | Default                   | Meaning                                       |
|--------------------------|----------------------------|-----------------------------------------------|
| `PORT`                   | `8080`                    | listen port                                   |
| `DATABASE_URL`           | `sqlite:data/secrets.db`  | sqlite connection string                      |
| `MAX_SECRET_BYTES`       | `262144`                  | max ciphertext size accepted (256 KiB)        |
| `MAX_ATTACHMENT_BYTES`   | `10485760`                | max attachment ciphertext size (10 MiB)       |
| `RATE_LIMIT_BURST`       | `20`                      | per-IP burst size for `POST /api/secrets`     |
| `RATE_LIMIT_PER_SECOND`  | `1`                       | per-IP refill rate (requests/sec) after burst |
| `RUST_LOG`               | —                          | tracing filter, e.g. `wick=debug`             |

## Running with Docker

```bash
docker build -t wick .
docker run -p 8080:8080 -v wick-data:/data wick
```

## Deploying to Kubernetes

```bash
kubectl apply -f k8s/
```

Runs as a single replica with a `ReadWriteOnce` PVC backing the sqlite file — this is a
small, self-hosted tool, not something designed to be horizontally scaled. If you need
more throughput, swap sqlite for Postgres (the `db.rs` module is the only place that
would need to change).

## Security notes

- Ciphertext + nonce (+ salt, if a passphrase was used) are the only things ever stored.
  Verify it yourself: `sqlite3 data/secrets.db 'select * from secrets'` — no plaintext,
  no keys.
- Consuming a secret is one atomic `DELETE ... RETURNING` — two concurrent viewers can't
  both read it.
- `GET /s/:id` (the reveal page) never returns ciphertext — only metadata. This defeats
  link-preview bots that would otherwise burn the secret on unfurl.
- Responses carry `Cache-Control: no-store`, a strict CSP, and `Referrer-Policy: no-referrer`.
- This is a software mitigation against casual/server-side snooping, not a defense against
  a compromised browser or endpoint malware reading the DOM.
- An attachment's filename, MIME type, and bytes are encrypted together into one envelope
  client-side before upload, under the same key as the text -- the server never sees any
  of it.
- `POST /api/secrets` is rate-limited per source IP (`RATE_LIMIT_BURST` /
  `RATE_LIMIT_PER_SECOND`) to curb automated filling of the database. Consuming a secret
  is not rate-limited: its id is already a 128-bit unguessable value.

## Tests

```bash
cargo test
```
