// Zero-knowledge client for "wick".
//
// All cryptography happens here, using only the browser's Web Crypto API. The server
// never sees plaintext and never sees the decryption key: the key lives in location.hash,
// which browsers never transmit in an HTTP request.
//
// Scheme:
//   no passphrase:   key K is random, carried raw in the URL fragment.
//   with passphrase: fragment carries a random salt; the AES key is derived via
//                     PBKDF2-SHA256(passphrase, salt, 310_000 iters). A leaked link alone
//                     is then useless without the passphrase too.

const PBKDF2_ITERATIONS = 310_000;

function b64urlEncode(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(len) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function deriveKeyFromPassphrase(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function generateRawKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// Encrypts the text, and -- if a file was attached -- a second, independent envelope
// `{ name, type, data }` (data is base64 of the raw bytes) under the *same* key but its
// own fresh nonce. Bundling the filename/type inside the encrypted envelope means the
// server never learns them either.
async function encryptSecret(plaintext, passphrase, attachmentFile) {
  const nonce = randomBytes(12);
  const encoded = new TextEncoder().encode(plaintext);

  let key, salt, fragment, requiresPassphrase;
  if (passphrase) {
    salt = randomBytes(16);
    key = await deriveKeyFromPassphrase(passphrase, salt, "encrypt");
    fragment = b64urlEncode(salt);
    requiresPassphrase = true;
  } else {
    key = await generateRawKey();
    const rawKey = await crypto.subtle.exportKey("raw", key);
    fragment = b64urlEncode(rawKey);
    requiresPassphrase = false;
  }

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, encoded);

  let attachment = null;
  if (attachmentFile) {
    const fileBytes = new Uint8Array(await attachmentFile.arrayBuffer());
    const envelope = JSON.stringify({
      name: attachmentFile.name,
      type: attachmentFile.type,
      data: b64urlEncode(fileBytes),
    });
    const attachmentNonce = randomBytes(12);
    const attachmentCiphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: attachmentNonce },
      key,
      new TextEncoder().encode(envelope),
    );
    attachment = { ciphertext: attachmentCiphertext, nonce: attachmentNonce };
  }

  return { ciphertext, nonce, salt, fragment, requiresPassphrase, attachment };
}

// `usage` is "encrypt" when called from encryptSecret, "decrypt" when called from
// decryptSecret -- PBKDF2-derived keys can only be used for the operation they were
// imported for.
async function deriveKeyFromPassphrase(passphrase, salt, usage) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

async function decryptSecret({ ciphertext, nonce, salt, requiresPassphrase, fragment, passphrase }) {
  let key;
  if (requiresPassphrase) {
    key = await deriveKeyFromPassphrase(passphrase, salt, "decrypt");
  } else {
    key = await crypto.subtle.importKey("raw", fragment, "AES-GCM", false, ["decrypt"]);
  }
  const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
  return { plaintext: new TextDecoder().decode(plaintextBuf), key };
}

async function decryptAttachment(key, ciphertext, nonce) {
  const envelopeBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertext);
  const envelope = JSON.parse(new TextDecoder().decode(envelopeBuf));
  return {
    name: envelope.name,
    type: envelope.type,
    bytes: b64urlDecode(envelope.data),
  };
}

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

// ---- Create page -----------------------------------------------------------------------

function initCreateForm() {
  const form = document.getElementById("create-form");
  if (!form) return;

  const usePassphrase = document.getElementById("use-passphrase");
  const passphraseField = document.getElementById("passphrase-field");
  usePassphrase.addEventListener("change", () => {
    passphraseField.hidden = !usePassphrase.checked;
  });

  const attachmentInput = document.getElementById("attachment");
  const maxAttachmentBytes = Number(attachmentInput?.dataset.maxBytes || 0);

  const attachmentHint = document.getElementById("attachment-hint");
  if (attachmentHint) {
    attachmentHint.textContent = `Encrypted in your browser along with the text, up to ${formatBytes(maxAttachmentBytes)}.`;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById("create-error");
    errorEl.hidden = true;

    const secret = document.getElementById("secret").value;
    const ttlSecs = Number(document.getElementById("ttl").value);
    const passphrase = usePassphrase.checked
      ? document.getElementById("passphrase").value
      : null;
    const attachmentFile = attachmentInput?.files[0] || null;

    if (usePassphrase.checked && !passphrase) {
      errorEl.textContent = "Enter a passphrase, or uncheck the passphrase option.";
      errorEl.hidden = false;
      return;
    }

    if (attachmentFile && attachmentFile.size > maxAttachmentBytes) {
      errorEl.textContent = `Attachment is too large (max ${formatBytes(maxAttachmentBytes)}).`;
      errorEl.hidden = false;
      return;
    }

    try {
      const enc = await encryptSecret(secret, passphrase, attachmentFile);

      const res = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ciphertext: b64urlEncode(enc.ciphertext),
          nonce: b64urlEncode(enc.nonce),
          salt: enc.salt ? b64urlEncode(enc.salt) : null,
          requires_passphrase: enc.requiresPassphrase,
          ttl_secs: ttlSecs,
          attachment_ciphertext: enc.attachment ? b64urlEncode(enc.attachment.ciphertext) : null,
          attachment_nonce: enc.attachment ? b64urlEncode(enc.attachment.nonce) : null,
        }),
      });

      if (!res.ok) {
        const body = await res.text();
        throw new Error(body || `request failed (${res.status})`);
      }

      const { id } = await res.json();
      const link = `${location.origin}/s/${id}#${enc.fragment}`;

      document.getElementById("result-link").value = link;
      document.getElementById("create-result").hidden = false;
      form.hidden = true;
    } catch (err) {
      errorEl.textContent = `Could not create secret: ${err.message}`;
      errorEl.hidden = false;
    }
  });

  const copyBtn = document.getElementById("copy-link");
  copyBtn?.addEventListener("click", async () => {
    const input = document.getElementById("result-link");
    await navigator.clipboard.writeText(input.value);
    copyBtn.textContent = "Copied!";
    setTimeout(() => (copyBtn.textContent = "Copy"), 1500);
  });
}

// ---- Reveal page ------------------------------------------------------------------------

function initRevealPage() {
  const card = document.getElementById("reveal-card");
  if (!card) return;

  const id = card.dataset.id;
  const requiresPassphrase = card.dataset.requiresPassphrase === "true";
  const revealBtn = document.getElementById("reveal-button");
  if (!revealBtn) return; // "not available" branch of the template -- nothing to wire up.

  revealBtn.addEventListener("click", async () => {
    const errorEl = document.getElementById("reveal-error");
    const outEl = document.getElementById("revealed-secret");
    errorEl.hidden = true;

    const fragment = location.hash.slice(1);
    if (!fragment) {
      errorEl.textContent = "Missing decryption key in the URL. Use the full link you were given.";
      errorEl.hidden = false;
      return;
    }

    let passphrase = null;
    if (requiresPassphrase) {
      passphrase = document.getElementById("passphrase")?.value;
      if (!passphrase) {
        errorEl.textContent = "Enter the passphrase.";
        errorEl.hidden = false;
        return;
      }
    }

    revealBtn.disabled = true;
    revealBtn.textContent = "Revealing...";

    try {
      const res = await fetch(`/api/secrets/${id}/consume`, {
        method: "POST",
        headers: { "X-Requested-With": "wick" },
      });
      if (!res.ok) {
        throw new Error(
          res.status === 404
            ? "This secret has already been viewed, expired, or never existed."
            : `request failed (${res.status})`,
        );
      }

      const data = await res.json();
      const { plaintext, key } = await decryptSecret({
        ciphertext: b64urlDecode(data.ciphertext),
        nonce: b64urlDecode(data.nonce),
        salt: data.salt ? b64urlDecode(data.salt) : null,
        requiresPassphrase: data.requires_passphrase,
        fragment: requiresPassphrase ? null : b64urlDecode(fragment),
        passphrase,
      });

      outEl.textContent = plaintext;
      outEl.hidden = false;
      revealBtn.hidden = true;

      if (data.attachment_ciphertext && data.attachment_nonce) {
        const attachment = await decryptAttachment(
          key,
          b64urlDecode(data.attachment_ciphertext),
          b64urlDecode(data.attachment_nonce),
        );
        const blob = new Blob([attachment.bytes], { type: attachment.type || "application/octet-stream" });
        const url = URL.createObjectURL(blob);

        const downloadLink = document.getElementById("attachment-download");
        downloadLink.href = url;
        downloadLink.download = attachment.name;
        downloadLink.textContent = `Download ${attachment.name}`;
        downloadLink.hidden = false;
        downloadLink.addEventListener("click", () => {
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        });
      }
    } catch (err) {
      // A decrypt failure (wrong passphrase, or tampered ciphertext) throws here too --
      // the secret is already burned server-side at this point, by design: a one-time
      // link is one-time even if the viewer mistypes the passphrase.
      errorEl.textContent = err.message.includes("decrypt")
        ? "Could not decrypt -- wrong passphrase? Note the secret is now burned regardless."
        : err.message;
      errorEl.hidden = false;
      revealBtn.hidden = true;
    }
  });
}

initCreateForm();
initRevealPage();
