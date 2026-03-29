use aead::{Aead, AeadCore, KeyInit, OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Envelope – the blob the server stores.
// `password` carries the argon2 PHC hash when the creator set a passphrase;
// the server stores it and uses it to gate future reads.  The actual
// encryption key is NEVER sent to the server – it lives in the URL fragment.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone)]
pub struct Envelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// Argon2id PHC string, produced client-side.  `None` → no passphrase.
    pub password: Option<String>,
}

// ---------------------------------------------------------------------------
// Content-type metadata embedded inside the plaintext BEFORE encryption.
//
// Format (binary, prepended to the actual payload):
//   [u8]      type tag  — 0x01 = text, 0x02 = file
//   [u16 BE]  name_len  — byte-length of the name/filename (0 for text)
//   [name_len bytes]    — UTF-8 filename (empty for text)
//   [rest]              — actual content
//
// Because this is encrypted together with the payload, the server learns
// nothing about whether the secret is text or a file.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum ContentType {
    Text,
    File { name: String },
}

const TAG_TEXT: u8 = 0x01;
const TAG_FILE: u8 = 0x02;

/// Prepend content-type metadata to `data` before encrypting.
pub fn wrap_payload(kind: &ContentType, data: &[u8]) -> Vec<u8> {
    let (tag, name_bytes): (u8, &[u8]) = match kind {
        ContentType::Text => (TAG_TEXT, b""),
        ContentType::File { name } => (TAG_FILE, name.as_bytes()),
    };

    let name_len = name_bytes.len() as u16;
    let mut out = Vec::with_capacity(3 + name_bytes.len() + data.len());
    out.push(tag);
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);
    out
}

/// Recover content-type and raw content from a decrypted payload.
pub fn unwrap_payload(data: &[u8]) -> Result<(ContentType, Vec<u8>), String> {
    if data.len() < 3 {
        return Err("payload too short".to_string());
    }

    let tag = data[0];
    let name_len = u16::from_be_bytes([data[1], data[2]]) as usize;

    if data.len() < 3 + name_len {
        return Err("payload truncated".to_string());
    }

    let name = std::str::from_utf8(&data[3..3 + name_len])
        .map_err(|_| "filename is not valid UTF-8".to_string())?
        .to_string();

    let content = data[3 + name_len..].to_vec();

    let kind = match tag {
        TAG_TEXT => ContentType::Text,
        TAG_FILE => ContentType::File { name },
        other => return Err(format!("unknown content-type tag: 0x{other:02x}")),
    };

    Ok((kind, content))
}

// ---------------------------------------------------------------------------
// Symmetric encryption / decryption (ChaCha20-Poly1305)
// ---------------------------------------------------------------------------

/// Encrypt `data` with a freshly-generated random key.
///
/// If `pass` is `Some`, it is hashed with Argon2id and the PHC string is
/// stored in `Envelope::password` — this happens CLIENT-SIDE in the browser.
///
/// Returns `(Envelope, encryption_key)`.  The caller must keep the key secret
/// and distribute it only through the URL fragment.
pub fn encrypt(data: &[u8], pass: Option<&[u8]>) -> Result<(Envelope, [u8; 32]), String> {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| "encryption failed".to_string())?;

    let password = pass.map(hash_password).transpose()?;

    let env = Envelope {
        nonce: nonce.to_vec(),
        ciphertext,
        password,
    };

    Ok((env, key.into()))
}

/// Decrypt ciphertext using the raw 32-byte key and the stored nonce.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed – wrong key or tampered data".to_string())
}

// ---------------------------------------------------------------------------
// Password helpers
// ---------------------------------------------------------------------------

/// Hash a plaintext password with Argon2id and return the PHC string.
/// The salt is generated freshly each time, so the hash is always unique.
pub fn hash_password(pass: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pass, &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("password hashing failed: {e}"))
}

/// Verify a plaintext `contestant` password against a stored Argon2 PHC hash.
/// Returns `true` only when the password is correct.
pub fn authenticate(dbpass: &str, contestant: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(dbpass) else {
        return false;
    };
    Argon2::default()
        .verify_password(contestant.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plain = b"hello, world";
        let (env, key) = encrypt(plain, None).unwrap();
        let decrypted = decrypt(&key, &env.nonce, &env.ciphertext).unwrap();
        assert_eq!(plain.as_slice(), decrypted.as_slice());
        assert!(env.password.is_none());
    }

    #[test]
    fn encrypt_with_password_stores_hash() {
        let plain = b"secret";
        let pass = b"hunter2";
        let (env, _key) = encrypt(plain, Some(pass)).unwrap();
        let hash = env.password.expect("hash should be present");
        assert!(authenticate(&hash, "hunter2"));
        assert!(!authenticate(&hash, "wrong"));
    }

    #[test]
    fn wrap_unwrap_text() {
        let content = b"some text content";
        let wrapped = wrap_payload(&ContentType::Text, content);
        let (kind, out) = unwrap_payload(&wrapped).unwrap();
        assert_eq!(kind, ContentType::Text);
        assert_eq!(out, content);
    }

    #[test]
    fn wrap_unwrap_file() {
        let content = b"\x89PNG\r\n\x1a\n"; // fake PNG header
        let kind_in = ContentType::File {
            name: "image.png".to_string(),
        };
        let wrapped = wrap_payload(&kind_in, content);
        let (kind_out, out) = unwrap_payload(&wrapped).unwrap();
        assert_eq!(
            kind_out,
            ContentType::File {
                name: "image.png".to_string()
            }
        );
        assert_eq!(out, content);
    }

    #[test]
    fn full_pipeline_text() {
        let text = "top secret message";
        let payload = wrap_payload(&ContentType::Text, text.as_bytes());
        let (env, key) = encrypt(&payload, Some(b"pass123")).unwrap();

        // Server stores env; viewer gets key from URL fragment and sends password.
        let hash = env.password.as_deref().unwrap();
        assert!(authenticate(hash, "pass123"));

        let decrypted = decrypt(&key, &env.nonce, &env.ciphertext).unwrap();
        let (kind, content) = unwrap_payload(&decrypted).unwrap();
        assert_eq!(kind, ContentType::Text);
        assert_eq!(content, text.as_bytes());
    }
}
