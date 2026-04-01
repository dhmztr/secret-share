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
    File { name: String,mime:String },
}

const TAG_TEXT: u8 = 0x01;
const TAG_FILE: u8 = 0x02;

/// Prepend content-type metadata to `data` before encrypting.
pub fn wrap_payload(kind: &ContentType, data: &[u8]) -> Vec<u8> {
    match kind {
        ContentType::Text => {
            let mut out = Vec::with_capacity(1 + 2 + data.len());
            out.push(TAG_TEXT);
            out.extend_from_slice(&(0u16).to_be_bytes());
            out.extend_from_slice(&(0u16).to_be_bytes());
            out.extend_from_slice(data);
            out

        }
    ContentType::File {name,mime} => {
            let name_bytes = name.as_bytes();
            let mime_bytes = mime.as_bytes();
            let name_len = name_bytes.len() as u16;
            let mime_len= mime_bytes.len() as u16;
            let mut out = Vec::with_capacity(1 + 2 + name_bytes.len() + 2 + mime_bytes.len() + data.len());
            out.push(TAG_FILE);
            out.extend_from_slice(&name_len.to_be_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&mime_len.to_be_bytes());
            out.extend_from_slice(mime_bytes );
            out.extend_from_slice(data);
            out
        }
    }
}

/// Recover content-type and raw content from a decrypted payload.
pub fn unwrap_payload(data: &[u8]) -> Result<(ContentType, Vec<u8>), String> {
     if data.is_empty() {
         return Err("payload too short".to_string());
     }

   let tag = data[0];
   match tag {
       TAG_TEXT => {
           // Expect tag(1) + name_len(2) + mime_len(2) = 5 bytes header
           if data.len() < 5 {
               return Err("payload too short for text".to_string());
           }
           let content = data[5..].to_vec();
           Ok((ContentType::Text, content))
       }

       TAG_FILE => {
           // Need at least tag(1) + name_len(2)
           if data.len() < 3 {
               return Err("payload too short for file header".to_string());
           }
           let name_len = u16::from_be_bytes([data[1], data[2]]) as usize;
           let mut pos = 3usize;

           if data.len() < pos + name_len {
               return Err("payload truncated (name)".to_string());
           }
           let name = std::str::from_utf8(&data[pos..pos + name_len])
               .map_err(|_| "filename is not valid UTF-8".to_string())?
               .to_string();
           pos += name_len;

           // Need mime_len(2)
           if data.len() < pos + 2 {
               return Err("payload truncated (mime length)".to_string());
           }
           let mime_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
           pos += 2;

           if data.len() < pos + mime_len {
               return Err("payload truncated (mime)".to_string());
           }
           let mime = std::str::from_utf8(&data[pos..pos + mime_len])
               .map_err(|_| "mime is not valid UTF-8".to_string())?
               .to_string();
           pos += mime_len;

           let content = data[pos..].to_vec();
           Ok((ContentType::File { name, mime }, content))
       }

       other => Err(format!("unknown content-type tag: 0x{other:02x}")),
   }
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

fn hex_dump_labelled(label: &str, bytes: &[u8]) {
       use std::io::Write;
       let mut out = String::new();
       out.push_str(&format!("--- {} (len={}) ---\n", label, bytes.len()));
       for (i, b) in bytes.iter().enumerate() {
           out.push_str(&format!("{:02x}", b));
           if i % 16 == 15 {
               out.push('\n');
           } else {
               out.push(' ');
           }
       }
       if !bytes.is_empty() && bytes.len() % 16 != 0 {
           out.push('\n');
       }
       // write to stderr so it's visible with --nocapture
       let _ = writeln!(std::io::stderr(), "{}", out);
   }

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
   fn wrap_unwrap_file_debug() {
       // przygotuj dane testowe
       let content = b"\x89PNG\r\n\x1a\n"; // fake PNG header
       // nowy format: include mime
       let kind_in = ContentType::File {
           name: "image.png".to_string(),
           mime: "image/png".to_string(),
       };

       // 1) wygeneruj wrapped payload
       let wrapped = wrap_payload(&kind_in, content);

       // 2) wypisz hexdump (debug)
       hex_dump_labelled("wrapped (new format)", &wrapped);

       // 3) spróbuj odszyfrować / parse'ować
       match unwrap_payload(&wrapped) {
           Ok((k, c)) => {
               eprintln!("unwrap ok: kind={:?}, content_len={}", k, c.len());
           }
           Err(e) => {
               eprintln!("unwrap error: {}", e);
               panic!("unwrap failed: {}", e);
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
           }
       }

       // 4) symulacja starego formatu (brak mime_len/mime)
       let name = "image.png".as_bytes();
       let mut old = Vec::new();
       old.push(TAG_FILE);
       old.extend_from_slice(&(name.len () as u16).to_be_bytes());
       old.extend_from_slice(name);
       old.extend_from_slice(content);

       hex_dump_labelled("wrapped (old format)", &old);

       match unwrap_payload(&old) {
           Ok((k, c)) => {
               eprintln!("unwrap(old) ok: kind={:?}, content_len={}", k, c.len());
           }
           Err(e) => {
               eprintln!("unwrap(old) error: {}", e);
           }
       }
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
