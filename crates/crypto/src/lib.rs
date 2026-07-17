use aead::{Aead, AeadCore, KeyInit, OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};


#[derive(Deserialize, Serialize, Clone)]
pub struct Envelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub password: Option<String>,
}


#[derive(Clone, Debug, PartialEq)]
pub enum ContentType {
    Text,
    File { name: String,mime:String },
}

const TAG_TEXT: u8 = 0x01;
const TAG_FILE: u8 = 0x02;

pub fn wrap_payload(kind: &ContentType, data: &[u8]) -> Vec<u8> {
    match kind {
        ContentType::Text => {
            let mut out = Vec::with_capacity(1 + 2 + data.len());
            out.push(TAG_TEXT);
            // reserved header fields; keeps TEXT payload layout parseable alongside FILE
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

pub fn unwrap_payload(data: &[u8]) -> Result<(ContentType, Vec<u8>), String> {
     if data.is_empty() {
         return Err("payload too short".to_string());
     }

   let tag = data[0];
   match tag {
       TAG_TEXT => {
           if data.len() < 5 {
               return Err("payload too short for text".to_string());
           }
           let content = data[5..].to_vec();
           Ok((ContentType::Text, content))
       }

       TAG_FILE => {
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

pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed – wrong key or tampered data".to_string())
}


pub fn hash_password(pass: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pass, &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("password hashing failed: {e}"))
}

pub fn authenticate(dbpass: &str, contestant: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(dbpass) else {
        return false;
    };
    Argon2::default()
        .verify_password(contestant.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
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
       let content = b"\x89PNG\r\n\x1a\n"; // fake PNG header
       let kind_in = ContentType::File {
           name: "image.png".to_string(),
           mime: "image/png".to_string(),
       };

       let wrapped = wrap_payload(&kind_in, content);

       hex_dump_labelled("wrapped (new format)", &wrapped);

       match unwrap_payload(&wrapped) {
           Ok((k, c)) => {
               eprintln!("unwrap ok: kind={:?}, content_len={}", k, c.len());
           }
           Err(e) => {
               eprintln!("unwrap error: {}", e);
               panic!("unwrap failed: {}", e);
           }
       }

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

        let hash = env.password.as_deref().unwrap();
        assert!(authenticate(hash, "pass123"));

        let decrypted = decrypt(&key, &env.nonce, &env.ciphertext).unwrap();
        let (kind, content) = unwrap_payload(&decrypted).unwrap();
        assert_eq!(kind, ContentType::Text);
        assert_eq!(content, text.as_bytes());
    }
}
