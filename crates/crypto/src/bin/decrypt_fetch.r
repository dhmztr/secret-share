use std::env;
use std::fs::File;
use std::io::Read;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crypto::{decrypt, unwrap_payload, ContentType};

#[derive(Deserialize)]
struct FetchResp {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn usage() {
    eprintln!("Usage: decrypt_fetch <fetch.json> <base64url-key> <out-file-or-dir>");
    eprintln!("Example: cargo run -p crypto --bin decrypt_fetch -- /tmp/fetch.json 7C3uw-... /tmp/out.bin");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let fetch_path = match args.next() {
        Some(p) => p,
        None => { usage(); return Ok(()) }
    };
    let key_b64 = match args.next() {
        Some(k) => k,
        None => { usage(); return Ok(()) }
    };
    let out_path = match args.next() {
        Some(o) => o,
        None => { usage(); return Ok(()) }
    };

    // Read fetch.json
    let mut f = File::open(&fetch_path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let fetch: FetchResp = serde_json::from_str(&s)?;

    // decode key (base64url no-pad)
    let key_bytes = URL_SAFE_NO_PAD.decode(key_b64.as_bytes())?;
    if key_bytes.len() != 32 {
        eprintln!("Warning: key length is {} bytes (expected 32)", key_bytes.len());
    }

    // decrypt
    let plaintext = decrypt(&key_bytes, &fetch.nonce, &fetch.ciphertext)
        .map_err(|e| format!("decrypt error: {}", e))?;

    // unwrap payload
    let (kind, content) = unwrap_payload(&plaintext)
        .map_err(|e| format!("unwrap error: {}", e))?;

    match kind {
        ContentType::Text => {
            // write as UTF-8 text
            std::fs::write(&out_path, content)?;
            println!("Wrote text output to {}", out_path);
        }
        ContentType::File { name, mime } => {
            // If out_path is a directory, write into it with the original filename
            let meta = std::fs::metadata(&out_path);
            let final_path = if meta.is_ok() && meta.unwrap().is_dir() {
                let mut p = std::path::PathBuf::from(out_path);
                p.push(name);
                p
            } else {
                std::path::PathBuf::from(out_path)
            };
            std::fs::write(&final_path, content)?;
            println!("Wrote file output to {} (mime={})", final_path.display(), mime);
        }
    }

    Ok(())
}
