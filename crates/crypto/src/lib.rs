use std::char::ParseCharError;
use serde::{Deserialize,Serialize};
use aead::{AeadCore,KeyInit,OsRng,Aead};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chacha20poly1305::{ChaCha20Poly1305,Key,Nonce};
#[derive(Deserialize,Serialize)]
pub struct Envelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub password: Option<String>
}
pub fn encrypt(data:&[u8],pass:Option<&[u8]>) -> Result<(Envelope,[u8;32]),String>{
    let key  = ChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce= ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher.encrypt(&nonce,data).map_err(|_| "encrypt failed".to_string())?;
    let password:Option<String> = if let Some(passbytes) = pass {
        let argon2 = Argon2::default();
        let argonsalt = SaltString::generate(&mut OsRng);
        Some(
            argon2.hash_password(passbytes, &argonsalt)
            .unwrap()
            .to_string()

        )
    } else {
        None
    };
    let env = Envelope {
        nonce:nonce.to_vec(),
        ciphertext,
        password,
    };
    Ok((env,key.into()))


}
pub fn decrypt(key: &[u8], nonce: &[u8],ciphertext:&[u8])  -> Result<Vec<u8>,String> {
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(key);
    let plain: Vec<u8> = cipher.decrypt(nonce,ciphertext).map_err(|_| "Unable to decrypt".to_string())?;
    Ok(plain)



}


pub fn authenticate(dbpass:&str,contestant:&str) -> bool{
    let Ok(parsed) = PasswordHash::new(dbpass) else {
        return false;
    };
    Argon2::default().verify_password(contestant.as_bytes(), &parsed).is_ok()

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_works() {
        let plain = "kocham zydow".as_bytes();
        let env: Envelope;
        let (env,klucz) = encrypt(plain,None).unwrap();
        let decrypted = decrypt(&klucz,&env.nonce,&env.ciphertext).unwrap();
        assert_eq!(plain,decrypted );

    }
}


