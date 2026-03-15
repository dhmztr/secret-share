pub fn add(left: u64, right: u64) -> u64 {
    left + right
}
use aead::{AeadCore,KeyInit,OsRng,Aead};
use chacha20poly1305::{ChaCha20Poly1305,Key,Nonce};

pub struct Envelope {
    pub nonce: [u8;12],
    pub ciphertext: Vec<u8>
}
pub fn encrypt(data:&[u8]) -> Result<(Envelope,[u8;32]),String>{
    let key  = ChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce= ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher.encrypt(&nonce,data).map_err(|_| "encrypt failed".to_string())?;
    let env = Envelope {
        nonce: nonce.into(),
        ciphertext
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
    #[test]
    fn encrypt_works() {
        let plain = "kocham zydow".as_bytes();
        let env: Envelope;
        let (env,klucz) = encrypt(plain).unwrap();
        let decrypted = decrypt(&klucz,&env.nonce,&env.ciphertext).unwrap();
        assert_eq!(plain,decrypted );

    }
}
