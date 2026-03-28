use axum::extract::{Path,Query,Json};
use crypto::Envelope;
use db::select_secret;
use leptos::attr::selected;
use uuid::Uuid;
use serde::{Serialize,Deserialize};
use db::SecretErrors;
#[derive(Serialize,Deserialize)]
pub struct Decrypt_data {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>

}
impl Decrypt_data {
    fn new(data:(Vec<u8>,Vec<u8>)) -> Decrypt_data {
        Decrypt_data {
            nonce: data.0,
        ciphertext: data.1
        }

    }
}


async fn encrypt_data() {

}

async fn fetch_decrypt(conn:&sqlx::Pool<sqlx::Postgres>,Path(path_data):Path<&str>)  -> Result<Json<Decrypt_data>,SecretErrors>
{
    let secret_uuid = Uuid::parse_str(path_data).unwrap();
    match select_secret(conn,secret_uuid).await {
        Ok(d) => {
            let decryption_items = Decrypt_data::new(d);
            Ok(Json::from(decryption_items))
        }
        Err(e) => Err(e)

    }




}

async fn authenticate() -> bool {


}
