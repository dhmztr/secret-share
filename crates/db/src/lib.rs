use chrono::{DateTime,Utc};
use crypto::{Envelope,encrypt};
use sqlx::{self, Connection, Error, PgConnection, postgres::{PgConnectOptions, PgPoolOptions}};
use uuid::Uuid;
const VERSION:i16= 1;
pub struct SecretLink {
    v: i16,
    nonce: Vec<u8>,
    cipher: Vec<u8>,
    max_views:i32,
    view_count:i32,
    expires_at: DateTime<Utc>,
    burned_at:Option<DateTime<Utc>>,
    created_at:DateTime<Utc>,
}
impl SecretLink {
    pub fn new(env: Envelope, max_views: i32, expires_at: DateTime<Utc>) -> Self {
        Self {
            v: VERSION,
            nonce: env.nonce,
            cipher: env.ciphertext,
            max_views,
            view_count: 0,
            expires_at,
            burned_at: None,
            created_at: Utc::now(),
        }
    }
}



pub async fn connect(user:&str,password:&str,port:u16,host:&str,dbname:&str) -> Result<sqlx::Pool<sqlx::Postgres>,String> {
    let connect_options = PgConnectOptions::new()
        .password(&password)
        .username(&user)
        .port(port)
        .host(host)
        .database(dbname);
    PgPoolOptions::new().max_connections(10).connect_with(connect_options).await.map_err(|err| format!("Error:{err}"))




}

pub async fn insert_secret(conn:sqlx::Pool<sqlx::Postgres>,secret:SecretLink) -> Result<Uuid,String> {

match sqlx::query_scalar!(
    r#"
    INSERT INTO secrets
        (v, nonce, ciphertext, max_views, view_count, expires_at, burned_at, created_at)
    VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING secret_id
    "#,
    secret.v,
    secret.nonce,
    secret.cipher,
    secret.max_views,
    secret.view_count,
    secret.expires_at,
    secret.burned_at,
    secret.created_at
)
.fetch_one(&conn)
.await
{
        Ok(new_uuid) => Ok(new_uuid),
        Err(err) => Err("Failed to insert secret".to_owned())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn try_connect() {
        let result = connect("REDACTED_USER","REDACTED_PASSWORD",5432,"REDACTED_HOST","secret_share").await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    pub async fn insert_test() {
        let conn= connect("REDACTED_USER","REDACTED_PASSWORD",5432,"REDACTED_HOST","secret_share").await.unwrap();

        let dummy_data: &[u8] = "lol".as_bytes();
        let (en,_) = encrypt(dummy_data).unwrap();
        let s = SecretLink::new(en,5,Utc::now());
        let ins_res = insert_secret(conn, s).await;
        assert!(ins_res.is_ok())


    }

}
