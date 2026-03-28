use chrono::{DateTime,Utc};
use crypto::{Envelope};
use sqlx::{self, postgres::{PgConnectOptions, PgPoolOptions}};
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
    haslo:Option<String>
}
pub enum SecretErrors {
    Expired,
    ConnectionFailed

}
impl SecretLink {
    pub fn new(env: Envelope, max_views: i32, expires_at: DateTime<Utc>,haslo:Option<String>) -> Self {
        Self {
            v: VERSION,
            nonce: env.nonce,
            cipher: env.ciphertext,
            max_views,
            view_count: 0,
            expires_at,
            burned_at: None,
            created_at: Utc::now(),
            haslo
        }
    }
}



pub async fn connect(user:&str,password:&str,port:u16,host:&str,dbname:&str) -> Result<sqlx::Pool<sqlx::Postgres>,String> {
    let connect_options = PgConnectOptions::new()
        .password(password)
        .username(user)
        .port(port)
        .host(host)
        .database(dbname);
    PgPoolOptions::new().max_connections(10).connect_with(connect_options).await.map_err(|err| format!("Error:{err}"))




}

pub async fn insert_secret(conn:sqlx::Pool<sqlx::Postgres>,secret:SecretLink) -> Result<Uuid,SecretErrors> {

match sqlx::query_scalar!(
    r#"
    INSERT INTO secrets
        (v, nonce, ciphertext, max_views, view_count, expires_at, burned_at, created_at,haslo)
    VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8,$9)
    RETURNING secret_id
    "#,
    secret.v,
    secret.nonce,
    secret.cipher,
    secret.max_views,
    secret.view_count,
    secret.expires_at,
    secret.burned_at,
    secret.created_at,
    secret.haslo
)
.fetch_one(&conn)
.await
{
        Ok(new_uuid) => Ok(new_uuid),
        Err(_) => Err(SecretErrors::ConnectionFailed)
    }

}
pub async fn select_secret(conn:&sqlx::Pool<sqlx::Postgres>,secret_id:Uuid) -> Result<(Vec<u8>,Vec<u8>),SecretErrors> {
    match sqlx::query!(
    r#"
    UPDATE secrets
    SET view_count = view_count + 1
    WHERE secret_id = $1
    RETURNING nonce,ciphertext,max_views,view_count,expires_at,burned_at,haslo
    "#,
    secret_id).fetch_one(conn).await {
    Ok(dane) => {
        if dane.max_views >= dane.view_count && dane.expires_at >= Utc::now() && dane.burned_at.is_none() {
            Ok((dane.nonce,dane.ciphertext))
        } else {
            burn_secret(conn,secret_id).await?;
            Err(SecretErrors::Expired)
            }
    }
    Err(_) => Err(SecretErrors::ConnectionFailed)
}

}
pub async fn burn_secret(conn:&sqlx::Pool<sqlx::Postgres>,secret_id:Uuid) -> Result<String,SecretErrors> {

    match sqlx::query_scalar!(
    "UPDATE secrets SET burned_at = $1 WHERE secret_id = $2",Utc::now(),secret_id).fetch_one(conn).await {
        Ok(_) =>  Ok(String::from("Ok")),
        Err(_) => Err(SecretErrors::ConnectionFailed)
    }


}

pub async fn retrieve_password(conn:&sqlx::Pool<sqlx::Postgres>,secret_id:Uuid) -> Result<Option<String>,SecretErrors> {
    match sqlx::query_scalar!(
    "SELECT haslo FROM secrets WHERE secret_id = $1",secret_id
).fetch_one(conn).await {
        Ok(data) => Ok(data),
        Err(_) => Err(SecretErrors::ConnectionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::encrypt;

    #[tokio::test]
    pub async fn try_connect() {
        let result = connect("secret_adm","tajnehaslo",5432,"192.168.88.6","secret_share").await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    pub async fn insert_test() {
        let conn= connect("secret_adm","tajnehaslo",5432,"192.168.88.6","secret_share").await.unwrap();

        let dummy_data: &[u8] = "lol".as_bytes();
        let (en,_) = encrypt(dummy_data,None).unwrap();
        let s = SecretLink::new(en,5,Utc::now(),None);
        let ins_res = insert_secret(conn, s).await;
        assert!(ins_res.is_ok())
    }
    #[tokio::test]
    pub async fn select_test() {
        let conn= connect("secret_adm","tajnehaslo",5432,"192.168.88.6","secret_share").await.unwrap();
        let uuid:Uuid  = Uuid::parse_str("f67c7cb0-ea3d-424f-bbe6-b96f9806bd8b").unwrap();
        assert!(select_secret(&conn, uuid).await.is_ok())

    }

}
