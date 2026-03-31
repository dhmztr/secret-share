use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use crypto::Envelope;
use sqlx::{
    self,
    postgres::{PgPool,PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;
const VERSION: i16 = 1;
pub struct SecretLink {
    v: i16,
    nonce: Vec<u8>,
    cipher: Vec<u8>,
    max_views: i32,
    view_count: i32,
    expires_at: DateTime<Utc>,
    burned_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    haslo: Option<String>,
}
pub enum SecretErrors {
    Expired,
    ConnectionFailed,
    BadRequest,
    NotAuthenticated,
}
pub enum UsersErrors {
    Exists,
    DoesntExist,
    Unauthorized,
    ConnectionFailed
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
            haslo: env.password,
        }
    }
}

pub async fn connect_postgres(
    user: &str,
    password: &str,
    port: u16,
    host: &str,
    dbname: &str,
) -> Result<sqlx::Pool<sqlx::Postgres>, String> {
    let connect_options = PgConnectOptions::new()
        .password(password)
        .username(user)
        .port(port)
        .host(host)
        .database(dbname);
    PgPoolOptions::new()
        .max_connections(10)
        .connect_with(connect_options)
        .await
        .map_err(|err| format!("Error:{err}"))
}

pub async fn insert_secret(
    conn: &sqlx::Pool<sqlx::Postgres>,
    secret: SecretLink,
) -> Result<Uuid, SecretErrors> {
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
    .fetch_one(conn)
    .await
    {
        Ok(new_uuid) => Ok(new_uuid),
        Err(_) => Err(SecretErrors::ConnectionFailed),
    }
}
pub async fn select_metadata(
    conn: &sqlx::Pool<sqlx::Postgres>,
    secret_id: Uuid,
) -> Result<(bool, bool, i32, DateTime<Utc>), SecretErrors> {
    match sqlx::query!(
        r#"
    SELECT haslo,burned_at,max_views,view_count,expires_at FROM secrets WHERE secret_id = $1"#,
        secret_id
    )
    .fetch_one(conn)
    .await
    {
        Ok(dane) => {
            let pass_exists = dane.haslo.is_some();
            let burned = dane.burned_at.is_some();
            let views = (dane.max_views - dane.view_count).max(0);
            Ok((pass_exists, burned, views, dane.expires_at))
        }
        Err(_) => Err(SecretErrors::ConnectionFailed),
    }
}
pub async fn increment_and_return(
    conn: &sqlx::Pool<sqlx::Postgres>,
    secret_id: Uuid,
) -> Result<(Vec<u8>, Vec<u8>), SecretErrors> {
    let row = sqlx::query!(
        r#"
        UPDATE secrets
        SET view_count = view_count + 1
        WHERE secret_id = $1
          AND burned_at IS NULL
          AND expires_at >= NOW()
          AND view_count < max_views
        RETURNING nonce, ciphertext
        "#,
        secret_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| SecretErrors::ConnectionFailed)?;

    match row {
        Some(r) => Ok((r.nonce, r.ciphertext)),
        None => Err(SecretErrors::Expired),
    }
}
pub async fn select_password(
    conn: &sqlx::Pool<sqlx::Postgres>,
    secret_id: Uuid,
) -> Result<Option<String>, SecretErrors> {
    let row = sqlx::query!(
        r#"
    SELECT
    haslo
    FROM secrets
    WHERE secret_id = $1
    "#,
        secret_id
    )
    .fetch_optional(conn)
    .await
    .map_err(|_| SecretErrors::ConnectionFailed)?;
    match row {
        Some(r) => Ok(r.haslo),
        None => Err(SecretErrors::Expired),
    }
}
pub async fn burn_secret(
    conn: &sqlx::Pool<sqlx::Postgres>,
    secret_id: Uuid,
) -> Result<String, SecretErrors> {
    match sqlx::query_scalar!(
        "UPDATE secrets SET burned_at = $1 WHERE secret_id = $2",
        Utc::now(),
        secret_id
    )
    .fetch_one(conn)
    .await
    {
        Ok(_) => Ok(String::from("Ok")),
        Err(_) => Err(SecretErrors::ConnectionFailed),
    }
}
pub async fn create_user(conn:&PgPool,email:&str,password:&str) -> Result<Uuid,UsersErrors> {
    if email_exists(conn,email).await.unwrap() {
        return Err(UsersErrors::Exists)
    }
    let row = sqlx::query!(
    "INSERT INTO users
        (email,password_hash) VALUES
($1,$2) RETURNING id
        ",email,password
).fetch_one(conn).await;
    if let Ok(val) = row {
        Ok(val.id)
    } else {
        Err(UsersErrors::ConnectionFailed)
    }
}
pub async fn fetch_user(conn:&PgPool,email:&str) -> Result<(String,String,String,i32),UsersErrors> {
    if !email_exists(conn, email).await.unwrap() {
        Err(UsersErrors::DoesntExist)
    } else {
    let row= sqlx::query!(
    "SELECT password_hash,tier,subscription_status,quota_used FROM users WHERE email = $1",email
).fetch_one(conn).await;
        match row {
            Ok(user_data) => Ok((user_data.password_hash,user_data.tier,user_data.subscription_status,user_data.quota_used)),
            Err(_) => Err(UsersErrors::ConnectionFailed)
        }
    }
}
async fn connect_redis(address:&str) -> Result<MultiplexedConnection,Box<dyn std::error::Error>> {
    let client = redis::Client::open(address)?;
    let con = client.get_multiplexed_async_connection().await?;
    Ok(con)


}
pub async fn email_exists(conn:&PgPool,email:&str) -> Result<bool,sqlx::Error>{
    let exists = sqlx::query_scalar!(
"SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)",
email).fetch_one(conn).await?;
    Ok(exists.unwrap_or(false))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn try_connect_psql() {
        let result = connect_postgres(
            "REDACTED_USER",
            "REDACTED_PASSWORD",
            5432,
            "REDACTED_HOST",
            "secret_share",
        )
        .await;
        assert!(result.is_ok());
    }
    // #[tokio::test]
    // pub async fn try_connect_redis() {
    // let result = connect_redis("redis://REDACTED_HOST").await;
    // assert!(result.is_ok())
    // }

}

