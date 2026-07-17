use chrono::{DateTime, Utc};
use crypto::Envelope;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, ErrorKind, RedisError};
use serde::{Deserialize, Serialize};
use sqlx::{
    self,
    postgres::{PgConnectOptions, PgPool, PgPoolOptions},
};
use subtle::ConstantTimeEq;
#[derive(Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub password_hash: String,
    pub tier: UserTiers,
    pub quota_left: i32,
}
use uuid::Uuid;
const VERSION: i16 = 1;

const VERIFY_CODE_PREFIX: &str = "verify:code:";
const VERIFY_ATTEMPTS_PREFIX: &str = "verify:attempts:";
const VERIFY_TTL_SECS: i64 = 900;
const VERIFY_MAX_ATTEMPTS: i64 = 5;

pub enum VerifyOutcome {
    Ok,
    WrongCode,
    TooManyAttempts,
    Expired,
}

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
#[derive(Deserialize, Serialize, Debug, sqlx::Type)]
#[sqlx(type_name = "user_tier", rename_all = "lowercase")]
pub enum UserTiers {
    Free,
    Premium,
    Enterprise,
}
pub enum SecretErrors {
    Expired,
    ConnectionFailed,
    BadRequest,
    NotAuthenticated,
}
#[derive(Debug)]
pub enum UsersErrors {
    Exists,
    DoesntExist,
    Unauthorized,
    ConnectionFailed,
    TokenCreationFailed,
    Expired,
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
impl From<&str> for UserTiers {
    fn from(value: &str) -> Self {
        match value {
            "Free" => UserTiers::Free,
            "Premium" => UserTiers::Premium,
            "Enterprise" => UserTiers::Enterprise,
            _ => unreachable!(),
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

pub async fn connect_redis(
    address: &str,
) -> Result<MultiplexedConnection, Box<dyn std::error::Error>> {
    let client = redis::Client::open(address)?;
    let con = client.get_multiplexed_async_connection().await?;
    Ok(con)
}
pub async fn redis_process_quota(
    mut conn: MultiplexedConnection,
    pg: &PgPool,
    email: &str,
) -> Result<i32, UsersErrors> {
    let exists: bool = conn
        .exists(email)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)?;
    if !exists {
        let user = fetch_user(pg, email).await?;
        let _: bool = conn
            .set_nx(email, user.quota_left)
            .await
            .map_err(|_| UsersErrors::ConnectionFailed)?;
    }
    conn.decr(email, 1)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)
}

pub async fn redis_set_quota_data(
    mut conn: (&PgPool, MultiplexedConnection),
    email: &str,
) -> Result<i32, UsersErrors> {
    let user = fetch_user(conn.0, email).await?;
    conn.1
        .set::<&String, i32, ()>(&user.email, user.quota_left)
        .await
        .map_err(|e| match e {
            _ => UsersErrors::ConnectionFailed,
        })?;
    Ok(user.quota_left)
}

pub async fn store_verify_code(
    mut conn: MultiplexedConnection,
    email: &str,
    code: &str,
) -> Result<(), UsersErrors> {
    let key = format!("{VERIFY_CODE_PREFIX}{email}");
    let akey = format!("{VERIFY_ATTEMPTS_PREFIX}{email}");
    conn.set_ex::<_, _, ()>(&key, code, VERIFY_TTL_SECS as u64)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)?;
    conn.set_ex::<_, _, ()>(&akey, 0, VERIFY_TTL_SECS as u64)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)?;
    Ok(())
}

pub async fn check_verify_code(
    mut conn: MultiplexedConnection,
    email: &str,
    submitted: &str,
) -> Result<VerifyOutcome, UsersErrors> {
    let key = format!("{VERIFY_CODE_PREFIX}{email}");
    let akey = format!("{VERIFY_ATTEMPTS_PREFIX}{email}");
    let attempts: i64 = conn
        .incr(&akey, 1)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)?;
    let _: bool = conn
        .expire(&akey, VERIFY_TTL_SECS)
        .await
        .unwrap_or(false);
    if attempts > VERIFY_MAX_ATTEMPTS {
        return Ok(VerifyOutcome::TooManyAttempts);
    }
    let stored: Option<String> = conn
        .get(&key)
        .await
        .map_err(|_| UsersErrors::ConnectionFailed)?;
    match stored {
        None => Ok(VerifyOutcome::Expired),
        Some(code) => {
            if code.as_bytes().ct_eq(submitted.as_bytes()).into() {
                let _: () = conn.del::<_, ()>(&[&key, &akey]).await.unwrap_or(());
                Ok(VerifyOutcome::Ok)
            } else {
                Ok(VerifyOutcome::WrongCode)
            }
        }
    }
}
pub async fn redis_synchronize_quota(
    mut conn: (&PgPool, MultiplexedConnection),
) -> Result<(), RedisError> {
    let mut conn_get = conn.1.clone();
    let mut redisiter: redis::AsyncIter<String> = conn.1.scan().await?;
    while let Some(key) = redisiter.next_item().await {
        let Ok(key_string) = key else { continue; };
        if key_string.starts_with("verify:") {
            continue;
        }
        let val: Option<i32> = conn_get.get(&key_string).await?;
        match val {
            Some(numer) => {
                sqlx::query!(
                    "UPDATE users SET quota_left = $1 WHERE email = $2",
                    numer,
                    key_string
                )
                .execute(conn.0)
                .await
                .map_err(|e| {
                    eprintln!("SQLx error: {}", e);

                    RedisError::from((
                        ErrorKind::Server(redis::ServerErrorKind::ResponseError),
                        "Failed to update database",
                    ))
                })?;
            }

            None => continue,
        };
    }
    Ok(())
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
pub async fn select_secret_password(
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
    let result = sqlx::query("UPDATE secrets SET burned_at = $1 WHERE secret_id = $2")
        .bind(Utc::now())
        .bind(secret_id)
        .execute(conn)
        .await
        .map_err(|_| SecretErrors::ConnectionFailed)?;

    if result.rows_affected() == 0 {
        Err(SecretErrors::Expired)
    } else {
        Ok(String::from("Ok"))
    }
}

pub async fn create_user(conn: &PgPool, email: &str, password: &str) -> Result<(), UsersErrors> {
    if email_exists(conn, email).await.map_err(|_| UsersErrors::ConnectionFailed)? {
        return Err(UsersErrors::Exists);
    }
    let row = sqlx::query!(
        "INSERT INTO users
        (email,password_hash,tier ,quota_left) VALUES
($1,$2,$3,$4) RETURNING id
        ",
        email,
        password,
        UserTiers::Free as UserTiers,
        5
    )
    .fetch_one(conn)
    .await;
    match row {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Error! : {:#?}", e);
            Err(UsersErrors::ConnectionFailed)
        }
    }
}
pub async fn fetch_user(conn: &PgPool, email: &str) -> Result<User, UsersErrors> {
    if !email_exists(conn, email).await.map_err(|_| UsersErrors::ConnectionFailed)? {
        Err(UsersErrors::DoesntExist)
    } else {
        let row= sqlx::query!(
    r#"SELECT password_hash,tier as "tier: UserTiers",quota_left FROM users WHERE email = $1"#,email
).fetch_one(conn).await;
        match row {
            Ok(user_data) => Ok(User {
                email: email.to_string(),
                password_hash: user_data.password_hash,
                tier: UserTiers::from(user_data.tier),
                quota_left: user_data.quota_left,
            }),
            Err(_) => Err(UsersErrors::ConnectionFailed),
        }
    }
}

pub async fn email_exists(conn: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", email)
        .fetch_one(conn)
        .await?;
    Ok(exists.unwrap_or(false))
}

pub async fn set_verified(conn: &PgPool, email: &str) -> Result<(), UsersErrors> {
    sqlx::query("UPDATE users SET verified_at = NOW() WHERE email = $1")
        .bind(email)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(|_| UsersErrors::ConnectionFailed)
}

pub async fn is_verified(conn: &PgPool, email: &str) -> Result<bool, UsersErrors> {
    let row: Option<bool> = sqlx::query_scalar(
        "SELECT verified_at IS NOT NULL FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(conn)
    .await
    .map_err(|_| UsersErrors::ConnectionFailed)?;
    row.ok_or(UsersErrors::DoesntExist)
}
pub async fn fetch_password(conn: &PgPool, email: &str) -> Result<String, sqlx::Error> {
    let passwd = sqlx::query_scalar!("SELECT password_hash FROM users WHERE email=$1", email)
        .fetch_one(conn)
        .await;
    passwd
}
#[cfg(test)]
mod tests {
    use argon2::{
        Argon2, PasswordHasher,
        password_hash::{SaltString, rand_core::OsRng},
    };

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
    #[tokio::test]
    pub async fn try_connect_redis() {
        let result = connect_redis("redis://REDACTED_HOST/").await;
        match result {
            Ok(_) => assert!(result.is_ok()),
            Err(ref r) => {
                eprintln!("error!!: {}", r);
                assert!(result.is_ok())
            }
        }
    }
    #[tokio::test]
    pub async fn try_create() {
        let result = connect_postgres(
            "REDACTED_USER",
            "REDACTED_PASSWORD",
            5432,
            "REDACTED_HOST",
            "secret_share",
        )
        .await
        .unwrap();
        let argon2 = Argon2::default();
        let passwd = argon2
            .hash_password(b"123", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();

        let rslt = create_user(&result, "test@adres.pl", &passwd).await;
        match rslt {
            Ok(_) => assert!(rslt.is_ok()),
            Err(ref e) => eprintln!("Error!: {:#?}", e),
        }
        assert!(rslt.is_ok())
    }
}
