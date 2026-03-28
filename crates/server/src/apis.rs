use axum::{extract::{Json, Path, Query}, http::StatusCode};
use crypto::Envelope;
use db::{SecretLink, burn_secret, increment_and_return, insert_secret, select_metadata,  select_password };
use leptos::attr::selected;
use chrono::{DateTime,Utc};
use uuid::Uuid;
use crypto::authenticate;
use serde::{Serialize,Deserialize};
use db::SecretErrors;
#[derive(Serialize)]
pub struct Decrypt_data {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>

}
#[derive(Serialize)]
    pub struct MetadataResponse {
        password_required:bool,
        views_left:i32,
        expires_at: DateTime<Utc>,
        burned:bool,

    }

#[derive(Deserialize)]
    pub struct FetchEncryptReq {
    pub env: Envelope,
    pub max_views: i32,
    pub expires_at: DateTime<Utc>,
    pub haslo:Option<String>
}
#[derive(Deserialize)]
pub struct FetchDecryptReq {
    pub password: Option<String>
}
impl From<(bool,bool,i32,DateTime<Utc>)> for MetadataResponse {
    fn from((password_required,burned,views_left,expires_at): (bool,bool,i32,DateTime<Utc>)) -> Self {
        Self {password_required,views_left,expires_at,burned}
    }
}
impl From<(Vec<u8>,Vec<u8>)> for Decrypt_data {
    fn from((nonce,ciphertext): (Vec<u8>,Vec<u8>)) -> Self {
        Self {nonce,ciphertext}
        }
}


async fn encrypt_data(conn:&sqlx::Pool<sqlx::Postgres>,Json(req):Json<FetchEncryptReq>) -> Result<Json<Uuid>,(StatusCode,String)> {
    let secret = SecretLink::new(req.env,req.max_views,req.expires_at,req.haslo);
    let id = insert_secret(conn, secret)
        .await
        .map_err(|_|
            (StatusCode::INTERNAL_SERVER_ERROR,
            "database error".to_string())


        )?;
    Ok(Json(id))


}

async fn fetch_decrypt(
    conn: &sqlx::Pool<sqlx::Postgres>,
    Path(path_data): Path<String>,
    Json(req): Json<FetchDecryptReq>,
) -> Result<Json<Decrypt_data>, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    let dbpass_opt:Option<String> = select_password(conn, secret_uuid)
        .await
        .map_err(|e| match e {
            SecretErrors::Expired => (StatusCode::GONE, "data expired".to_string()),
            SecretErrors::ConnectionFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "unknown error".to_string()),
        })?;

    if let Some(dbpass) = dbpass_opt.as_deref() {
        let contest = req
            .password
            .as_deref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing password".to_string()))?;

        if !authenticate(dbpass, contest) {
            return Err((StatusCode::UNAUTHORIZED, "bad password".to_string()));
        }
    }
    let (nonce,ciphertext) = increment_and_return(conn, secret_uuid).await.map_err(|e| match e {
        SecretErrors::ConnectionFailed => (StatusCode::INTERNAL_SERVER_ERROR,"db connection failed".to_string()),
        SecretErrors::Expired => (StatusCode::BAD_REQUEST,"Expired".to_string()),
        _ => unreachable!()
    })?;
    Ok(Json(Decrypt_data { nonce, ciphertext }))
}
async fn fetch_metadata(conn:&sqlx::Pool<sqlx::Postgres>, Path(path_data): Path<String> ) -> Result<Json<MetadataResponse>,(StatusCode,String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;
    let mut data = select_metadata(conn, secret_uuid).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR,"database failed".to_string()))?;


    Ok(Json(MetadataResponse::from(data)))


}
async fn burn(
    conn: &sqlx::Pool<sqlx::Postgres>,
    Path(path_data): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    burn_secret(conn, secret_uuid)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to connect to db".to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
