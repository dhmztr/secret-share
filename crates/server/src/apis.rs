use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use crypto::Envelope;
use crypto::authenticate;
use db::SecretErrors;
use db::{
    SecretLink, burn_secret, increment_and_return, insert_secret, select_metadata, select_password,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Serialize)]
pub struct DecryptData {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
pub struct MetadataResponse {
    password_required: bool,
    views_left: i32,
    expires_at: DateTime<Utc>,
    burned: bool,
}

/// Request body for POST /api/secrets.
/// The envelope already contains the Argon2 password hash (produced client-side)
/// in its `password` field, so there is no separate `haslo` here.
#[derive(Deserialize)]
pub struct CreateSecretReq {
    pub env: Envelope,
    pub max_views: i32,
    pub expires_at: DateTime<Utc>,
}

/// Request body for POST /api/secrets/:id/fetch.
/// The viewer sends their plaintext password; the server verifies it against
/// the stored Argon2 hash.  `None` means no password attempt.
#[derive(Deserialize)]
pub struct FetchDecryptReq {
    pub password: Option<String>,
}

impl From<(bool, bool, i32, DateTime<Utc>)> for MetadataResponse {
    fn from(
        (password_required, burned, views_left, expires_at): (bool, bool, i32, DateTime<Utc>),
    ) -> Self {
        Self {
            password_required,
            views_left,
            expires_at,
            burned,
        }
    }
}

impl From<(Vec<u8>, Vec<u8>)> for DecryptData {
    fn from((nonce, ciphertext): (Vec<u8>, Vec<u8>)) -> Self {
        Self { nonce, ciphertext }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Store a new encrypted secret and return its UUID.
#[axum::debug_handler]
pub async fn encrypt_data(
    State(pool): State<PgPool>,
    Json(req): Json<CreateSecretReq>,
) -> Result<Json<Uuid>, (StatusCode, String)> {
    let secret = SecretLink::new(req.env, req.max_views, req.expires_at);
    let id = insert_secret(&pool, secret).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error".to_string(),
        )
    })?;
    Ok(Json(id))
}

/// Verify the optional password, increment the view counter, and return the
/// raw nonce + ciphertext so the client can decrypt with the key from the URL
/// fragment.
pub async fn fetch_decrypt(
    State(pool): State<PgPool>,
    Path(path_data): Path<String>,
    Json(req): Json<FetchDecryptReq>,
) -> Result<Json<DecryptData>, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    // Check whether the secret is password-protected.
    let dbpass_opt: Option<String> =
        select_password(&pool, secret_uuid)
            .await
            .map_err(|e| match e {
                SecretErrors::Expired => (StatusCode::GONE, "secret expired".to_string()),
                SecretErrors::ConnectionFailed => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unknown error".to_string(),
                ),
            })?;

    if let Some(dbpass) = dbpass_opt.as_deref() {
        let submitted = req
            .password
            .as_deref()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "password required".to_string()))?;

        if !authenticate(dbpass, submitted) {
            return Err((StatusCode::UNAUTHORIZED, "wrong password".to_string()));
        }
    }

    let (nonce, ciphertext) =
        increment_and_return(&pool, secret_uuid)
            .await
            .map_err(|e| match e {
                SecretErrors::ConnectionFailed => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db connection failed".to_string(),
                ),
                SecretErrors::Expired => (
                    StatusCode::GONE,
                    "secret expired or view limit reached".to_string(),
                ),
                _ => unreachable!(),
            })?;

    Ok(Json(DecryptData { nonce, ciphertext }))
}

/// Return non-sensitive metadata so the client can decide whether to prompt
/// for a password before spending a view.
pub async fn fetch_metadata(
    State(pool): State<PgPool>,
    Path(path_data): Path<String>,
) -> Result<Json<MetadataResponse>, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    let data = select_metadata(&pool, secret_uuid).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error".to_string(),
        )
    })?;

    Ok(Json(MetadataResponse::from(data)))
}

/// Permanently mark the secret as burned (destroyed on demand).
pub async fn burn(
    State(pool): State<PgPool>,
    Path(path_data): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    burn_secret(&pool, secret_uuid).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to burn secret".to_string(),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}
