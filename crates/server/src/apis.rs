use crate::AppState;
use auth::{login_user, register_user, verify_token, SmtpConfig, send_verification_email, generate_code};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use crypto::Envelope;
use crypto::authenticate;
use db::{SecretErrors, UsersErrors, redis_process_quota, set_verified, is_verified, store_verify_code, check_verify_code, VerifyOutcome};
use db::{
    SecretLink, burn_secret, increment_and_return, insert_secret, select_metadata,
    select_secret_password,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use redis::aio::MultiplexedConnection;
use std::collections::HashSet;
use std::sync::LazyLock;

// blocklist source: github.com/disposable-email-domains/disposable-email-domains
static DISPOSABLE_DOMAINS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("disposable_domains.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
});

// dummy hash to equalize timing when a secret has no password
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$iSu0lbxkeSv2K3fKi3PBQQ$NC62cyncpyVMM0liOZNVwYzxQGSHfALtO4dnPO8PLyo";

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

#[derive(Deserialize)]
pub struct CreateSecretReq {
    pub env: Envelope,
    pub max_views: i32,
    pub expires_at: DateTime<Utc>,
    pub token: String,
}

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

#[axum::debug_handler]
pub async fn encrypt_data(
    State(state): State<AppState>,
    Json(req): Json<CreateSecretReq>,
) -> Result<Json<Uuid>, (StatusCode, String)> {
    if let Ok(useremail) = verify_token(req.token).await {
        match is_verified(&state.postgres, &useremail).await {
            Ok(true) => {}
            Ok(false) => return Err((StatusCode::FORBIDDEN, "Email not verified".to_owned())),
            Err(db::UsersErrors::DoesntExist) => return Err((StatusCode::UNAUTHORIZED, "user not found".to_owned())),
            Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "verification check failed".to_owned())),
        }
        if let Ok(amount_left) = redis_process_quota(state.redis, &state.postgres, &useremail).await
        {
            if amount_left >= 0 {
                let secret = SecretLink::new(req.env, req.max_views, req.expires_at);
                let id = insert_secret(&state.postgres, secret).await.map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "database error".to_string(),
                    )
                })?;

                Ok(Json(id))
            } else {
                Err((StatusCode::UNAUTHORIZED, "No quota left :(".to_owned()))
            }
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch remaining quota".to_owned(),
            ))
        }
    } else {
        Err((StatusCode::UNAUTHORIZED, "Verification failed".to_owned()))
    }
}

pub async fn fetch_decrypt(
    State(state): State<AppState>,
    Path(path_data): Path<String>,
    Json(req): Json<FetchDecryptReq>,
) -> Result<Json<DecryptData>, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    let dbpass_opt: Option<String> = select_secret_password(&state.postgres, secret_uuid)
        .await
        .map_err(|e| match e {
            SecretErrors::Expired => {
                if req.password.is_some() {
                    let submitted = req.password.as_deref().unwrap_or("");
                    let _ = authenticate(DUMMY_HASH, submitted);
                }
                (StatusCode::GONE, "secret expired".to_string())
            }
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
    } else if req.password.is_some() {
        let submitted = req.password.as_deref().unwrap_or("");
        let _ = authenticate(DUMMY_HASH, submitted);
        return Err((StatusCode::UNAUTHORIZED, "wrong password".to_string()));
    }

    let (nonce, ciphertext) = increment_and_return(&state.postgres, secret_uuid)
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

pub async fn fetch_metadata(
    State(state): State<AppState>,
    Path(path_data): Path<String>,
) -> Result<Json<MetadataResponse>, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    let data = select_metadata(&state.postgres, secret_uuid)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error".to_string(),
            )
        })?;

    Ok(Json(MetadataResponse::from(data)))
}

pub async fn burn(
    State(state): State<AppState>,
    Path(path_data): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let secret_uuid = Uuid::parse_str(&path_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid uuid".to_string()))?;

    burn_secret(&state.postgres, secret_uuid)
        .await
        .map_err(|e| match e {
            SecretErrors::Expired => (
                StatusCode::GONE,
                "secret expired".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to burn secret".to_string(),
            ),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ResendReq {
    pub email: String,
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub email: String,
    pub passhash: String,
}

#[derive(Deserialize)]
pub struct RegisterReq {
    pub email: String,
    pub passhash: String,
}

fn validate_email(email: &str) -> Result<(), (StatusCode, String)> {
    if email.is_empty() || email.len() > 254 {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format".to_string()));
    }

    if email.chars().any(|c| c.is_whitespace()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format".to_string()));
    }

    let at_count = email.matches('@').count();
    if at_count != 1 {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format".to_string()));
    }

    let parts: Vec<&str> = email.split('@').collect();
    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() || domain.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format".to_string()));
    }

    if !domain.contains('.') {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format".to_string()));
    }

    if DISPOSABLE_DOMAINS.contains(domain.to_ascii_lowercase().as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Disposable email addresses are not allowed".to_string(),
        ));
    }

    Ok(())
}

fn spawn_verification_email(redis: MultiplexedConnection, email: String) {
    tokio::spawn(async move {
        let code = generate_code();
        if let Err(e) = store_verify_code(redis, &email, &code).await {
            eprintln!("store_verify_code failed for {email}: {e:?}");
            return;
        }
        match SmtpConfig::from_env() {
            Ok(cfg) => {
                if let Err(e) = send_verification_email(&cfg, &email, &code).await {
                    eprintln!("verification email send failed for {email}: {e}");
                }
            }
            Err(e) => eprintln!("SMTP config error: {e}"),
        }
    });
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    validate_email(&req.email)?;
    if let Ok(token) = login_user(&state.postgres, &req.email, &req.passhash).await {
        Ok((StatusCode::OK, token))
    } else {
        Err((StatusCode::UNAUTHORIZED, "Failed to login user".to_owned()))
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    validate_email(&req.email)?;
    match register_user(&state.postgres, &req.email, &req.passhash).await {
        Ok(val) => {
            spawn_verification_email(state.redis.clone(), req.email.clone());
            Ok((StatusCode::CREATED, val))
        }
        Err(e) => match e {
            UsersErrors::TokenCreationFailed => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create user token".to_string(),
            )),
            UsersErrors::Exists => Err((StatusCode::CONFLICT, "User already exists".to_owned())),
            UsersErrors::ConnectionFailed => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to connect to db".to_string(),
            )),
            _ => unreachable!(),
        },
    }
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_email(&req.email)?;
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid code format".to_owned()));
    }
    match check_verify_code(state.redis.clone(), &req.email, &req.code).await {
        Ok(VerifyOutcome::Ok) => {
            set_verified(&state.postgres, &req.email)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error".to_owned()))?;
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(VerifyOutcome::WrongCode) => {
            Err((StatusCode::UNAUTHORIZED, "Incorrect code".to_owned()))
        }
        Ok(VerifyOutcome::TooManyAttempts) => {
            Err((StatusCode::TOO_MANY_REQUESTS, "Too many attempts".to_owned()))
        }
        Ok(VerifyOutcome::Expired) => Err((StatusCode::GONE, "Code expired".to_owned())),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "verification failed".to_owned(),
        )),
    }
}

pub async fn resend_code(
    State(state): State<AppState>,
    Json(req): Json<ResendReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_email(&req.email)?;
    match is_verified(&state.postgres, &req.email).await {
        Ok(false) => {
            spawn_verification_email(state.redis.clone(), req.email.clone());
        }
        Ok(true) => {}
        Err(UsersErrors::DoesntExist) => {}
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_owned())),
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::validate_email;

    #[test]
    fn accepts_normal_email() {
        assert!(validate_email("user@gmail.com").is_ok());
    }

    #[test]
    fn rejects_disposable_email() {
        assert!(validate_email("throwaway@mailinator.com").is_err());
        assert!(validate_email("x@guerrillamail.com").is_err());
    }

    #[test]
    fn disposable_check_is_case_insensitive() {
        assert!(validate_email("x@MailInator.CoM").is_err());
    }
}
