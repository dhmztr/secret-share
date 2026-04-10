use jsonwebtoken;
use sqlx::{PgPool, types::Uuid};
use serde::{Serialize,Deserialize};
use std::{fs::{OpenOptions }, io::Write};
use argon2::{Argon2, PasswordHash,  PasswordVerifier, };
use db::{UserTiers, UsersErrors,create_user};
use rand::distr::{Alphanumeric,SampleString};
use chrono::{DateTime,Utc};

fn get_jwt_secret() -> String {

    match std::env::var("JWT_SECRET")  {
        Ok(val) => val,
        Err(_) => {
            let mut f = OpenOptions::new().read(true).write(true).create(true).open("../.env").unwrap();
            let temp_val = Alphanumeric.sample_string(&mut rand::rng(), 64);
            let fmtstring = format!("JWT_SECRET:\"{temp_val}\"");
            f.write_all(fmtstring.as_bytes()).unwrap();
            f.flush().unwrap();
            temp_val
        }
    }
}



#[derive(Serialize,Deserialize)]
pub struct Claim {
    pub userid: String,
    pub tier: UserTiers,
    pub quota_used:i32,
    pub expires: DateTime<Utc>

}
pub async fn create_token(conn:&PgPool,user:&str) -> Result<String,UsersErrors> {
    let user_data = db::fetch_user(conn,user).await?;

    let claim = Claim {
        userid: user_data.email,
        tier: user_data.tier,
        quota_used: user_data.quota_used,
        expires: Utc::now() + chrono::Duration::hours(24)
    };
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claim, &jsonwebtoken::EncodingKey::from_secret(get_jwt_secret().as_bytes())).unwrap();
    Ok(token)
    


}

pub async fn verify_token(token_to_check:Claim) -> Result<bool,UsersErrors>{
    let token_data = jsonwebtoken::decode::<Claim>(&token_to_check.userid, 
        &jsonwebtoken::DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &jsonwebtoken::Validation::default()).unwrap();
    if token_data.claims.expires < Utc::now() {
        return Ok(false);
    }
    Ok(true)
}
pub async fn fetch_quota_from_token(token_to_check:String) -> Result<i32,UsersErrors> {
    let token_data = jsonwebtoken::decode::<Claim>(&token_to_check, &jsonwebtoken::DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &jsonwebtoken::Validation::default()).unwrap();
    Ok(token_data.claims.quota_used)
}

pub async fn verify_user(conn:&PgPool,user:&str,password:&str) -> Result<String,UsersErrors> {
    let user_data = db::fetch_user(conn,user).await?;
    let parsed_hash = PasswordHash::new(&user_data.password_hash).unwrap();
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(),&parsed_hash) {
        Ok(_) => Ok(create_token(conn, user).await?),
        Err(_) => Err(UsersErrors::Unauthorized)
    }

}
pub async fn register_user(conn:&PgPool,user:&str,pswdhash: &str) -> Result<Uuid,UsersErrors> {
    create_user(conn,user,pswdhash).await
   
    
}
