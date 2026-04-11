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
    pub expires: DateTime<Utc>

}
pub async fn create_token(conn:&PgPool,user:&str) -> Result<String,UsersErrors> {
    let user_data = db::fetch_user(conn,user).await?;

    let claim = Claim {
        userid: user_data.email,
        tier: user_data.tier,
        expires: Utc::now() + chrono::Duration::hours(24)
    };
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claim, &jsonwebtoken::EncodingKey::from_secret(get_jwt_secret().as_bytes())).unwrap();
    Ok(token)
    


}

pub async fn verify_token(token_to_check:String) -> Result<String,UsersErrors>{
    let token_data = jsonwebtoken::decode::<Claim>(&token_to_check, 
        &jsonwebtoken::DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &jsonwebtoken::Validation::default()).unwrap();
    if token_data.claims.expires < Utc::now() {
        return Err(UsersErrors::Expired);
    }
    Ok(token_data.claims.userid)
}

pub async fn login_user(conn:&PgPool,user:&str,password:&str) -> Result<String,UsersErrors> {
    let user_data = db::fetch_user(conn,user).await?;
    let parsed_hash = PasswordHash::new(&user_data.password_hash).unwrap();
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(),&parsed_hash) {
        Ok(_) => Ok(create_token(conn, user).await?),
        Err(_) => Err(UsersErrors::Unauthorized)
    }

}
pub async fn register_user(conn:&PgPool,email:&str,pswdhash: &str) -> Result<String,UsersErrors> {
        match create_user(conn,email,pswdhash).await {
            Ok(_) => match create_token(conn, email).await {
                Ok(val) => Ok(val),
                Err(_) => Err(UsersErrors::TokenCreationFailed)
            },
            Err(e) => Err(e) 
        }
}
