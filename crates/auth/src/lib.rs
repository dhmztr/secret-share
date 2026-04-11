use jsonwebtoken;
use sqlx::{PgPool, types::Uuid};
use serde::{Serialize,Deserialize};
use std::{fs::{OpenOptions }, io::Write};
use argon2::{Argon2, PasswordHash,  PasswordVerifier, };
use db::{UserTiers, UsersErrors,create_user};
use rand::distr::{Alphanumeric,SampleString};
use chrono::{DateTime,Utc};


fn get_jwt_secret() -> String {
    dotenvy::dotenv().ok();

    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")

}



#[derive(Serialize,Deserialize)]
pub struct Claim {
    pub userid: String,
    pub tier: UserTiers,
    pub expires: usize

}
pub async fn create_token(conn:&PgPool,user:&str) -> Result<String,UsersErrors> {
    println!("JWT SECRET USED: {}", get_jwt_secret());
    let user_data = db::fetch_user(conn,user).await?;

    let claim = Claim {
        userid: user_data.email,
        tier: user_data.tier,
        expires: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
    };
    let token = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claim, &jsonwebtoken::EncodingKey::from_secret(get_jwt_secret().as_bytes())).unwrap();
    println!("Token: {}, len: {}",token,token.len());
    Ok(token)
    


}

pub async fn verify_token(token_to_check:String) -> Result<String,UsersErrors>{
     println!("JWT SECRET USED: {}", get_jwt_secret());

    println!("Token: {}, len: {}",token_to_check,token_to_check.len());
    let token_data = jsonwebtoken::decode::<Claim>(&token_to_check, 
        &jsonwebtoken::DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &jsonwebtoken::Validation::default()).unwrap();
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
