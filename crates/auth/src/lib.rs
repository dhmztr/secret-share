use jsonwebtoken;
use serde::{Serialize,Deserialize};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString,rand_core::OsRng}};
use db::UserTiers;
use std::sync::OnceLock;
use rand::distr::{Alphanumeric,SampleString};
static SALT: OnceLock<String> = OnceLock::new();

fn get_salt() -> String {
    std::env::var("JWT_SECRET").expect("JWT_SECRET_NOT_SET")
}



#[derive(Serialize,Deserialize)]
pub struct Claim {
    userid: String,
    tier: UserTiers,
    quota_used:i32

}

pub async fn create_token(user:String) {
    


}

pub async fn verify_token(token_to_check:Claim) {


}
