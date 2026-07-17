use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub from: String,
}

impl SmtpConfig {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            host: std::env::var("SMTP_HOST")
                .map_err(|_| "SMTP_HOST must be set".to_string())?,
            port: std::env::var("SMTP_PORT")
                .map_err(|_| "SMTP_PORT".to_string())?
                .parse()
                .map_err(|_| "SMTP_PORT invalid".to_string())?,
            user: std::env::var("SMTP_USER").map_err(|_| "SMTP_USER".to_string())?,
            pass: std::env::var("SMTP_PASS").map_err(|_| "SMTP_PASS".to_string())?,
            from: std::env::var("SMTP_FROM").map_err(|_| "SMTP_FROM".to_string())?,
        })
    }
}

pub async fn send_verification_email(
    cfg: &SmtpConfig,
    to: &str,
    code: &str,
) -> Result<(), String> {
    let email = Message::builder()
        .from(cfg.from.parse().map_err(|e| format!("bad from: {e}"))?)
        .to(to.parse().map_err(|e| format!("bad to: {e}"))?)
        .subject("Your SecretShare verification code")
        .body(format!(
            "Your verification code is: {code}\n\nIt expires in 15 minutes."
        ))
        .map_err(|e| format!("build error: {e}"))?;
    let creds = Credentials::new(cfg.user.clone(), cfg.pass.clone());
    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|e| format!("relay error: {e}"))?
            .port(cfg.port)
            .credentials(creds)
            .build();
    mailer.send(email).await.map(|_| ()).map_err(|e| format!("send error: {e}"))
}

pub fn generate_code() -> String {
    use rand::RngExt;
    let n: u32 = rand::rng().random_range(0..1_000_000);
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_returns_6_digits() {
        let code = generate_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
