use crate::infrastructure::auth::AuthError;
use crate::infrastructure::env::Environment;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, FromRow, Debug)]
pub struct Session {
    pub key: String,
    pub csrf: String,
    pub userid: Uuid,
    pub expiry: DateTime<Utc>,
    pub invalidated: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Session {
    /**
     * Select the existing session from jwt and crsf
     */
    pub async fn new(env: &Environment, jwt: &str, csrf: &str) -> anyhow::Result<Session> {
        let claims = env.decode(jwt.to_string()).unwrap().private;
        let db = env.database();

        if claims.csrf != csrf {
            info!("Should not have landed here");
            Err(AuthError::InvalidCredentials)?
        }
        let session = sqlx::query_as!(
            Session,
            r#"
            SELECT key, csrf, userid, expiry, invalidated, created_at, updated_at
              FROM sessions
              WHERE key = $1 AND csrf = $2 AND expiry > NOW() AND NOT invalidated
              "#,
            claims.session,
            &csrf
        )
        .fetch_optional(db)
        .await?;

        Ok(session.ok_or(AuthError::InvalidCredentials)?)
    }
}
