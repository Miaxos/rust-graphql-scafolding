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
