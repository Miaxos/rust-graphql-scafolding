use chrono::{DateTime, Utc};
use sqlx::query_as;
use uuid::Uuid;

/**
 * An User entity
 * It represent data from the database but shouldn't always be 1-1 to the DB model.
 */
#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub firstname: String,
    pub lastname: String,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /**
     * Create a user in the database
     * Should return the user entity created
     */
    pub async fn create_a_new_user(
        conn: &mut sqlx::PgConnection,
        firstname: String,
        lastname: String,
        email: String,
        password_encoded: String,
    ) -> anyhow::Result<User> {
        let user = query_as!(
            User,
            r#"INSERT INTO users (
                firstname,
                lastname,
                password,
                email
            ) VALUES ($1, $2, $3, $4) RETURNING id, firstname, lastname, email, password, created_at, updated_at
            "#,
            firstname,
            lastname,
            password_encoded,
            email,
        )
        .fetch_one(&mut *conn)
        .await?;

        Ok(user)
    }
}

impl User {
    pub async fn get_user_by_id(pool: &mut sqlx::PgConnection, id: Uuid) -> anyhow::Result<User> {
        let user = query_as!(
            User,
            r#"
            SELECT * from users
            WHERE id = $1
            LIMIT 1
            "#,
            id
        )
        .fetch_one(&mut *pool)
        .await?;
        Ok(user)
    }
}
