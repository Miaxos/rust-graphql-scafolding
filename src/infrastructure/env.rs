use crate::infrastructure::auth;
use argonautica::{Hasher, Verifier};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{RegisteredHeader, Secret};
use biscuit::ClaimsSet;
use biscuit::RegisteredClaims;
use biscuit::SingleOrMultiple;
use biscuit::Timestamp;
use biscuit::JWT;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::str::FromStr;
use std::time::Duration;

/**
 * Environment is the main structure of the application, it should be availaible
 * everywhere, it's our dependency injection
 */
#[derive(Debug, Clone)]
pub struct Environment {
    pub pool: PgPool,
    // JWT
    signing_secret: String,
    // Argon
    argon_secret_key: String,
    // Session lifetime, should be defined to 7 days
    session_lifetime: i64,
    // Redis client,
    redis_client: redis::Client,
}

impl Environment {
    /**
     * Create a new environment.
     */
    pub async fn new(
        db_url: &String,
        pool_size: u32,
        session_lifetime: i64,
        argon_secret_key: &String,
        signing_secret: &String,
        redis_url: &String,
    ) -> anyhow::Result<Environment> {
        // Create a connection pool
        let pool = PgPoolOptions::new()
            .connect_timeout(Duration::from_secs(10))
            .min_connections(5)
            .max_connections(pool_size)
            .connect(db_url)
            .await?;

        let redis_client = redis::Client::open(redis_url.to_string())?;

        Ok(Environment {
            pool,
            session_lifetime,
            argon_secret_key: argon_secret_key.clone(),
            signing_secret: signing_secret.clone(),
            redis_client,
        })
    }

    /**
     * Get the database pool
     */
    pub fn database(&self) -> &PgPool {
        &self.pool
    }

    /**
     * Get the session lifetime in seconds
     */
    pub fn session_lifetime(&self) -> i64 {
        self.session_lifetime
    }

    /**
     * One of the struct used for verify a password
     */
    pub fn verify(&self, hash: &str, password: &str) -> Result<bool, auth::AuthError> {
        Verifier::default()
            .with_secret_key(&self.argon_secret_key)
            .with_hash(hash)
            .with_password(password)
            .verify()
            .or(Err(auth::AuthError::ArgonError))
    }

    /**
     * One of the struct used for create a hash of a password
     */
    pub fn hasher(&self, password: &str) -> String {
        Hasher::default()
            .with_secret_key(&self.argon_secret_key)
            .with_password(password)
            .hash()
            .unwrap()
    }

    /**
     * Encode a Claims to a JWT
     */
    pub fn encode(&self, private_claims: auth::Claims, expiry: DateTime<Utc>) -> String {
        let signing_secret = Secret::Bytes(self.signing_secret.clone().into_bytes());
        let expected_claims = ClaimsSet::<auth::Claims> {
            registered: RegisteredClaims {
                issuer: Some(FromStr::from_str("https://todo.io").unwrap()),
                subject: Some(FromStr::from_str("TODO").unwrap()),
                audience: Some(SingleOrMultiple::Single(
                    FromStr::from_str("htts://todo.io").unwrap(),
                )),
                expiry: Some(Timestamp::from(expiry)),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: private_claims,
        };

        let token = JWT::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::HS256,
                ..Default::default()
            }),
            expected_claims.clone(),
        );

        let token = token.into_encoded(&signing_secret).unwrap();
        let token = token.unwrap_encoded().to_string();
        token
    }

    /**
     * Get a connection for the redis
     */
    pub async fn redis(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        self.redis_client.get_multiplexed_tokio_connection().await
    }

    /*


    /**
     * Decode a JWT to a Claims
     */
    pub fn decode(&self, jwt: String) -> Result<ClaimsSet<auth::Claims>, biscuit::errors::Error> {
        let signing_secret = Secret::Bytes(self.signing_secret.clone().into_bytes());
        let token = JWT::<auth::Claims, biscuit::Empty>::new_encoded(&jwt);
        let token = token
            .into_decoded(&signing_secret, SignatureAlgorithm::HS256)
            // TODO: Remove ce unwrap et le gérer mieux -> panic du thread quand on
            // file un header auth daubé
            .unwrap();

        token.payload().map(|x| x.clone())
    }

    */
}
