use crate::infrastructure::auth_model::Session as SessionDB;
use crate::infrastructure::env::Environment;
use chrono::Utc;
use redis::AsyncCommands;
use std::convert::TryInto;
use uuid::Uuid;

#[derive(Clone, Debug)]
/**
 * Describe the actual session of the user:
 * - if auth is None -> Unauthentificated or authentification is outdated
 * - if auth is Some -> Authentificated and authentification is still valid
 */
pub struct Session {
    auth: Option<SessionDB>,
    env: Environment,
}

impl Session {
    pub async fn new(env: Environment, auth: Option<(String, String)>) -> anyhow::Result<Self> {
        // Get the session from the user
        // If the user is not connected anymore, return a None session
        let session = match auth {
            None => None,
            Some((jwt, crsf)) => SessionDB::new(&env, &jwt, &crsf).await.ok(),
        };

        Ok(Self { env, auth: session })
    }

    /**
     * Give use the userid for the user
     */
    pub fn userid(&self) -> Option<Uuid> {
        match &self.auth {
            Some(session) => Some(session.userid),
            None => None,
        }
    }

    /**
     * To set a value inside the redis for the session.
     */
    pub async fn set<'r>(&self, key: String, value: String) -> anyhow::Result<&'r ()> {
        let redis_co = self.env.redis();
        match self.auth.clone() {
            Some(auth) => {
                let expiry = auth.expiry.signed_duration_since(Utc::now());

                redis_co
                    .await?
                    .set_ex(
                        format!("session:{}:{}", auth.key, key),
                        bincode::serialize(&value)?,
                        expiry.num_seconds().try_into()?,
                    )
                    .await?;

                Ok(&())
            }
            _ => Err(anyhow!("Error while setting a session's key.")),
        }
    }

    /**
     * To get a value from a session inside the redis.
     */
    pub async fn get(&self, key: String) -> anyhow::Result<String> {
        let redis_co = self.env.redis();
        match self.auth.clone() {
            Some(auth) => {
                let bytes: Vec<u8> = redis_co
                    .await?
                    .get(format!("session:{}:{}", auth.key, key))
                    .await?;

                Ok(bincode::deserialize(&bytes)?)
            }
            _ => Err(anyhow!("Error while getting a session's key")),
        }
    }

    /**
     * To set an array of value from a session inside the redis.
     */
    pub async fn set_array(&self, array: Vec<(String, String)>) -> anyhow::Result<()> {
        let redis_co = self.env.redis();
        match self.auth.clone() {
            Some(auth) => {
                let expiry = auth.expiry.signed_duration_since(Utc::now());
                let mut co = redis_co.await?;
                for i in array.iter() {
                    co.set_ex(
                        format!("session:{}:{}", auth.key, &i.0),
                        bincode::serialize(&i.1)?,
                        expiry.num_seconds().try_into()?,
                    )
                    .await?;
                }
                Ok(())
            }
            _ => Err(anyhow!("blbl")),
        }
    }
}
