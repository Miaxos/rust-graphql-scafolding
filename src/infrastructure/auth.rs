/**
 * Authentification workflow
 */
/*
use crate::domains::permissions::Permission;
use crate::infrastructure::model;
use crate::infrastructure::model::Account;
use crate::infrastructure::model::Identity;
use crate::infrastructure::session::Session;
use crate::Environment;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::query;
use sqlx::query_as_unchecked;
*/
use crate::infrastructure::env::Environment;
use chrono::{DateTime, Duration, Utc};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::net::SocketAddr;
use thiserror::Error;
use warp::http;
use warp::Reply;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Login {
    pub email: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Claims {
    pub session: String,
    pub csrf: String,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("could not hash password")]
    ArgonError,
}

/*
/**
 * Handle the request for a session, checks the user exists and that the password
 * matches, if it's good -> Create a session.
 */
pub async fn request(
    env: Environment,
    req: Login,
    addr: Option<SocketAddr>,
) -> anyhow::Result<(String, String)> {
    let account: Account = query_as_unchecked!(
        Account,
        r#"
    SELECT id, password
      FROM users
      WHERE email = $1
    "#,
        &req.email
    )
    .fetch_optional(env.database())
    .await?
    .ok_or(AuthError::InvalidCredentials)?;

    info!("{}", account.id);

    let is_valid = env.verify(&account.password, &req.password).unwrap();

    if !is_valid {
        return Err(AuthError::InvalidCredentials.into());
    }

    let identity = Identity {
        fingerprint: None,
        ip: addr.map(|addr| addr.ip()),
    };

    let claims = Claims {
        session: thread_rng().sample_iter(&Alphanumeric).take(64).collect(),
        csrf: thread_rng().sample_iter(&Alphanumeric).take(64).collect(),
    };

    let csrf = claims.csrf.clone();
    let expiry: DateTime<Utc> = Utc::now() + Duration::seconds(env.session_lifetime());

    info!("session {}", &claims.session);
    info!("csrf {}", &claims.csrf);
    info!("id {}", account.id);
    info!("identity {:?}", identity);
    info!("expiry {}", expiry);

    query!(
        r#"
    INSERT INTO sessions (key, csrf, userid, identity, expiry)
      VALUES ($1, $2, $3, $4, $5)
  "#,
        &claims.session,
        &claims.csrf,
        account.id,
        json!(identity),
        expiry,
    )
    .execute(env.database())
    .await?;

    let jwt = env.clone().encode(claims, expiry);

    // Should add log to check if everythings is alright
    let session_db = session(env.clone(), &jwt.clone(), &csrf).await.ok();

    let mut session = Session::new(env.clone(), session_db).await?;

    Permission::init(env.clone(), &mut session, account.id).await;

    Ok((jwt.clone(), csrf))
}

pub async fn session(env: Environment, jwt: &str, csrf: &str) -> anyhow::Result<model::Session> {
    let claims = env.clone().decode(jwt.to_string()).unwrap().private;

    if claims.csrf != csrf {
        info!("Should not have landed here");
        Err(AuthError::InvalidCredentials)?
    }

    let session = query_as_unchecked!(
        model::Session,
        r#"
        SELECT key, csrf, userid, identity, expiry, invalidated, created_at, updated_at
          FROM sessions
          WHERE key = $1 AND csrf = $2 AND expiry > NOW() AND NOT invalidated
          "#,
        claims.session,
        &csrf
    )
    .fetch_optional(env.database())
    .await?;

    Ok(session.ok_or(AuthError::InvalidCredentials)?)
}
*/

/**
 * Handle the request for a session, checks the user exists and that the password
 * matches, if it's good -> Create a session.
 */
pub async fn request(env: Environment, req: Login) -> anyhow::Result<(String, String)> {
    // Connect to the db and get the ARGON password
    let account = sqlx::query!(
        r#"
        SELECT id, password
          FROM users
          WHERE email = $1
        "#,
        &req.email
    )
    .fetch_optional(env.database())
    .await?
    .ok_or(AuthError::InvalidCredentials)?;

    // Check if he is valid with the password inputed.
    let is_valid = env.verify(&account.password, &req.password)?;
    if !is_valid {
        // If invalid return error
        return Err(AuthError::InvalidCredentials.into());
    }

    // Generate a Claim
    let claims = Claims {
        // generate a random session id
        session: thread_rng().sample_iter(&Alphanumeric).take(64).collect(),
        // generate a random csrf token
        csrf: thread_rng().sample_iter(&Alphanumeric).take(64).collect(),
    };

    let csrf = claims.csrf.clone();
    let expiry: DateTime<Utc> = Utc::now() + Duration::seconds(env.session_lifetime());
    let jwt = env.encode(claims.clone(), expiry);

    // Create a session for the user in the DB
    sqlx::query!(
        r#"
        INSERT INTO sessions (key, csrf, userid, expiry)
          VALUES ($1, $2, $3, $4)
          "#,
        &claims.session,
        &claims.csrf,
        account.id,
        expiry,
    )
    .execute(env.database())
    .await?;

    // Initialize the permission system
    // Should add log to check if everythings is alright
    // let session_db = session(env.clone(), &jwt.clone(), &csrf).await.ok();
    // let mut session = Session::new(env.clone(), session_db).await?;
    // Permission::init(env.clone(), &mut session, account.id).await;

    Ok((jwt, csrf))
}

pub async fn filter(env: Environment, req: Login) -> anyhow::Result<impl Reply> {
    let (jwt, csrf) = request(env, req).await?;

    let reply = warp::reply::json(&serde_json::json!({ "jwt": jwt, "csrf": csrf }));
    let reply = warp::reply::with_status(reply, http::StatusCode::OK);

    let reply = warp::reply::with_header(reply, http::header::CONTENT_TYPE, "application/json");

    // Set the cookie for the user
    let reply = warp::reply::with_header(reply, http::header::SET_COOKIE, format!("jwt={}", jwt));

    Ok(reply)
}
