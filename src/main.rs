#[macro_use]
extern crate log;
#[macro_use]
extern crate anyhow;

mod applications;
mod infrastructure;

use applications::graphql_schema::graphql::{Mutation, Query};
use async_graphql::extensions::Logger as GQLLogger;
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql::{EmptySubscription, Schema};
use dotenv::dotenv;
use infrastructure::auth;
use infrastructure::env::Environment;
use infrastructure::logger::ConfigLogger;
use infrastructure::problem;
use infrastructure::session::Session;
use log::LevelFilter;
use std::env;

use warp::{http::StatusCode, Filter};

#[derive(serde::Deserialize, Debug)]
struct QueryLogin {
    csrf: Option<String>,
}

#[tokio::main(max_threads = 10_000)]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    let log_level = match env::var("RUST_LOG").ok() {
        Some(level) => match level.as_ref() {
            "ERROR" => LevelFilter::Error,
            "WARN" => LevelFilter::Warn,
            "INFO" => LevelFilter::Info,
            "DEBUG" => LevelFilter::Debug,
            "TRACE" => LevelFilter::Trace,
            _ => LevelFilter::Off,
        },
        None => LevelFilter::Info,
    };

    // Start logger
    let _logger = ConfigLogger::init(log_level);
    info!("Starting Graphql server");

    info!("Start reading env variables");
    let db_url = env::var("DATABASE_URL").expect("No DATABASE_URL provided in env variables.");
    let pool_size: u32 = env::var("DATABASE_POOL")
        .ok()
        .and_then(|x| x.parse().ok())
        .expect("No DATABASE_POOL provided in env variable.");
    let signing_secret = env::var("JWT_SECRET").expect("No JWT_SECRET in env variable.");
    let argon_secret_key =
        env::var("ARGON_SECRET_KEY").expect("No ARGON_SECRET_KEY in env variable.");
    let session_lifetime: i64 = env::var("SESSION_LIFETIME")
        .ok()
        .and_then(|x| x.parse().ok())
        .expect("No SESSION_LIFETIME in env variable.");
    let redis_url = env::var("REDIS_URL").expect("No REDIS_URL in env variable.");

    let env = Environment::new(
        &db_url,
        pool_size,
        session_lifetime,
        &argon_secret_key,
        &signing_secret,
        &redis_url,
    )
    .await?;

    let env_schema = env.clone();

    let env_filter = warp::any().map(move || env.clone());

    info!("Starting connection to DB");

    let cors = warp::cors()
        .allow_methods(vec!["GET", "POST"])
        .allow_header("content-type")
        .allow_header("authorization")
        .allow_any_origin()
        .build();

    let log = warp::log("INFO");

    let health_route = warp::path!("health").map(|| StatusCode::OK);

    // TODO: Add health check based on DB connection
    // https://blog.logrocket.com/create-an-async-crud-web-service-in-rust-with-warp/
    let routes = health_route.with(warp::cors().allow_any_origin());

    /*
     * Auth filer used to login.
     */
    let auth = warp::post()
        .and(warp::path("auth"))
        .and(env_filter.clone())
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json())
        .and_then(|env: Environment, req: auth::Login| async move {
            auth::filter(env, req).await.map_err(problem::build)
        });

    let schema = Schema::build(Query, Mutation, EmptySubscription)
        .data(env_schema.clone())
        // .extension(ApolloTracing::default) // Enable ApolloTracing extension
        .extension(GQLLogger::default)
        .finish();

    /*
     * Auth filter to check if a user is logged in.
     */
    let auth_filter = warp::header::optional("authorization")
        .or(warp::cookie::optional("jwt"))
        .unify()
        .and(warp::query())
        .and(env_filter.clone())
        .and_then(
            |jwt: Option<String>, query: QueryLogin, env: Environment| async move {
                // Should craft a session here if the user is logged In
                if jwt.is_none() && query.csrf.is_none() {
                    return Ok(Session::new(env, None).await);
                }

                if jwt.is_none() || query.csrf.is_none() {
                    return Err(problem::build(auth::AuthError::InvalidCredentials));
                }

                Ok(Session::new(env, Some((jwt.unwrap(), query.csrf.unwrap()))).await)
            },
        );

    let graphql_post = auth_filter
        .and(async_graphql_warp::graphql(schema))
        .and_then(
            |auths: Result<Session, _>,
             (schema, request): (
                Schema<Query, Mutation, EmptySubscription>,
                async_graphql::Request,
            )| async move {
                Ok::<_, std::convert::Infallible>(async_graphql_warp::GQLResponse::from(
                    // Store the session inside the request
                    schema.execute(request.data(auths)).await,
                ))
            },
        );

    let graphql_playground = warp::get().and(warp::path("graphqli")).map(|| {
        warp::http::Response::builder()
            .header("content-type", "text/html")
            .body(playground_source(GraphQLPlaygroundConfig::new("/graphqli")))
    });

    warp::serve(
        routes
            .or(auth)
            .or(graphql_post)
            .or(graphql_playground)
            .with(log)
            .with(cors)
            .recover(problem::unpack),
    )
    .run(([0, 0, 0, 0], 8080))
    .await;

    Ok(())
}
