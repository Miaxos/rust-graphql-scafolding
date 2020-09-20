/**
 * This file is the Error management for the whole REST routes,
 * every errors will either:
 *   - Have a mapping because it's an error that'll be managed and be converted
 *     to a HTTP Error.
 *   - Won't have a mapping so will be converted into a Generic error.
 */
use crate::infrastructure::auth::AuthError;
use http_api_problem::*;
use warp::http;
use warp::{Rejection, Reply};

/**
 * Here we can turn any internal errors into meaningful responses,
 * or just let them through as internal server errors.
 */
pub fn pack(err: anyhow::Error) -> HttpApiProblem {
    // If it's a HTTPAPIPROBLEM, we return it, no problem.
    let err = match err.downcast::<HttpApiProblem>() {
        Ok(problem) => return problem,
        Err(err) => err,
    };

    if let Some(err) = err.downcast_ref::<AuthError>() {
        match err {
            AuthError::InvalidCredentials => {
                return HttpApiProblem::new("Invalid credentials.")
                    .set_status(StatusCode::BAD_REQUEST)
                    .set_detail("The passed credentials were invalid.")
            }

            AuthError::ArgonError => (),
        }
    }

    error!("internal error occurred: {:#}", err);
    HttpApiProblem::with_title_and_type_from_status(StatusCode::INTERNAL_SERVER_ERROR)
}

/**
 * Here we turn one of our rejections into the proper reply.
 */
pub async fn unpack(rejection: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(problem) = rejection.find::<HttpApiProblem>() {
        let code = problem
            .status
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);

        let reply = warp::reply::json(problem);
        let reply = warp::reply::with_status(reply, code);
        let reply = warp::reply::with_header(
            reply,
            http::header::CONTENT_TYPE,
            http_api_problem::PROBLEM_JSON_MEDIA_TYPE,
        );

        Ok(reply)
    } else {
        Err(rejection)
    }
}

/**
 * Here we turn anything that can turn into an anyhow::Error (which is any std::Error)
 * into a warp::Rejection.
 */
pub fn build<E: Into<anyhow::Error>>(err: E) -> Rejection {
    warp::reject::custom(pack(err.into()))
}
