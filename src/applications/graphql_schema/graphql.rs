use crate::applications::users::users::{UserCreatePayload, UserInput};
use crate::domain::users::users::User;
use crate::infrastructure::env::Environment;
use crate::infrastructure::session::Session;
use async_graphql::*;

pub struct Query;

#[Object]
impl Query {
    async fn user<'ctx>(&self, ctx: &'ctx Context<'_>) -> FieldResult<User> {
        let env = ctx.data::<Environment>()?;
        let session = match ctx.data::<anyhow::Result<Session>>()? {
            Err(_) => {
                return Err(FieldError(
                    "Your session can't be acquire, something wrong is going on".into(),
                    None,
                ))
            }
            Ok(session) => session,
        };
        let mut con = env.database().acquire().await?;
        let userid = match session.userid() {
            Some(userid) => userid,
            None => {
                return Err(FieldError(
                    "You are not authentificated anymore, please authentificate again".into(),
                    None,
                ))
            }
        };

        let user = User::get_user_by_id(&mut con, userid).await?;
        Ok(user)
    }

    async fn is_authentificated<'ctx>(&self, ctx: &'ctx Context<'_>) -> FieldResult<bool> {
        let tr = ctx.data::<Environment>().unwrap();
        let bl = ctx.data::<anyhow::Result<Session>>();
        let mut transaction = tr.database().begin().await?;
        dbg!(tr);

        match bl {
            Ok(Ok(result)) => Ok(result.userid().is_some()),
            _ => Err(FieldError(
                "Fail to get the session from the context.".into(),
                None,
            )),
        }
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    #[field(desc = "Create a new user")]
    async fn user_create<'ctx>(
        &self,
        ctx: &'ctx Context<'_>,
        input: UserInput,
    ) -> FieldResult<UserCreatePayload> {
        let env = ctx.data::<Environment>()?;
        let mut con = env.database().begin().await?;
        let UserInput {
            firstname,
            lastname,
            password,
            email,
        } = input;
        let password_hashed = env.hasher(&password);

        let u =
            User::create_a_new_user(&mut con, firstname, lastname, email, password_hashed).await?;
        con.commit().await?;

        info!("User created {:?}", u);
        Ok(UserCreatePayload { user: u })
    }

    #[field(feature = "login-preview")]
    async fn login(&self, username: String, password: String) -> FieldResult<String> {
        Ok("token".into())
    }
}
