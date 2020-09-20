use crate::infrastructure::env::Environment;
use crate::infrastructure::session::Session;
use async_graphql::*;

pub struct Query;

#[Object]
impl Query {
    async fn test<'ctx>(&self, ctx: &'ctx Context<'_>) -> FieldResult<String> {
        let tr = ctx.data::<Environment>();
        let bl = ctx.data::<anyhow::Result<Session>>();
        dbg!(tr);
        dbg!(bl);
        Ok("machin".into())
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    /*
    async fn signup(&self, username: String, password: String) -> Result<bool> {
        // User signup
    }
    */

    async fn login(&self, username: String, password: String) -> FieldResult<String> {
        Ok("token".into())
    }
}
