use crate::domain::users::users::User;
use async_graphql::ID;

#[async_graphql::Object(desc = "User of the application")]
impl User {
    // TODO: Engine to do an ID relay compliant
    async fn id(&self) -> ID {
        self.id.into()
    }

    #[field(desc = "First name of the user")]
    async fn firstname(&self) -> async_graphql::FieldResult<String> {
        Ok(self.firstname.clone())
    }

    #[field(desc = "Last name of the user")]
    async fn lastname(&self) -> async_graphql::FieldResult<String> {
        Ok(self.lastname.clone())
    }

    #[field(desc = "Email of the user")]
    async fn email(&self) -> async_graphql::FieldResult<String> {
        Ok(self.email.clone())
    }
}

#[derive(async_graphql::InputObject)]
pub struct UserInput {
    #[field(desc = "First name of the user")]
    pub firstname: String,
    #[field(desc = "Last name of the user")]
    pub lastname: String,
    #[field(desc = "Email of the user")]
    pub email: String,
    #[field(desc = "Password of the user, will be stored with an encryption")]
    pub password: String,
}

#[derive(async_graphql::SimpleObject)]
pub struct UserCreatePayload {
    #[field(desc = "User created")]
    pub user: User,
}
