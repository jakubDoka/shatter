use axum::extract::State;
use axum::http::StatusCode;

use crate::model::{self, Username};

use super::chat::Base64;
use super::login;

pub async fn post(
    State(state): State<crate::State>,
    axum::extract::Form(mut form): axum::extract::Form<Form>,
) -> Result<Result<login::Form, Form>, StatusCode> {
    if form.password != form.confirm_password {
        form.errors.push("Passwords do not match.");
    }

    if let Err(err) = super::validate_username(form.username) {
        form.errors.push(err);
    }

    if !form.errors.is_empty() {
        return Ok(Err(form));
    }

    let user = model::User::new(form.username, &form.password, form.public_key.0)
        .map_err(super::internal)?;
    if !user.create(&state.db).await.map_err(super::internal)? {
        form.errors.push("Username already taken.");
        return Ok(Err(form));
    }

    Ok(Ok(login::Form::from_username(form.username)))
}

#[derive(askama::Template, Default)]
#[template(path = "login.html")]
pub struct Register {
    pub theme: super::Theme,
    pub form: Form,
}

#[derive(serde::Deserialize, askama::Template, Default)]
#[template(path = "register.form.html")]
pub struct Form {
    username: Username,
    password: String,
    confirm_password: String,
    public_key: Base64<model::PublicKey>,
    #[serde(skip)]
    errors: Vec<&'static str>,
}
