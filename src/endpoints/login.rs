use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use tower_cookies::{Cookie, Cookies};

use crate::endpoints::Session;
use crate::model::{User, Username};

use super::{HtmxRedirect, Theme};

#[axum::debug_handler]
pub async fn post(
    cookie: Cookies,
    State(state): State<crate::State>,
    axum::Form(mut form): axum::Form<Form>,
) -> Result<Result<HtmxRedirect, Form>, StatusCode> {
    if let Err(err) = super::validate_username(&form.username) {
        form.errors.push(err);
    }

    if form.is_invalid() {
        return Ok(Err(form));
    }

    let user = User::login(&state.db, &form.username, &form.password)
        .await
        .map_err(super::internal)?;

    let Some(user) = user else {
        form.errors.push("Invalid username or password.");
        return Ok(Err(form));
    };

    let session = Session::new(user.username, Duration::from_secs(60 * 60));

    cookie.private(&state.cookie_key).add(Cookie::new(
        "session",
        serde_json::to_string(&session).unwrap(),
    ));

    Ok(Ok(HtmxRedirect("/")))
}

#[derive(askama::Template, Default)]
#[template(path = "login.html")]
pub struct Login {
    pub theme: Theme,
    pub form: Form,
}

#[derive(askama::Template)]
#[template(path = "login.form.html")]
#[derive(serde::Deserialize, Default)]
pub struct Form {
    username: Username,
    password: String,
    #[serde(skip)]
    errors: Vec<&'static str>,
}

impl Form {
    fn is_invalid(&mut self) -> bool {
        !self.errors.is_empty()
    }

    pub fn from_username(username: Username) -> Self {
        Self {
            username,
            ..Default::default()
        }
    }
}
