use axum::extract::{Path, State};
use axum::http::StatusCode;
use tower_cookies::{Cookie, Cookies};

use crate::model::{self, Username};

use super::chat::Base;
use super::filters;
use super::{Session, Theme};

pub type ProfileFull = Result<Base<Profile>, Base<NotFound>>;

pub async fn full(session: Session, username: Path<Username>) -> Result<ProfileFull, StatusCode> {
    Ok(match content(session.clone(), username).await? {
        Ok(profile) => Ok(Base {
            theme: profile.theme,
            username: session.username,
            content: profile,
        }),
        Err(not_found) => Err(Base {
            theme: session.theme(),
            username: session.username,
            content: not_found,
        }),
    })
}

pub async fn content(
    session: Session,
    Path(username): Path<Username>,
) -> Result<Result<Profile, NotFound>, StatusCode> {
    if session.username == username {
        return Ok(Ok(Profile {
            is_me: true,
            apply_theme: false,
            password_change: Default::default(),
            username,
            theme: session.theme(),
            errors: Vec::new(),
        }));
    }

    Ok(Err(NotFound { target: username }))
}

pub async fn edit(
    mut session: Session,
    State(state): State<crate::State>,
    cookies: Cookies,
    axum::Form(mut form): axum::Form<Profile>,
) -> Result<Profile, StatusCode> {
    form.is_me = true;
    form.apply_theme = true;

    if form.password_change.new_password.is_empty() && form.username != session.username {
        form.errors.push("Password is required to change username.");
        return Ok(form);
    }

    if form.password_change.new_password != form.password_change.confirm_password {
        form.errors
            .push("New password and confirm password do not match.");
        return Ok(form);
    }

    if let Err(err) = model::User::update(
        &state.db,
        session.username,
        form.username,
        &form.password_change.old_password,
        &form.password_change.new_password,
        form.theme,
    )
    .await
    .map_err(super::internal)?
    {
        form.errors.push(err);
        return Ok(form);
    }

    session.update(form.username, form.theme.as_bytes());
    cookies.private(&state.cookie_key).add(Cookie::new(
        "session",
        serde_json::to_string(&session).unwrap(),
    ));

    Ok(form)
}

#[derive(askama::Template)]
#[template(
    source = "<div class='text-center text-error'>
        <b>{{ target }}</b> does not appear to give a f*** about this app
        so yes, this name is free
    </div>",
    ext = "html"
)]
pub struct NotFound {
    target: Username,
}

#[derive(askama::Template, serde::Deserialize)]
#[template(path = "profile.html")]
pub struct Profile {
    username: Username,
    #[serde(flatten)]
    theme: Theme,
    #[serde(flatten)]
    password_change: PasswordChange,
    #[serde(skip)]
    is_me: bool,
    #[serde(skip)]
    apply_theme: bool,
    #[serde(skip)]
    errors: Vec<&'static str>,
}

#[derive(serde::Deserialize, Default)]
pub struct PasswordChange {
    old_password: String,
    new_password: String,
    confirm_password: String,
}
