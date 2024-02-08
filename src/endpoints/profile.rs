use arrayvec::ArrayVec;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::AppendHeaders;
use tower_cookies::{Cookie, Cookies};

use crate::model::{self, Username};

use super::chat::{Base, Base64};
use super::filters;
use super::{Session, Theme};

pub type ProfileFull = Result<Base<Profile>, Base<NotFound>>;

pub async fn full(
    session: Session,
    state: State<crate::State>,
    username: Path<Username>,
) -> Result<ProfileFull, StatusCode> {
    Ok(match content(session.clone(), state, username).await? {
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
    State(state): State<crate::State>,
    Path(username): Path<Username>,
) -> Result<Result<Profile, NotFound>, StatusCode> {
    if session.username == username {
        return Ok(Ok(Profile {
            is_me: true,
            apply_theme: false,
            name_changed: false,
            public_key: Default::default(),
            password_change: Default::default(),
            username,
            theme: session.theme(),
            errors: Vec::new(),
        }));
    }

    let Some(user) = model::User::get(&state.db, username)
        .await
        .map_err(super::internal)?
    else {
        return Ok(Err(NotFound { target: username }));
    };

    Ok(Ok(Profile {
        is_me: false,
        apply_theme: false,
        name_changed: false,
        public_key: Default::default(),
        password_change: Default::default(),
        username,
        theme: user.theme.0.to_theme(),
        errors: Vec::new(),
    }))
}
#[axum::debug_handler]
pub async fn edit(
    mut session: Session,
    State(state): State<crate::State>,
    cookies: Cookies,
    axum::Form(mut form): axum::Form<Profile>,
) -> Result<(AppendHeaders<ArrayVec<(&'static str, String), 1>>, Profile), StatusCode> {
    let empty = AppendHeaders(ArrayVec::new());

    form.is_me = true;
    form.apply_theme = true;
    form.name_changed = form.username != session.username;

    if form.password_change.new_password.is_empty() && form.name_changed {
        form.errors.push("Password is required to change username.");
        return Ok((empty, form));
    }

    if form.password_change.new_password != form.password_change.confirm_password {
        form.errors
            .push("New password and confirm password do not match.");
        return Ok((empty, form));
    }

    if let Err(err) = model::User::update(
        &state.db,
        session.username,
        form.username,
        &form.password_change.old_password,
        &form.password_change.new_password,
        form.theme,
        form.public_key.0,
    )
    .await
    .map_err(super::internal)?
    {
        form.errors.push(err);
        return Ok((empty, form));
    }

    session.update(form.username, form.theme.as_bytes());
    cookies.private(&state.cookie_key).add(Cookie::new(
        "session",
        serde_json::to_string(&session).unwrap(),
    ));

    Ok((
        AppendHeaders([("HX-Replace-Url", format!("/profile/{}/", form.username))].into()),
        form,
    ))
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
    #[serde(default)]
    public_key: Base64<model::PublicKey>,
    #[serde(flatten)]
    theme: Theme,
    #[serde(flatten)]
    password_change: PasswordChange,
    #[serde(skip)]
    name_changed: bool,
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
