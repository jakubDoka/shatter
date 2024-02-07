use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Redirect;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::model::Username;

use self::chat::FullChatList;

pub mod chat;
pub mod files;
pub mod login;
pub mod register;

pub async fn index(
    cookies: Cookies,
    State(state): State<crate::State>,
) -> Result<Result<FullChatList, login::Login>, StatusCode> {
    let Some(session) = Session::extract_from_cookies(&cookies, &state) else {
        return Ok(Err(Default::default()));
    };

    Ok(Ok(chat::full_list(State(state), session).await?))
}

fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters long.");
    }

    if username.len() > 32 {
        return Err("Username must be at most 32 characters long.");
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub username: Username,
    pub valid_until: u64,
}

impl Session {
    pub fn new(username: Username, valid_for: std::time::Duration) -> Self {
        Self {
            username,
            valid_until: std::time::SystemTime::now()
                .checked_add(valid_for)
                .expect("valid time")
                .duration_since(std::time::UNIX_EPOCH)
                .expect("duration since")
                .as_secs(),
        }
    }

    pub fn extract_from_cookies(cookies: &Cookies, state: &impl CookieKey) -> Option<Self> {
        cookies
            .private(state.cookie_key())
            .get("session")
            .and_then(|cookie| serde_json::from_str(cookie.value()).ok())
    }
}

#[axum::async_trait]
impl<S: Send + Sync + CookieKey> FromRequestParts<S> for Session {
    type Rejection = Redirect;

    /// Perform the extraction.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let error = Redirect::to("/login/");

        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| error.clone())?;

        let session: Self = Self::extract_from_cookies(&cookies, state).ok_or(error.clone())?;

        if session.valid_until
            < std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        {
            return Err(error);
        }

        Ok(session)
    }
}

pub trait CookieKey {
    fn cookie_key(&self) -> &tower_cookies::Key;
}

impl CookieKey for crate::State {
    fn cookie_key(&self) -> &tower_cookies::Key {
        &self.cookie_key
    }
}

#[derive(askama::Template)]
#[template(path = "theme.txt")]
pub struct Theme {
    pub primary_color: u32,
    pub secondary_color: u32,
    pub highlight_color: u32,
    pub font_color: u32,
    pub error_color: u32,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            primary_color: 0x1E1E1E,
            secondary_color: 0x494949,
            highlight_color: 0x87DF6D,
            font_color: 0xDCDCDC,
            error_color: 0xFF0000,
        }
    }
}

mod filters {
    pub fn css_color(input: &u32) -> askama::Result<String> {
        Ok(format!("#{input:x}"))
    }
}

fn internal(err: anyhow::Error) -> StatusCode {
    log::error!("ISE: {:#}", err);
    StatusCode::INTERNAL_SERVER_ERROR
}

pub struct HtmxRedirect(&'static str);

impl axum::response::IntoResponse for HtmxRedirect {
    fn into_response(self) -> axum::response::Response {
        axum::response::Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("HX-Redirect", axum::http::HeaderValue::from_static(self.0))
            .body(Default::default())
            .unwrap()
    }
}

//macro_rules! enum_template {
//    (
//        enum $name:ident {$(
//            $variant:ident($content:ty)
//        ),* $(,)?}
//    ) => {
//        pub enum $name {$(
//            $variant($content),
//        )*}
//
//        impl Template for $name {
//            fn render_into(&self, writer: &mut (impl std::fmt::Write + ?Sized)) -> askama::Result<()> {
//                match self {$(
//                    Self::$variant(content) => content.render_into(writer),
//                )*}
//            }
//
//            const EXTENSION: Option<&'static str> = Some("html");
//            const SIZE_HINT: usize = 0 $(.max(<$content as Template>::SIZE_HINT))*.max(0);
//            const MIME_TYPE: &'static str = "text/html";
//        }
//
//        impl fmt::Display for $name {
//            #[inline]
//            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//                self.render_into(f).map_err(|_| fmt::Error {})
//            }
//        }
//    };
//}
//
//enum_template! {
//    enum PageContent {
//        Chat(chat::ChatList),
//        ChatRoom(chat::Room),
//        NotFoundRoom(chat::RoomNotFound),
//        Login(login::Form),
//        Register(register::Form),
//    }
//}
