use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Redirect;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::model::Username;

use self::chat::{Base64, FullChatList};

pub mod chat;
pub mod files;
pub mod login;
pub mod mail;
pub mod profile;
pub mod register;
pub mod sse;

pub async fn index(
    cookies: Cookies,
    State(state): State<crate::State>,
) -> Result<Result<FullChatList, login::Login>, StatusCode> {
    let Some(session) = Session::extract_from_cookies(&cookies, &state) else {
        return Ok(Err(Default::default()));
    };

    Ok(Ok(chat::full_list(State(state), session).await?))
}

fn validate_username(username: Username) -> Result<(), &'static str> {
    if username.len() < 3 {
        return Err("Username must be at least 3 characters long.");
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub username: Username,
    pub valid_until: u64,
    pub theme: Base64<ThemeBytes>,
}

impl Session {
    pub fn new(username: Username, valid_for: std::time::Duration, theme: ThemeBytes) -> Self {
        Self {
            username,
            valid_until: std::time::SystemTime::now()
                .checked_add(valid_for)
                .expect("valid time")
                .duration_since(std::time::UNIX_EPOCH)
                .expect("duration since")
                .as_secs(),
            theme: Base64(theme),
        }
    }

    pub fn update(&mut self, username: Username, theme: ThemeBytes) {
        self.username = username;
        self.theme = Base64(theme);
    }

    pub fn extract_from_cookies(cookies: &Cookies, state: &impl CookieKey) -> Option<Self> {
        cookies
            .private(state.cookie_key())
            .get("session")
            .and_then(|cookie| serde_json::from_str(cookie.value()).ok())
    }

    pub fn theme(&self) -> Theme {
        self.theme.0.to_theme()
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

macro_rules! gen_theme {
    (
        struct $name:ident {$(
            $field:ident: $default:literal,
        )*}
    ) => {
        #[derive(askama::Template, serde::Deserialize, Clone, Copy)]
        #[template(path = "theme.txt")]
        pub struct $name {$(
            #[serde(deserialize_with = "deserialize_html_color")]
            pub $field: u32,
        )*}

        impl Theme {
            pub fn fields(&self) -> impl Iterator<Item = ThemeField> {
                [$(
                    ThemeField {
                        name: stringify!($field),
                        value: self.$field,
                    },
                )*].into_iter()
            }

        }

        impl Default for $name {
            fn default() -> Self {
                Self {$(
                    $field: $default,
                )*}
            }
        }

    };
}

gen_theme! {
    struct Theme {
        primary_color: 0x1E1E1E,
        secondary_color: 0x494949,
        highlight_color: 0x87DF6D,
        font_color: 0xDCDCDC,
        error_color: 0xFF0000,
    }
}

impl Theme {
    pub fn as_bytes(&self) -> ThemeBytes {
        ThemeBytes(unsafe { std::mem::transmute(*self) })
    }
}

#[derive(Copy, Clone, Default)]
pub struct ThemeBytes([u8; std::mem::size_of::<Theme>()]);

impl ThemeBytes {
    pub fn to_theme(self) -> Theme {
        unsafe { std::mem::transmute(self) }
    }
}

impl AsRef<[u8]> for ThemeBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for ThemeBytes {
    type Error = &'static str;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        v.try_into().map(Self).map_err(|_| "wrong size")
    }
}

pub struct ThemeField {
    pub name: &'static str,
    pub value: u32,
}

pub fn deserialize_html_color<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = s.trim_start_matches('#');
    u32::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

mod filters {
    pub fn css_color(input: &u32) -> askama::Result<String> {
        Ok(format!("#{input:x}"))
    }

    pub fn replace(input: &str, from: &str, to: &str) -> askama::Result<String> {
        Ok(input.replace(from, to))
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
