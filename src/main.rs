#![feature(const_trait_impl)]
#![feature(effects)]

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use dashmap::DashMap;
use tokio::sync::broadcast::Sender;
use tower_http::services::ServeFile;

use crate::endpoints::register::Register;
use crate::endpoints::{login, mail, profile, register, sse};

use self::endpoints::chat::{self, Message};
use self::endpoints::login::Login;
use self::model::{Chatname, Username};

mod endpoints;
mod model;

pub type ChatPubSub = Arc<DashMap<Chatname, PubSubEntry>>;
pub type UserPubSub = Arc<DashMap<Username, tokio::sync::mpsc::Sender<model::Mail>>>;

pub struct PubSubEntry {
    sender: Sender<Message>,
}

impl Default for PubSubEntry {
    fn default() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(20);
        Self { sender }
    }
}

#[derive(Clone)]
struct State {
    db: model::Db,
    cookie_key: tower_cookies::Key,
    message_pubsub: ChatPubSub,
    mail_pubsub: UserPubSub,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    use axum::routing::{delete, get, post};
    use tower_http::services::ServeDir;

    let mongo_url = if cfg!(debug_assertions) {
        "mongodb://localhost:27017".into()
    } else {
        std::env::var("MONGO_URL").expect("MONGO_URL env var")
    };

    let db = model::connect(&mongo_url, "db").await.unwrap();
    let cookie_key = if cfg!(debug_assertions) {
        tower_cookies::Key::derive_from(b"super secret key that has 32 bts")
    } else {
        tower_cookies::Key::generate()
    };

    let router = axum::Router::new()
        .route("/", get(endpoints::index))
        .route("/chat-list/", get(chat::full_list))
        .route("/chat-list/content", get(chat::list_content))
        .route("/chat-list/create", get(def_handler::<chat::CreateForm>))
        .route("/chat-list/create", post(chat::create))
        .route("/chat-list/events", get(sse::mail_count))
        .route(
            "/chat-list/create/back",
            get(def_handler::<chat::CreateButton>),
        )
        .route("/chat-room/:name/", get(chat::full_room))
        .route("/chat-room/:name/messages", get(chat::get_messages))
        .route("/chat-room/:name/messages", post(chat::send_message))
        .route("/chat-room/:name/content", get(chat::room_content))
        .route("/chat-room/:name/events", get(sse::chat))
        .route("/chat-room/:name/invite", get(mail::invite))
        .route("/chat-room/:name/invite", post(mail::send_invite))
        .route("/chat-room/:name/nav", get(chat::nav))
        .route("/login/", get(def_handler::<Login>))
        .route("/login", post(endpoints::login::post))
        .route("/login/content", get(def_handler::<login::Form>))
        .route("/register/", get(def_handler::<Register>))
        .route("/register", post(endpoints::register::post))
        .route("/register/content", get(def_handler::<register::Form>))
        .route("/profile/:username/", get(profile::full))
        .route("/profile", post(profile::edit))
        .route("/profile/:username/content", get(profile::content))
        .route("/profile/:username/events", get(sse::mail_count))
        .route("/mail", get(mail::get_mail))
        .route("/mail/", get(mail::full))
        .route("/mail/:id/invite", delete(mail::handle_invite))
        .route("/mail/content", get(mail::content))
        .route("/mail/events", get(sse::mail))
        .nest_service("/assets", ServeDir::new("assets"))
        .nest_service("/manifest.json", ServeFile::new("manifest.json"))
        .route("/vaults", post(endpoints::files::set_vault))
        .route("/vaults", get(endpoints::files::get_vault))
        .route("/avatars", post(endpoints::files::set_avatar))
        .route("/avatars/:username", get(endpoints::files::get_avatar))
        .layer(tower_cookies::CookieManagerLayer::new())
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(State {
            db,
            cookie_key,
            message_pubsub: Default::default(),
            mail_pubsub: Default::default(),
        });

    #[cfg(feature = "tower-livereload")]
    let router = {
        #[derive(Clone, Copy)]
        struct OnlyRoot;

        impl tower_livereload::predicate::Predicate<axum::http::Request<axum::body::Body>> for OnlyRoot {
            fn check(&mut self, req: &axum::http::Request<axum::body::Body>) -> bool {
                req.uri().path().ends_with('/')
            }
        }

        router.layer(tower_livereload::LiveReloadLayer::new().request_predicate(OnlyRoot))
    };

    let addr = if cfg!(debug_assertions) {
        "0.0.0.0:42069".into()
    } else {
        std::env::var("ADDR").expect("ADDR env var")
    };

    let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(tcp, router).await.unwrap();
}

async fn def_handler<T: Default>() -> T {
    T::default()
}
