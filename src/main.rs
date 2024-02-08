#![feature(const_trait_impl)]
#![feature(effects)]

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use dashmap::DashMap;
use tokio::sync::broadcast::Sender;
use tower_livereload::predicate;

use crate::endpoints::register::Register;
use crate::endpoints::{login, profile, register};

use self::endpoints::chat::{self, Message};
use self::endpoints::login::Login;
use self::model::Chatname;

mod endpoints;
mod model;

pub type PubSub = Arc<DashMap<Chatname, PubSubEntry>>;

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
    message_pubsub: PubSub,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    use axum::routing::{get, post};
    use tower_http::services::ServeDir;

    let db = model::connect("mongodb://localhost:27017", "db")
        .await
        .unwrap();
    let cookie_key = tower_cookies::Key::derive_from(b"super secret key that has 32 bts");

    let router = axum::Router::new()
        .route("/", get(endpoints::index))
        .route("/chat-list/", get(chat::full_list))
        .route("/chat-list/content", get(chat::list_content))
        .route("/chat-list/create", get(def_handler::<chat::CreateForm>))
        .route("/chat-list/create", post(chat::create))
        .route(
            "/chat-list/create/back",
            get(def_handler::<chat::CreateButton>),
        )
        .route("/chat-room/:name/", get(chat::full_room))
        .route("/chat-room/:name/messages", get(chat::get_messages))
        .route("/chat-room/:name/messages", post(chat::send_message))
        .route("/chat-room/:name/content", get(chat::room_content))
        .route("/chat-room/:name/new-messages", get(chat::new_messages_sse))
        .route("/login/", get(def_handler::<Login>))
        .route("/login", post(endpoints::login::post))
        .route("/login/content", get(def_handler::<login::Form>))
        .route("/register/", get(def_handler::<Register>))
        .route("/register", post(endpoints::register::post))
        .route("/register/content", get(def_handler::<register::Form>))
        .route("/profile/:username/", get(profile::full))
        .route("/profile", post(profile::edit))
        .route("/profile/:username/content", get(profile::content))
        .nest_service("/assets", ServeDir::new("assets"))
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
        });

    #[cfg(feature = "tower-livereload")]
    let router = router.layer(tower_livereload::LiveReloadLayer::new().request_predicate(OnlyRoot));

    let tcp = tokio::net::TcpListener::bind("0.0.0.0:42069")
        .await
        .unwrap();
    axum::serve(tcp, router).await.unwrap();
}

async fn def_handler<T: Default>() -> T {
    T::default()
}

#[cfg(feature = "tower-livereload")]
#[derive(Clone, Copy)]
struct OnlyRoot;

#[cfg(feature = "tower-livereload")]
impl predicate::Predicate<axum::http::Request<axum::body::Body>> for OnlyRoot {
    fn check(&mut self, req: &axum::http::Request<axum::body::Body>) -> bool {
        req.uri().path().ends_with('/')
    }
}
