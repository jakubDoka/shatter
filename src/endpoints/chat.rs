use core::fmt;
use std::convert::Infallible;
use std::fmt::Display;
use std::sync::Arc;

use anyhow::Result;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive};
use axum::response::Sse;
use base64::Engine;
use chrono::SubsecRound;
use futures::Stream;
use serde::{Deserialize, Deserializer, Serialize};

use crate::model::{self, Chat, Chatname, Db, Username};

use super::{Session, Theme};

pub type FullChatList = Base<ChatList>;
pub type FullRoom = Base<Room>;
pub type FullRoomNotFound = Base<RoomNotFound>;

pub async fn send_message(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
    axum::Form(mut form): axum::Form<SendMessageForm>,
) -> Result<SendMessageForm, StatusCode> {
    if form.content.0.len() > 1024 + 30 {
        form.errors.push("message too long");
        return Ok(form);
    }

    let message = model::Message::new(room, session.username, form.content.0);
    message.create(&state.db).await.map_err(super::internal)?;
    message
        .send(&state.message_pubsub)
        .map_err(super::internal)?;

    Ok(SendMessageForm {
        name: room,
        content: Base64(Arc::from([])),
        errors: vec![],
    })
}

pub async fn new_messages_sse(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let stream = state
        .message_pubsub
        .entry(room)
        .or_default()
        .sender
        .subscribe();

    let stream = futures::stream::unfold(stream, move |mut stream| async move {
        let Ok(mut message) = stream.recv().await else {
            return None;
        };

        message.is_me = message.by == session.username;

        let Ok(message) = message.render() else {
            log::error!("failed to render message {}", message);
            return None;
        };

        Some((
            Ok(Event::default().event("NewMessage").data(message)),
            stream,
        ))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

pub async fn create(
    State(state): State<crate::State>,
    session: Session,
    axum::Form(mut form): axum::Form<CreateForm>,
) -> Result<Result<CreateButton, CreateForm>, StatusCode> {
    if form.name.len() < 3 {
        form.errors.push("name must be at least 3 characters long");
        return Ok(Err(form));
    }

    if !model::Chat::create(&state.db, form.name)
        .await
        .map_err(super::internal)?
    {
        form.errors.push("chat already exists");
        return Ok(Err(form));
    }

    let success = model::Member::join(&state.db, form.name, session.username, model::Role::Owner)
        .await
        .map_err(super::internal)?;
    debug_assert!(success);

    Ok(Ok(CreateButton {
        added_chat: Some(form.name),
    }))
}

pub async fn full_list(
    state: State<crate::State>,
    session: Session,
) -> Result<FullChatList, StatusCode> {
    Ok(Base {
        theme: Theme::default(),
        username: session.username,
        content: list_content(state, session).await?,
    })
}

pub async fn full_room(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
) -> Result<Result<FullRoom, FullRoomNotFound>, StatusCode> {
    Ok(
        match Room::new(&state.db, room, session.username)
            .await
            .map_err(super::internal)?
        {
            Some(content) => Ok(Base {
                theme: Theme::default(),
                username: session.username,
                content,
            }),
            None => Err(Base {
                theme: Theme::default(),
                username: session.username,
                content: RoomNotFound,
            }),
        },
    )
}

pub async fn list_content(
    State(state): State<crate::State>,
    session: Session,
) -> Result<ChatList, StatusCode> {
    ChatList::new(&state.db, session.username)
        .await
        .map_err(super::internal)
}

pub async fn room_content(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
) -> Result<Result<Room, RoomNotFound>, StatusCode> {
    Ok(Room::new(&state.db, room, session.username)
        .await
        .map_err(super::internal)?
        .ok_or(RoomNotFound))
}

pub async fn get_messages(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    Query(params): Query<GetMessageParams>,
    session: Session,
) -> Result<MessageBlock, StatusCode> {
    MessageBlock::new(&state.db, room, session.username, params.before)
        .await
        .map_err(super::internal)?
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(serde::Deserialize, askama::Template)]
#[template(path = "chat.room.send.html")]
pub struct SendMessageForm {
    name: Chatname,
    content: Base64,
    #[serde(skip)]
    errors: Vec<&'static str>,
}

#[derive(serde::Deserialize)]
pub struct GetMessageParams {
    before: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(askama::Template)]
#[template(path = "chat.room.html")]
pub struct Room {
    name: Chatname,
    init_block: MessageBlock,
}

impl Room {
    pub async fn new(db: &Db, room: Chatname, username: Username) -> anyhow::Result<Option<Self>> {
        let Some(block) = MessageBlock::new(db, room, username, None).await? else {
            return Ok(None);
        };

        Ok(Some(Self {
            name: room,
            init_block: block,
        }))
    }
}

#[derive(askama::Template)]
#[template(path = "chat.room.message_block.html")]
pub struct MessageBlock {
    last_message_stamp: chrono::DateTime<chrono::Utc>,
    messages: Vec<Message>,
}

impl MessageBlock {
    pub async fn new(
        db: &Db,
        room: Chatname,
        username: Username,
        before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<Option<Self>> {
        let before = before.unwrap_or_else(chrono::Utc::now);
        let mut messages = model::Message::get_before(db, room, before)
            .await?
            .into_iter()
            .map(Message::from)
            .collect::<Vec<_>>();

        for message in &mut messages {
            message.is_me = message.by == username;
        }

        Ok(Some(Self {
            last_message_stamp: messages.first().map(|m| m.sent).unwrap_or_else(|| before),
            messages,
        }))
    }
}

#[derive(askama::Template, Clone)]
#[template(path = "chat.room.message.html")]
pub struct Message {
    id: mongodb::bson::oid::ObjectId,
    sent: chrono::DateTime<chrono::Utc>,
    chat: Chatname,
    by: Username,
    is_me: bool,
    content: Base64,
}

impl From<model::Message> for Message {
    fn from(m: model::Message) -> Self {
        Self {
            id: m.id,
            sent: chrono::DateTime::from_timestamp_millis(m.timestamp.timestamp_millis()).unwrap(),
            chat: m.chat,
            by: m.author,
            is_me: false,
            content: Base64(m.content.0),
        }
    }
}

#[derive(askama::Template, serde::Deserialize, Default)]
#[template(path = "chat.list.create.form.html")]
pub struct CreateForm {
    name: Chatname,
    #[serde(skip)]
    errors: Vec<&'static str>,
}

#[derive(askama::Template, Default)]
#[template(path = "chat.list.create.button.html")]
pub struct CreateButton {
    added_chat: Option<Chatname>,
}

#[derive(askama::Template)]
#[template(path = "chat.room.not_found.html")]
pub struct RoomNotFound;

#[derive(askama::Template)]
#[template(path = "chat.list.html")]
pub struct ChatList {
    chats: Vec<Chatname>,
}

impl ChatList {
    pub async fn new(db: &Db, username: Username) -> anyhow::Result<Self> {
        Ok(Self {
            chats: Chat::names_by_user(db, username).await?,
        })
    }
}

#[derive(askama::Template)]
#[template(path = "chat.html")]
pub struct Base<T: Display + PageName> {
    pub theme: Theme,
    pub username: Username,
    pub content: T,
}

pub trait PageName {
    fn page_name(&self) -> &'static str {
        "non-existant-page"
    }
}

impl PageName for Room {}
impl PageName for RoomNotFound {}

impl PageName for ChatList {
    fn page_name(&self) -> &'static str {
        "chat-list"
    }
}

#[derive(Clone)]
pub struct Base64(pub Arc<[u8]>);

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
            .map(Into::into)
            .map(Base64)
    }
}

impl Serialize for Base64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64::engine::general_purpose::STANDARD
            .encode(&self.0)
            .serialize(serializer)
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        base64::engine::general_purpose::STANDARD
            .encode(&self.0)
            .fmt(f)
    }
}
