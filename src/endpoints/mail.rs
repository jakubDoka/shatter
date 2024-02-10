use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use dashmap::mapref::entry::Entry;
use serde::Deserialize;
use tokio::sync::mpsc::error::TrySendError;

use crate::model::{self, Chatname, Db, MailPayload, Member, Username};

use super::chat::{Base, Base64, RoomNav};
use super::{internal, Session};

pub type MailBoxFull = Base<MailBox>;

pub async fn invite(Path(name): Path<Chatname>) -> InviteForm {
    InviteForm {
        name,
        ..Default::default()
    }
}

pub async fn handle_invite(
    State(state): State<crate::State>,
    session: Session,
    Path(id): Path<mongodb::bson::oid::ObjectId>,
    axum::Form(form): axum::Form<HandleInvite>,
) -> Result<SetMailCount, StatusCode> {
    let Some(message) = model::Mail::get_and_delete(&state.db, id, session.username)
        .await
        .map_err(internal)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let MailPayload::ChatInvite { chat, .. } = message.payload;

    if matches!(form.command, HandleInviteCommand::Accept) {
        model::Member::join(&state.db, chat, session.username, model::Role::Member)
            .await
            .map_err(internal)?;
    }

    Ok(SetMailCount {
        count: model::Mail::count(&state.db, session.username)
            .await
            .map_err(super::internal)?,
        error: matches!(form.command, HandleInviteCommand::Failed)
            .then(|| "The invite ciphertext was invalid."),
    })
}

#[derive(Deserialize)]
pub struct HandleInvite {
    command: HandleInviteCommand,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleInviteCommand {
    Accept,
    Decline,
    Failed,
}

#[derive(askama::Template)]
#[template(path = "mail.set-count.html")]
pub struct SetMailCount {
    count: u64,
    error: Option<&'static str>,
}

pub async fn full(
    State(state): State<crate::State>,
    session: Session,
) -> Result<MailBoxFull, StatusCode> {
    Ok(MailBoxFull {
        theme: session.theme(),
        username: session.username,
        content: MailBox {
            init_block: MailBlock::new(&state.db, session.username, None)
                .await
                .map_err(super::internal)?,
        },
    })
}

pub async fn content(
    State(state): State<crate::State>,
    session: Session,
) -> Result<MailBox, StatusCode> {
    Ok(MailBox {
        init_block: MailBlock::new(&state.db, session.username, None)
            .await
            .map_err(super::internal)?,
    })
}

pub async fn get_mail(
    State(state): State<crate::State>,
    session: Session,
    Query(query): Query<GetMail>,
) -> Result<MailBlock, StatusCode> {
    MailBlock::new(&state.db, session.username, query.before)
        .await
        .map_err(super::internal)
}

#[derive(Deserialize)]
pub struct GetMail {
    before: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn send_invite(
    Path(chat): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
    axum::Form(mut form): axum::Form<InviteForm>,
) -> Result<Result<RoomNav, InviteForm>, StatusCode> {
    if form.username == session.username {
        form.errors.push("Na na na, you can't invite yourself.");
        return Ok(Err(form));
    }

    if let Err(err) = super::validate_username(form.username) {
        form.errors.push(err);
        return Ok(Err(form));
    }

    let Some(ciphertext) = &form.ciphertext else {
        if Member::exists(&state.db, chat, form.username)
            .await
            .map_err(super::internal)?
        {
            form.errors.push("User is already in the chat.");
            return Ok(Err(form));
        }

        if form.fetched_already {
            form.errors.push("You are not supposed to get here.");
            return Ok(Err(form));
        }

        let Some(user) = model::User::get(&state.db, form.username)
            .await
            .map_err(super::internal)?
        else {
            form.errors.push("User not found.");
            return Ok(Err(form));
        };

        form.fetched_already = true;
        form.user_key = Some(Base64(user.public_key.0));
        return Ok(Err(form));
    };

    let mail = model::Mail::new(
        form.username,
        model::MailPayload::ChatInvite {
            chat,
            from: session.username,
            role: model::Role::Member,
            ciphertext: model::Bytes(ciphertext.0),
        },
    );

    if let Err(err) = mail.create(&state.db).await.map_err(super::internal)? {
        form.errors.push(err);
        return Ok(Err(form));
    }

    if let Entry::Occupied(chan) = state.mail_pubsub.entry(form.username) {
        if let Err(TrySendError::Closed(_)) = chan.get().try_send(mail) {
            chan.remove();
        }
    }

    Ok(Ok(RoomNav { name: chat }))
}

#[derive(serde::Deserialize, askama::Template, Default)]
#[template(path = "chat.invite.html")]
pub struct InviteForm {
    pub fetched_already: bool,
    #[serde(skip)]
    pub name: Chatname,
    pub username: Username,
    pub ciphertext: Option<Base64<model::Ciphertext>>,
    #[serde(skip)]
    pub user_key: Option<Base64<model::PublicKey>>,
    #[serde(skip)]
    pub errors: Vec<&'static str>,
}

#[derive(askama::Template)]
#[template(path = "mail.content.html")]
pub struct MailBox {
    init_block: MailBlock,
}

#[derive(askama::Template)]
#[template(path = "mail.block.html")]
pub struct MailBlock {
    last_message_stamp: chrono::DateTime<chrono::Utc>,
    mail: Vec<Mail>,
}

impl MailBlock {
    pub async fn new(
        db: &Db,
        username: Username,
        before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<Self> {
        let mut mail =
            model::Mail::get_before(db, username, before.unwrap_or_else(chrono::Utc::now))
                .await?
                .into_iter()
                .map(Mail::from)
                .collect::<Vec<_>>();

        mail.reverse();

        Ok(Self {
            last_message_stamp: mail
                .first()
                .map(|m| m.stamp)
                .unwrap_or_else(chrono::Utc::now),
            mail,
        })
    }
}

#[derive(askama::Template)]
#[template(path = "mail.html")]
pub struct Mail {
    pub id: mongodb::bson::oid::ObjectId,
    pub stamp: chrono::DateTime<chrono::Utc>,
    pub payload: MailPayload,
}

impl From<model::Mail> for Mail {
    fn from(mail: model::Mail) -> Self {
        Self {
            id: mail.id,
            stamp: chrono::DateTime::from_timestamp_millis(mail.stamp.timestamp_millis()).unwrap(),
            payload: mail.payload,
        }
    }
}
