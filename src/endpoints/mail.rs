use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::model::{self, Chatname, Db, Username};

use super::chat::{Base, Base64, RoomNav};
use super::Session;

pub type MailBoxFull = Base<MailBox>;

pub async fn invite(Path(name): Path<Chatname>) -> InviteForm {
    InviteForm {
        name,
        ..Default::default()
    }
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
    //if form.username == session.username {
    //    form.errors.push("Na na na, you can't invite yourself.");
    //    return Ok(Err(form));
    //}

    if let Err(err) = super::validate_username(form.username) {
        form.errors.push(err);
        return Ok(Err(form));
    }

    let Some(ciphertext) = form.ciphertext else {
        let Some(user) = model::User::get(&state.db, form.username)
            .await
            .map_err(super::internal)?
        else {
            form.errors.push("User not found.");
            return Ok(Err(form));
        };

        form.user_key = Some(Base64(user.public_key.0));
        return Ok(Err(form));
    };

    model::Mail::send(
        &state.db,
        form.username,
        model::MailPayload::ChatInvite {
            chat,
            from: session.username,
            ciphertext: model::Bytes(ciphertext.0),
        },
    )
    .await
    .map_err(super::internal)?;

    Ok(Ok(RoomNav { name: chat }))
}

#[derive(serde::Deserialize, askama::Template, Default)]
#[template(path = "chat.invite.html")]
pub struct InviteForm {
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
    mail: Vec<model::Mail>,
}

impl MailBlock {
    pub async fn new(
        db: &Db,
        username: Username,
        before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<Self> {
        let mut mail =
            model::Mail::get_before(db, username, before.unwrap_or_else(chrono::Utc::now)).await?;

        mail.reverse();

        Ok(Self {
            last_message_stamp: mail
                .last()
                .map(|m| m.stamp)
                .unwrap_or_else(chrono::Utc::now),
            mail,
        })
    }
}
