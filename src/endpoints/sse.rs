use std::convert::Infallible;

use anyhow::Result;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive};
use axum::response::Sse;

use futures::{stream, Stream, StreamExt};

use crate::endpoints::mail;
use crate::model::{self, Chatname, Username};
use crate::UserPubSub;

use super::Session;

pub async fn chat(
    Path(room): Path<Chatname>,
    State(state): State<crate::State>,
    session: Session,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let messaeg_sub = state
        .message_pubsub
        .entry(room)
        .or_default()
        .sender
        .subscribe();

    let mail_stream = setup_mail_stream(&state, &session, false).await?;

    let message_stream = futures::stream::unfold(messaeg_sub, move |mut stream| async move {
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

    Ok(
        Sse::new(futures::stream::select(mail_stream, message_stream))
            .keep_alive(KeepAlive::default()),
    )
}

pub async fn mail_count(
    State(state): State<crate::State>,
    session: Session,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let mail_stream = setup_mail_stream(&state, &session, false).await?;
    Ok(Sse::new(mail_stream).keep_alive(KeepAlive::default()))
}

pub async fn mail(
    State(state): State<crate::State>,
    session: Session,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let mail_stream = setup_mail_stream(&state, &session, true).await?;
    Ok(Sse::new(mail_stream).keep_alive(KeepAlive::default()))
}

async fn setup_mail_stream(
    state: &crate::State,
    session: &Session,
    incude_mail: bool,
) -> Result<impl Stream<Item = Result<Event, Infallible>>, StatusCode> {
    struct RemoveOnDrop(UserPubSub, Username);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            self.0.remove(&self.1);
        }
    }

    let (mail_in, mail_out) = tokio::sync::mpsc::channel(30);
    state.mail_pubsub.insert(session.username, mail_in.clone());
    let initial_mail_count = model::Mail::count(&state.db, session.username)
        .await
        .map_err(super::internal)?;
    let stream = futures::stream::unfold(
        (
            mail_out,
            initial_mail_count,
            RemoveOnDrop(state.mail_pubsub.clone(), session.username),
        ),
        move |(mut stream, mail_count, drop)| async move {
            let mail = stream.recv().await?;
            let mail = incude_mail.then(|| {
                Event::default()
                    .event("NewMail")
                    .data(mail::Mail::from(mail).render().unwrap())
            });

            Some((
                (
                    Event::default()
                        .event("MailCount")
                        .data(format!("{}", mail_count + 1)),
                    mail,
                ),
                (stream, mail_count + 1, drop),
            ))
        },
    );

    let init_counter = (initial_mail_count > 0).then(|| {
        Event::default()
            .event("MailCount")
            .data(format!("{initial_mail_count}"))
    });

    Ok(stream::iter(init_counter)
        .chain(stream.flat_map(|(a, b)| stream::iter(Some(a)).chain(stream::iter(b))))
        .map(Ok))
}
