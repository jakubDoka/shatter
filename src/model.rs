use core::fmt;
use std::sync::Arc;

use anyhow::Context;
use arrayvec::ArrayString;
use dashmap::mapref::entry::Entry;
use futures::TryStreamExt;
use mongodb::bson::doc;
use mongodb::error::{WriteError, WriteFailure};
use mongodb::options::FindOptions;
use mongodb::IndexModel;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};

use argon2::password_hash::Salt;
use argon2::{PasswordHasher, PasswordVerifier};
use base64::Engine;

use crate::endpoints::{files, Theme, ThemeBytes};
use crate::PubSub;

pub type Db = mongodb::Database;
pub type Username = ArrayString<32>;
pub type Chatname = ArrayString<32>;

pub async fn connect(url: &str, db: &str) -> anyhow::Result<Db> {
    let client = mongodb::Client::with_uri_str(url)
        .await
        .context("connection to db")?;

    let db = client.database(db);
    User::setup_collection(&db).await?;
    Message::setup_collection(&db).await?;

    Ok(db)
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub username: Username,
    pub password_hash: String,
    #[serde(default)]
    pub theme: ThemeBytes,
}

impl User {
    pub fn new(username: Username, password: &str) -> anyhow::Result<Self> {
        Ok(Self {
            username,
            password_hash: Self::hash_password(password, username)?,
            theme: Theme::default().as_bytes(),
        })
    }

    pub async fn login(db: &Db, username: &str, password: &str) -> anyhow::Result<Option<Self>> {
        let user = Self::collection(db)
            .find_one(mongodb::bson::doc! { "_id": username }, None)
            .await
            .context("find user")?;

        let Some(user) = user else {
            return Ok(None);
        };

        if Self::verify_password(password, &user.password_hash) {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn update(
        db: &Db,
        from: Username,
        to: Username,
        old_password: &str,
        new_password: &str,
        theme: Theme,
    ) -> anyhow::Result<Result<(), &'static str>> {
        let theme_bson = mongodb::bson::to_bson(&theme.as_bytes()).unwrap();

        if from == to {
            let old_password_hash = Self::hash_password(old_password, from)?;
            let new_password_hash = if new_password.is_empty() {
                old_password_hash.clone()
            } else {
                Self::hash_password(new_password, to)?
            };
            Self::collection(db)
                .update_one(
                    doc! { "_id": from.as_str(), "password_hash": old_password_hash },
                    doc! { "$set": {
                        "theme": theme_bson,
                        "password_hash": new_password_hash
                    } },
                    None,
                )
                .await
                .context("update theme")?;
            return Ok(Ok(()));
        }

        let Some(mut s) = Self::collection(db)
            .find_one(doc! { "_id": from.as_str() }, None)
            .await?
        else {
            return Ok(Err("User was deleted in mean time."));
        };

        s.username = to;
        s.theme = theme.as_bytes();
        if !new_password.is_empty() {
            if !Self::verify_password(old_password, &s.password_hash) {
                return Ok(Err("Invalid password."));
            }

            s.password_hash = Self::hash_password(new_password, to)?;
        }

        if !s.create(db).await? {
            return Ok(Err("Username already taken."));
        }

        Self::delete(db, from).await?;

        Member::collection(db)
            .update_many(
                doc! { "user": from.as_str() },
                doc! { "$set": { "user": to.as_str() } },
                None,
            )
            .await
            .context("rename user in chat")?;

        Message::collection(db)
            .update_many(
                doc! { "author": from.as_str() },
                doc! { "$set": { "author": to.as_str() } },
                None,
            )
            .await
            .context("rename user in messages")?;

        let vault_path = files::vault_path(from);
        let new_vault_path = files::vault_path(to);
        let avatar_path = files::avatar_path(from);
        let new_avatar_path = files::avatar_path(to);

        if vault_path.exists() {
            std::fs::rename(vault_path, new_vault_path).context("rename vault")?;
        }

        if avatar_path.exists() {
            std::fs::rename(avatar_path, new_avatar_path).context("rename avatar")?;
        }

        Ok(Ok(()))
    }

    pub async fn delete(db: &Db, username: Username) -> anyhow::Result<()> {
        Self::collection(db)
            .delete_one(doc! { "_id": username.as_str() }, None)
            .await
            .context("delete user")
            .map(drop)
    }

    pub async fn create(&self, db: &Db) -> anyhow::Result<bool> {
        Self::collection(db)
            .insert_one(self, None)
            .await
            .map(|_| true)
            .or_else(|err| {
                if err_is_duplicate(&err) {
                    return Ok(false);
                }
                Err(err)
            })
            .context("create user")
    }

    fn collection(db: &Db) -> mongodb::Collection<User> {
        db.collection("users")
    }

    async fn setup_collection(_: &Db) -> anyhow::Result<()> {
        Ok(())
    }

    fn hash_password(password: &str, username: Username) -> anyhow::Result<String> {
        let mut userame_bytes = [0xffu8; 32];
        userame_bytes[..username.len().min(32)].copy_from_slice(username.as_bytes());
        let value = base64::engine::general_purpose::STANDARD_NO_PAD.encode(userame_bytes);
        let salt = Salt::from_b64(&value)?;

        Ok(argon2::Argon2::default()
            .hash_password(password.as_bytes(), salt)?
            .to_string())
    }

    fn verify_password(password: &str, hash: &str) -> bool {
        let Ok(hash) = argon2::PasswordHash::new(hash) else {
            return false;
        };

        argon2::Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Chat {
    #[serde(rename = "_id")]
    pub name: Chatname,
}

impl Chat {
    pub async fn create(db: &Db, name: Chatname) -> anyhow::Result<bool> {
        Self::collection(db)
            .insert_one(Self { name }, None)
            .await
            .map(|_| true)
            .or_else(|err| {
                if err_is_duplicate(&err) {
                    return Ok(false);
                }
                Err(err)
            })
            .context("create chat")
    }

    pub async fn names_by_user(db: &Db, username: Username) -> anyhow::Result<Vec<Chatname>> {
        Ok(Member::collection(db)
            .find(doc! { "user": username.as_str() }, None)
            .await
            .context("find members")?
            .try_collect::<Vec<_>>()
            .await
            .context("fetch members")?
            .into_iter()
            .map(|member| member.chat)
            .collect::<Vec<_>>())
    }

    fn collection(db: &Db) -> mongodb::Collection<Chat> {
        db.collection("chats")
    }
}

#[derive(Serialize, Deserialize)]
pub struct Member {
    pub chat: Chatname,
    pub user: Username,
    pub role: Role,
}

impl Member {
    pub async fn join(db: &Db, chat: Chatname, user: Username, role: Role) -> anyhow::Result<bool> {
        Self::collection(db)
            .insert_one(Self { chat, user, role }, None)
            .await
            .map(|_| true)
            .or_else(|err| {
                if err_is_duplicate(&err) {
                    return Ok(false);
                }
                Err(err)
            })
            .context("join chat")
    }

    fn collection(db: &Db) -> mongodb::Collection<Member> {
        db.collection("members")
    }
}

#[derive(Serialize, Deserialize, Default)]
pub enum Role {
    Owner,
    Admin,
    #[default]
    Member,
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "_id")]
    pub id: mongodb::bson::oid::ObjectId,
    pub timestamp: mongodb::bson::DateTime,
    pub chat: Chatname,
    pub author: Username,
    pub content: Bytes,
}

impl Message {
    pub fn send(self, psb: &PubSub) -> anyhow::Result<()> {
        match psb.entry(self.chat) {
            Entry::Occupied(o) => {
                if o.get().sender.receiver_count() == 0 {
                    o.remove();
                } else {
                    o.get()
                        .sender
                        .send(self.into())
                        .map_err(|_| anyhow::anyhow!("send message"))?;
                }
            }
            Entry::Vacant(_) => {}
        }
        Ok(())
    }

    pub fn new(chat: Chatname, author: Username, content: Arc<[u8]>) -> Self {
        Self {
            id: mongodb::bson::oid::ObjectId::new(),
            timestamp: mongodb::bson::DateTime::now(),
            chat,
            author,
            content: Bytes(content),
        }
    }

    pub async fn create(&self, db: &Db) -> anyhow::Result<()> {
        Self::collection(db)
            .insert_one(self, None)
            .await
            .context("create message")?;
        Ok(())
    }

    pub async fn get_before(
        db: &Db,
        chat: Chatname,
        before: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<Self>> {
        let before = mongodb::bson::DateTime::from_millis(before.timestamp_millis());
        Self::collection(db)
            .find(
                doc! {
                    "chat": chat.as_str(),
                    "timestamp": { "$lt": before },
                },
                FindOptions::builder()
                    .limit(30)
                    .sort(doc! { "_id": -1 })
                    .build(),
            )
            .await
            .context("find messages")?
            .try_collect()
            .await
            .context("fetch messages")
    }

    fn collection(db: &Db) -> mongodb::Collection<Message> {
        db.collection("messages")
    }

    async fn setup_collection(db: &Db) -> anyhow::Result<()> {
        let coll = Self::collection(db);

        coll.create_index(
            IndexModel::builder()
                .keys(doc! { "chat": 1, "_id": 1 })
                .build(),
            None,
        )
        .await
        .context("partition message by chat")?;

        Ok(())
    }
}

fn err_is_duplicate(err: &mongodb::error::Error) -> bool {
    if let mongodb::error::ErrorKind::Write(WriteFailure::WriteError(WriteError {
        code: 11000,
        ..
    })) = err.kind.as_ref()
    {
        return true;
    }
    false
}

#[derive(Clone)]
pub struct Bytes(pub Arc<[u8]>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;
        impl Visitor<'_> for Vis {
            type Value = Bytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Bytes(v.into()))
            }
        }

        deserializer.deserialize_bytes(Vis)
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}
