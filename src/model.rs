use core::fmt;
use std::fmt::Display;
use std::sync::Arc;

use anyhow::Context;
use arrayvec::ArrayString;
use dashmap::mapref::entry::Entry;
use futures::{StreamExt, TryStreamExt};
use mongodb::bson::doc;
use mongodb::error::{WriteError, WriteFailure};
use mongodb::options::{FindOptions, IndexOptions};
use mongodb::IndexModel;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};

use argon2::password_hash::Salt;
use argon2::{PasswordHasher, PasswordVerifier};
use base64::Engine;

use crate::endpoints::{files, Theme, ThemeBytes};
use crate::ChatPubSub;

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
    Mail::setup_collection(&db).await?;
    Member::setup_collection(&db).await?;

    Ok(db)
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum MailPayload {
    ChatInvite {
        chat: Chatname,
        from: Username,
        role: Role,
        ciphertext: Bytes<Ciphertext>,
    },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Mail {
    #[serde(rename = "_id")]
    pub id: mongodb::bson::oid::ObjectId,
    pub to: Username,
    pub stamp: mongodb::bson::DateTime,
    #[serde(flatten)]
    pub payload: MailPayload,
}

impl Mail {
    pub async fn get_and_delete(
        db: &Db,
        id: mongodb::bson::oid::ObjectId,
        username: Username,
    ) -> anyhow::Result<Option<Self>> {
        let mail = Self::collection(db)
            .find_one_and_delete(doc! { "_id": id, "to": username.as_str() }, None)
            .await
            .context("find mail")?;
        Ok(mail)
    }

    pub fn new(to: Username, payload: MailPayload) -> Self {
        Self {
            id: mongodb::bson::oid::ObjectId::new(),
            to,
            stamp: mongodb::bson::DateTime::now(),
            payload,
        }
    }

    pub async fn create(&self, db: &Db) -> anyhow::Result<Result<(), &'static str>> {
        if Self::count(db, self.to).await? > 1024 {
            return Ok(Err("Users mailbox is full."));
        }

        match &self.payload {
            MailPayload::ChatInvite { chat, .. } => {
                if Member::exists(db, *chat, self.to).await? {
                    return Ok(Err("User is already in chat."));
                }
            }
        }

        Self::collection(db)
            .insert_one(self, None)
            .await
            .context("create mail")
            .map(drop)
            .map(Ok)
    }

    pub async fn count(db: &Db, to: Username) -> anyhow::Result<u64> {
        Self::collection(db)
            .count_documents(doc! { "to": to.as_str() }, None)
            .await
            .context("count mail")
    }

    pub async fn get_before(
        db: &Db,
        to: Username,
        before: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Vec<Self>> {
        let before = mongodb::bson::DateTime::from_millis(before.timestamp_millis());
        Ok(Self::collection(db)
            .find(
                doc! {
                    "to": to.as_str(),
                    "stamp": { "$lt": before },
                },
                FindOptions::builder()
                    .limit(30)
                    .sort(doc! { "_id": -1 })
                    .build(),
            )
            .await
            .context("find mail")?
            .filter_map(|mail| async move {
                match mail {
                    Ok(mail) => Some(mail),
                    Err(err) => {
                        log::error!("mail is malformed: {}", err);
                        None
                    }
                }
            })
            .collect()
            .await)
    }

    fn collection(db: &Db) -> mongodb::Collection<Mail> {
        db.collection("mail")
    }

    async fn setup_collection(db: &Db) -> anyhow::Result<()> {
        let coll = Self::collection(db);

        coll.create_index(
            IndexModel::builder()
                .keys(doc! { "to": 1, "sent": 1 })
                .build(),
            None,
        )
        .await
        .context("partition mail by recipient")?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub username: Username,
    pub password_hash: String,
    #[serde(default)]
    pub theme: Bytes<ThemeBytes>,
    pub public_key: Bytes<PublicKey>,
}

impl User {
    pub fn new(username: Username, password: &str, public_key: PublicKey) -> anyhow::Result<Self> {
        Ok(Self {
            username,
            password_hash: Self::hash_password(password, username)?,
            theme: Bytes(Theme::default().as_bytes()),
            public_key: Bytes(public_key),
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

    pub async fn get(db: &Db, username: Username) -> anyhow::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "_id": username.as_str() }, None)
            .await
            .context("find user")
    }

    pub async fn update(
        db: &Db,
        from: Username,
        to: Username,
        old_password: &str,
        new_password: &str,
        theme: Theme,
        public_key: PublicKey,
    ) -> anyhow::Result<Result<(), &'static str>> {
        if from == to {
            let theme_bson = mongodb::bson::to_bson(&Bytes(theme.as_bytes())).unwrap();
            let pk_bson = mongodb::bson::to_bson(&Bytes(public_key.as_ref())).unwrap();

            let mut query = doc! { "_id": from.as_str() };
            let mut update = doc! { "$set": {
                "theme": theme_bson,
                "public_key": pk_bson,
            } };

            if !new_password.is_empty() {
                query.insert("password_hash", Self::hash_password(old_password, from)?);
                update.insert("password_hash", Self::hash_password(new_password, to)?);
            }

            Self::collection(db)
                .update_one(query, update, None)
                .await
                .context("update theme")?;
            return Ok(Ok(()));
        }

        let Some(mut s) = Self::get(db, from).await? else {
            return Ok(Err("User was deleted in mean time."));
        };

        s.username = to;
        s.public_key = Bytes(public_key);
        s.theme = Bytes(theme.as_bytes());
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

    async fn setup_collection(db: &Db) -> anyhow::Result<()> {
        let coll = Self::collection(db);

        coll.create_index(
            IndexModel::builder()
                .keys(doc! { "chat": 1, "user": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        )
        .await
        .context("partition member by chat and user")?;

        Ok(())
    }

    pub async fn exists(
        db: &mongodb::Database,
        chat: ArrayString<32>,
        to: ArrayString<32>,
    ) -> anyhow::Result<bool> {
        Self::collection(db)
            .count_documents(doc! { "chat": chat.as_str(), "user": to.as_str() }, None)
            .await
            .context("find member")
            .map(|n| n > 0)
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub enum Role {
    Owner,
    Admin,
    #[default]
    Member,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", format!("{:?}", self).to_lowercase())
    }
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
    pub fn send(self, psb: &ChatPubSub) -> anyhow::Result<()> {
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

#[derive(Clone, Copy)]
pub struct Ciphertext(crypto::Serialized<crypto::enc::ChoosenCiphertext>);

impl Default for Ciphertext {
    fn default() -> Self {
        Self([0; std::mem::size_of::<crypto::enc::ChoosenCiphertext>()])
    }
}

impl TryFrom<Vec<u8>> for Ciphertext {
    type Error = &'static str;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        v.try_into().map(Self).map_err(|_| "wrong size")
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(crypto::Serialized<crypto::enc::PublicKey>);

impl Default for PublicKey {
    fn default() -> Self {
        Self([0; std::mem::size_of::<crypto::enc::PublicKey>()])
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = &'static str;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        v.try_into().map(Self).map_err(|_| "wrong size")
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Default)]
pub struct Bytes<T = Arc<[u8]>>(pub T);

impl<'de, T: TryFrom<Vec<u8>>> Deserialize<'de> for Bytes<T>
where
    T::Error: Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis<T>(std::marker::PhantomData<T>);
        impl<'d, T> Visitor<'d> for Vis<T>
        where
            T: TryFrom<Vec<u8>>,
            T::Error: Display,
        {
            type Value = Bytes<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Bytes(
                    v.to_vec().try_into().map_err(serde::de::Error::custom)?,
                ))
            }
        }

        deserializer.deserialize_bytes(Vis(std::marker::PhantomData))
    }
}

impl<T: AsRef<[u8]>> Serialize for Bytes<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_ref())
    }
}
