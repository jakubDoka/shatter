use std::path::PathBuf;

use anyhow::Context as _;
use arrayvec::ArrayString;
use askama_axum::IntoResponse;
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;

use http_body::{Body, Frame};
use tokio::io::AsyncWriteExt;

use crate::model::Username;

use super::Session;

pub async fn get_avatar(Path(username): Path<Username>) -> Result<impl IntoResponse, StatusCode> {
    let path = ["files/avatars", &encode_name(username)]
        .into_iter()
        .collect();
    read_file(path).await
}

pub async fn set_avatar(session: Session, avatar: axum::body::Body) -> Result<(), StatusCode> {
    let path = ["files/avatars", &encode_name(session.username)]
        .into_iter()
        .collect();
    write_file(avatar, path).await
}

pub async fn get_vault(session: Session) -> Result<impl IntoResponse, StatusCode> {
    let path = ["files/vaults", &encode_name(session.username)]
        .into_iter()
        .collect();
    read_file(path).await
}

pub async fn set_vault(session: Session, vault: axum::body::Body) -> Result<(), StatusCode> {
    let path = ["files/vaults", &encode_name(session.username)]
        .into_iter()
        .collect();
    write_file(vault, path).await
}

fn encode_name(name: Username) -> ArrayString<64> {
    fn byte_to_hex(byte: u8) -> u8 {
        match byte {
            0..=9 => b'0' + byte,
            10..=15 => b'a' + byte - 10,
            _ => unreachable!(),
        }
    }

    let mut result = ArrayString::new();
    for byte in name.as_bytes() {
        result.push(byte_to_hex(byte >> 4) as char);
        result.push(byte_to_hex(byte & 0xf) as char);
    }

    result
}

async fn read_file(path: PathBuf) -> Result<impl IntoResponse, StatusCode> {
    let file = tokio::fs::File::open(&path).await;

    if let Err(err) = &file {
        if err.kind() == std::io::ErrorKind::NotFound {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    let file = file
        .context("failed to open file")
        .map_err(super::internal)?;

    let size = file
        .metadata()
        .await
        .context("failed to read metadata")
        .map_err(super::internal)?
        .len();

    let good_size = size.min(1 << 16) as usize;

    Ok(AsyncReadBody::with_capacity(file, good_size))
}

async fn write_file(vault: axum::body::Body, path: PathBuf) -> Result<(), StatusCode> {
    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .context("failed to create directory")
        .map_err(super::internal)?;

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .await
        .context("failed to open file")
        .map_err(super::internal)?;

    let mut file = tokio::io::BufWriter::new(file);
    let mut vault = std::pin::pin!(vault);
    while let Some(chunk) = std::future::poll_fn(|cx| vault.as_mut().poll_frame(cx)).await {
        let chunk = chunk
            .context("failed to read chunk")
            .map_err(super::internal)?;

        let Ok(chunk) = chunk.into_data() else {
            continue;
        };

        file.write_all(&chunk)
            .await
            .context("failed to write chunk")
            .map_err(super::internal)?;
    }

    file.flush()
        .await
        .context("failed to flush file")
        .map_err(super::internal)?;

    Ok(())
}

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub struct AsyncReadBody<T> {
    reader: T,
    progress: usize,
    buffer: Vec<u8>,
}

impl<T> IntoResponse for AsyncReadBody<T>
where
    T: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    fn into_response(self) -> askama_axum::Response {
        askama_axum::Response::new(axum::body::Body::new(self))
    }
}

impl<T> AsyncReadBody<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    /// Create a new [`AsyncReadBody`] wrapping the given reader,
    /// with a specific read buffer capacity
    fn with_capacity(read: T, capacity: usize) -> Self {
        Self {
            reader: read,
            progress: 0,
            buffer: vec![0; capacity],
        }
    }
}

impl<T> Body for AsyncReadBody<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let s = self.get_mut();
        let iner = Pin::new(&mut s.reader);

        let mut buf = tokio::io::ReadBuf::new(&mut s.buffer[s.progress..]);
        std::task::ready!(iner.poll_read(cx, &mut buf))?;
        let len = buf.filled().len();
        s.progress += len;

        if len == 0 && s.progress == 0 {
            return Poll::Ready(None);
        }

        if s.progress == s.buffer.len() {
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(
                s.buffer[..std::mem::take(&mut s.progress)].to_vec(),
            )))));
        }

        Poll::Pending
    }
}
