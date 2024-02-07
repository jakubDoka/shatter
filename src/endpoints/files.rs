use std::path::PathBuf;

use anyhow::Context;
use axum::body::Body;
use axum::http::StatusCode;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use super::Session;

pub async fn set_vault(session: Session, vault: Body) -> Result<(), StatusCode> {
    let path = ["files", session.username.as_str(), "vault"]
        .into_iter()
        .collect::<PathBuf>();

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

    let mut stream = vault.into_data_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .context("failed to read chunk")
            .map_err(super::internal)?;
        file.write_all(&chunk)
            .await
            .context("failed to write chunk")
            .map_err(super::internal)?;
    }
    Ok(())
}
