//! PortalGems wormhole engine: an app-shaped wrapper around magic-wormhole.rs.
//!
//! Phase 0 scope: prove send/receive interop with the reference CLI, including
//! sender-specified codes (the pairing prerequisite). The API is deliberately
//! shaped like the future UniFFI surface: plain async functions, callbacks for
//! code/transit/progress, and a small error enum.

use std::path::{Path, PathBuf};

use futures_lite::future::pending;

uniffi::setup_scaffolding!();

mod ffi;
pub use ffi::{create_test_file, IncomingFile, TransferListener};
use magic_wormhole::{
    transfer::{self, APP_CONFIG},
    transit::{self, Abilities, RelayHint, TransitInfo},
    MailboxConnection, Wormhole,
};

/// Number of wordlist words in generated codes (the CLI default).
pub const DEFAULT_CODE_LENGTH: usize = 2;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    #[error("invalid wormhole code: {0}")]
    InvalidCode(String),
    #[error("the transfer was cancelled")]
    Cancelled,
    #[error("this transfer was already accepted or rejected")]
    AlreadyConsumed,
    #[error(transparent)]
    Wormhole(#[from] magic_wormhole::WormholeError),
    #[error(transparent)]
    Transfer(#[from] transfer::TransferError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) fn default_relay_hints() -> Vec<RelayHint> {
    vec![
        RelayHint::from_urls(None, [transit::DEFAULT_RELAY_SERVER.parse().unwrap()])
            .expect("default relay URL is valid"),
    ]
}

pub(crate) fn describe_transit(info: &TransitInfo) -> String {
    format!("{:?} peer={}", info.conn_type, info.peer_addr)
}

/// Send a file (or folder). With `code: None` a fresh code is generated and
/// reported through `on_code`. With `code: Some(..)` the wormhole is opened on
/// that exact code (`allocate = true` claims the nameplate) — this is what
/// paired devices use to meet on a derived code without typing anything.
pub async fn send_file<F, G, H>(
    path: impl AsRef<Path>,
    code: Option<&str>,
    on_code: F,
    on_transit: G,
    progress: H,
) -> Result<(), Error>
where
    F: FnOnce(String),
    G: FnOnce(String),
    H: FnMut(u64, u64) + 'static,
{
    let path = path.as_ref();
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no file name",
            ))
        })?
        .to_string_lossy()
        .into_owned();

    let mailbox = match code {
        None => MailboxConnection::create(APP_CONFIG, DEFAULT_CODE_LENGTH).await?,
        Some(raw) => {
            let code = raw.parse().map_err(|_| Error::InvalidCode(raw.into()))?;
            MailboxConnection::connect(APP_CONFIG, code, true).await?
        },
    };
    on_code(mailbox.code().to_string());

    let wormhole = Wormhole::connect(mailbox).await?;
    transfer::send_file_or_folder(
        wormhole,
        default_relay_hints(),
        path,
        file_name,
        Abilities::ALL,
        |info| on_transit(describe_transit(&info)),
        progress,
        pending::<()>(),
    )
    .await?;
    Ok(())
}

/// Receive a file offered under `code` into `dest_dir`. The sender's file name
/// is sanitized and never overwrites an existing file. Returns the saved path.
pub async fn receive_file<G, H>(
    code: &str,
    dest_dir: impl AsRef<Path>,
    on_transit: G,
    progress: H,
) -> Result<PathBuf, Error>
where
    G: FnOnce(String),
    H: FnMut(u64, u64) + 'static,
{
    let parsed = code.parse().map_err(|_| Error::InvalidCode(code.into()))?;
    let mailbox = MailboxConnection::connect(APP_CONFIG, parsed, false).await?;
    let wormhole = Wormhole::connect(mailbox).await?;

    let request = transfer::request_file(
        wormhole,
        default_relay_hints(),
        Abilities::ALL,
        pending::<()>(),
    )
    .await?
    .ok_or(Error::Cancelled)?;

    let file_name = sanitize_file_name(&request.file_name());
    let (dest, mut file) = create_unique(dest_dir.as_ref(), &file_name).await?;
    request
        .accept(
            |info| on_transit(describe_transit(&info)),
            progress,
            &mut file,
            pending::<()>(),
        )
        .await?;
    Ok(dest)
}

/// Strip any path components the sender may have smuggled into the file name.
pub(crate) fn sanitize_file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| "received.bin".to_string())
}

/// Open `dir/name` for writing without clobbering: falls back to
/// `name (1)`, `name (2)`, … if the file already exists.
pub(crate) async fn create_unique(
    dir: &Path,
    name: &str,
) -> Result<(PathBuf, async_fs::File), Error> {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    for n in 0u32..1000 {
        let candidate = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        match async_fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not find a free file name",
    )))
}
