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
/// that exact code (`allocate = true` claims the nameplate) - this is what
/// paired devices use to meet on a derived code without typing anything.
pub async fn send_file<F, G, H>(
    path: impl AsRef<Path>,
    code: Option<&str>,
    on_code: F,
    on_transit: G,
    progress: H,
    cancel: impl std::future::Future<Output = ()>,
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

    // Race the whole pipeline against `cancel`: a sender waiting for its
    // receiver blocks inside Wormhole::connect (the PAKE needs a peer), so
    // cancellation must cover more than just the transfer phase.
    let work = async {
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
    };
    futures_lite::future::or(work, async {
        cancel.await;
        Err(Error::Cancelled)
    })
    .await
}

/// A file offer that has been received but not yet accepted: the platform
/// bindings build their confirmation UIs on top of this.
pub struct PendingReceive {
    pub file_name: String,
    pub file_size: u64,
    request: transfer::ReceiveRequest,
}

/// Connect to the wormhole under `code` and wait for the sender's offer,
/// without accepting it.
pub async fn request_receive(
    code: &str,
    cancel: impl std::future::Future<Output = ()>,
) -> Result<PendingReceive, Error> {
    let work = async {
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

        Ok(PendingReceive {
            file_name: sanitize_file_name(&request.file_name()),
            file_size: request.file_size(),
            request,
        })
    };
    futures_lite::future::or(work, async {
        cancel.await;
        Err(Error::Cancelled)
    })
    .await
}

impl PendingReceive {
    /// Accept the offer, writing into `dest_dir`; returns the saved path.
    pub async fn accept<G, H>(
        self,
        dest_dir: impl AsRef<Path>,
        on_transit: G,
        progress: H,
        cancel: impl std::future::Future<Output = ()>,
    ) -> Result<PathBuf, Error>
    where
        G: FnOnce(String),
        H: FnMut(u64, u64) + 'static,
    {
        let (dest, mut file) = create_unique(dest_dir.as_ref(), &self.file_name).await?;
        self.request
            .accept(
                |info| on_transit(describe_transit(&info)),
                progress,
                &mut file,
                cancel,
            )
            .await?;
        Ok(dest)
    }

    /// Decline the offer; the sender sees the transfer fail cleanly.
    pub async fn reject(self) -> Result<(), Error> {
        self.request.reject().await?;
        Ok(())
    }
}

/// Receive a file offered under `code` into `dest_dir`. The sender's file name
/// is sanitized and never overwrites an existing file. Returns the saved path.
pub async fn receive_file<G, H>(
    code: &str,
    dest_dir: impl AsRef<Path>,
    on_transit: G,
    progress: H,
    cancel: impl std::future::Future<Output = ()>,
) -> Result<PathBuf, Error>
where
    G: FnOnce(String),
    H: FnMut(u64, u64) + 'static,
{
    let pending_receive = request_receive(code, pending::<()>()).await?;
    pending_receive
        .accept(dest_dir, on_transit, progress, cancel)
        .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_components_and_empties() {
        assert_eq!(sanitize_file_name("normal.jpg"), "normal.jpg");
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("/abs/path/file.txt"), "file.txt");
        assert_eq!(sanitize_file_name(""), "received.bin");
        assert_eq!(sanitize_file_name(".."), "received.bin");
        assert_eq!(sanitize_file_name("."), "received.bin");
    }

    #[test]
    fn create_unique_never_clobbers() {
        futures_lite::future::block_on(async {
            let dir = std::env::temp_dir().join(format!("pg-core-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let (p1, _) = create_unique(&dir, "a.txt").await.unwrap();
            let (p2, _) = create_unique(&dir, "a.txt").await.unwrap();
            let (p3, _) = create_unique(&dir, "a.txt").await.unwrap();
            assert_eq!(p1.file_name().unwrap(), "a.txt");
            assert_eq!(p2.file_name().unwrap(), "a (1).txt");
            assert_eq!(p3.file_name().unwrap(), "a (2).txt");
            // extensionless names get plain " (n)" suffixes too
            let (q1, _) = create_unique(&dir, "noext").await.unwrap();
            let (q2, _) = create_unique(&dir, "noext").await.unwrap();
            assert_eq!(q1.file_name().unwrap(), "noext");
            assert_eq!(q2.file_name().unwrap(), "noext (1)");
            std::fs::remove_dir_all(&dir).ok();
        });
    }

    #[test]
    fn create_test_file_writes_requested_size() {
        let dir = std::env::temp_dir();
        let path = create_test_file(dir.to_string_lossy().into_owned(), 4).unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        std::fs::remove_file(&path).ok();
        assert_eq!(len, 4 * 1024);
    }

    /// Full network round-trip against the public mailbox server; run with
    /// `cargo test -- --ignored` when online.
    #[test]
    #[ignore]
    fn roundtrip_over_public_server() {
        futures_lite::future::block_on(async {
            let dir = std::env::temp_dir().join(format!("pg-rt-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let src = create_test_file(dir.to_string_lossy().into_owned(), 64).unwrap();
            let code = format!(
                "9{}-integration-test",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
                    % 1_000_000
            );
            let send_code = code.clone();
            let src_clone = src.clone();
            let sender = std::thread::spawn(move || {
                futures_lite::future::block_on(send_file(
                    &src_clone,
                    Some(&send_code),
                    |_| {},
                    |_| {},
                    |_, _| {},
                    futures_lite::future::pending::<()>(),
                ))
            });
            std::thread::sleep(std::time::Duration::from_secs(2));
            let dest = receive_file(&code, &dir, |_| {}, |_, _| {}, futures_lite::future::pending::<()>())
                .await
                .unwrap();
            sender.join().unwrap().unwrap();
            assert_eq!(std::fs::read(&src).unwrap(), std::fs::read(&dest).unwrap());
            std::fs::remove_dir_all(&dir).ok();
        });
    }
}
