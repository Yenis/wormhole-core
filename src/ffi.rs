//! The UniFFI surface: what Kotlin (Android) and, via
//! uniffi-bindgen-react-native, TypeScript see of this crate.
//!
//! Thin wrappers over the generic functions in `lib.rs` — UniFFI cannot export
//! generics, so callbacks are funneled through the `TransferListener` trait,
//! which foreign code implements.

use std::sync::{Arc, Mutex};

use futures_lite::future::pending;

use crate::{Error, PendingReceive};

/// Implemented by the app (Kotlin/TypeScript) to observe a running transfer.
#[uniffi::export(with_foreign)]
pub trait TransferListener: Send + Sync {
    /// The wormhole code the receiver must use (fires once, senders only).
    fn on_code(&self, code: String);
    /// How the transit connection was established (direct vs relay).
    fn on_transit(&self, info: String);
    /// Bytes done / bytes total.
    fn on_progress(&self, done: u64, total: u64);
}

/// Send a file or folder. `code: None` generates a fresh code (reported via
/// `listener.on_code`); `code: Some(..)` opens the wormhole on that exact code
/// (paired-device flow).
#[uniffi::export]
pub async fn send_file(
    path: String,
    code: Option<String>,
    listener: Arc<dyn TransferListener>,
) -> Result<(), Error> {
    let code_listener = listener.clone();
    let transit_listener = listener.clone();
    crate::send_file(
        &path,
        code.as_deref(),
        move |code| code_listener.on_code(code),
        move |info| transit_listener.on_transit(info),
        move |done, total| listener.on_progress(done, total),
        pending::<()>(),
    )
    .await
}

/// Phase 0 test helper: write a `size_kb` KiB file into `dir` and return its
/// path, so the spike app has something to send without a filesystem library.
#[uniffi::export]
pub fn create_test_file(dir: String, size_kb: u32) -> Result<String, Error> {
    use std::io::Write;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = std::path::Path::new(&dir).join(format!("portalgems-test-{stamp}.bin"));
    let mut file = std::fs::File::create(&path)?;
    let mut block = [0u8; 1024];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    for _ in 0..size_kb {
        file.write_all(&block)?;
    }
    file.sync_all()?;
    Ok(path.to_string_lossy().into_owned())
}

/// A pending file offer. Inspect `file_name`/`file_size`, then `accept` into a
/// destination directory or `reject` to tell the sender you declined.
#[derive(uniffi::Object)]
pub struct IncomingFile {
    name: String,
    size: u64,
    request: Mutex<Option<PendingReceive>>,
}

/// Connect to the wormhole under `code` and wait for the sender's file offer,
/// without accepting it yet. This is what allows a confirmation UI.
#[uniffi::export]
pub async fn request_receive(code: String) -> Result<Arc<IncomingFile>, Error> {
    let pending_receive = crate::request_receive(&code, pending::<()>()).await?;
    Ok(Arc::new(IncomingFile {
        name: pending_receive.file_name.clone(),
        size: pending_receive.file_size,
        request: Mutex::new(Some(pending_receive)),
    }))
}

#[uniffi::export]
impl IncomingFile {
    pub fn file_name(&self) -> String {
        self.name.clone()
    }

    pub fn file_size(&self) -> u64 {
        self.size
    }

    /// Accept the offer, writing into `dest_dir`; returns the saved path.
    pub async fn accept(
        &self,
        dest_dir: String,
        listener: Arc<dyn TransferListener>,
    ) -> Result<String, Error> {
        let request = self
            .request
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::AlreadyConsumed)?;
        let transit_listener = listener.clone();
        let dest = request
            .accept(
                &dest_dir,
                move |info| transit_listener.on_transit(info),
                move |done, total| listener.on_progress(done, total),
                pending::<()>(),
            )
            .await?;
        Ok(dest.to_string_lossy().into_owned())
    }

    /// Decline the offer; the sender sees the transfer fail cleanly.
    pub async fn reject(&self) -> Result<(), Error> {
        let request = self
            .request
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::AlreadyConsumed)?;
        request.reject().await?;
        Ok(())
    }
}

/// Receive the file offered under `code` into `dest_dir`; returns the saved path.
#[uniffi::export]
pub async fn receive_file(
    code: String,
    dest_dir: String,
    listener: Arc<dyn TransferListener>,
) -> Result<String, Error> {
    let transit_listener = listener.clone();
    let path = crate::receive_file(
        &code,
        &dest_dir,
        move |info| transit_listener.on_transit(info),
        move |done, total| listener.on_progress(done, total),
        pending::<()>(),
    )
    .await?;
    Ok(path.to_string_lossy().into_owned())
}
