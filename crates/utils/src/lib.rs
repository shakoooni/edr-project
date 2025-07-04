
//! Utilities for ultra_edr: shared error enums, encryption, and logging.

#![deny(unsafe_code)]
#![deny(missing_docs)]
/// Utils module: shared error enums, encryption, and logging.

use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

/// Compute the SHA256 hash of a file at the given path.
pub fn file_sha256<P: AsRef<std::path::Path>>(path: P) -> Result<[u8; 32], std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

use log::{Record, Level, Metadata, LevelFilter};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::sync::Mutex;
use std::path::Path;

/// Binary redacted logger for EDR.
pub struct BinaryLogger {
    file: Mutex<std::fs::File>,
}

impl BinaryLogger {
    /// Initialize logger at the given path.
    pub fn init<P: AsRef<Path>>(path: P) -> Result<(), std::io::Error> {
        if let Some(parent) = path.as_ref().parent() {
            create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let logger = BinaryLogger { file: Mutex::new(file) };
        log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Info)).map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "logger set failed"))
    }
}

impl log::Log for BinaryLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut file = self.file.lock().unwrap();
            // Redact: only log level and message, no file/line/path
            let msg = format!("[{:?}] {}\n", record.level(), record.args());
            let _ = file.write_all(msg.as_bytes());
        }
    }
    fn flush(&self) {}
}
