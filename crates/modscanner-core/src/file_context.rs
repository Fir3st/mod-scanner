use crate::engine::FileContext;
use memmap2::Mmap;
use std::fs::{self, File};
use std::path::Path;

const MMAP_THRESHOLD: u64 = 64 * 1024; // 64 KB
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
const TEXT_CHECK_SIZE: usize = 8192;

/// Error loading a file for scanning
#[derive(Debug, thiserror::Error)]
pub enum FileLoadError {
    #[error("file too large: {0} bytes (max {MAX_FILE_SIZE})")]
    TooLarge(u64),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Holds owned file data (either mmap'd or read into memory)
pub enum FileData {
    Mapped(Mmap),
    InMemory(Vec<u8>),
}

impl AsRef<[u8]> for FileData {
    fn as_ref(&self) -> &[u8] {
        match self {
            FileData::Mapped(m) => m.as_ref(),
            FileData::InMemory(v) => v.as_slice(),
        }
    }
}

/// Determines if data looks like text (no null bytes in the first N bytes)
fn is_likely_text(data: &[u8]) -> bool {
    let check_len = data.len().min(TEXT_CHECK_SIZE);
    let slice = &data[..check_len];
    // Text files don't contain null bytes or most control chars (except \t, \n, \r)
    !slice.contains(&0)
}

/// Load a file and return owned data + metadata
pub fn load_file(path: &Path) -> Result<(FileData, u64), FileLoadError> {
    let metadata = fs::metadata(path)?;
    let size = metadata.len();

    if size > MAX_FILE_SIZE {
        return Err(FileLoadError::TooLarge(size));
    }

    if size == 0 {
        return Ok((FileData::InMemory(Vec::new()), 0));
    }

    let data = if size >= MMAP_THRESHOLD {
        let file = File::open(path)?;
        // SAFETY: read-only mmap, file won't be modified during scan
        let mmap = unsafe { Mmap::map(&file)? };
        FileData::Mapped(mmap)
    } else {
        let bytes = fs::read(path)?;
        FileData::InMemory(bytes)
    };

    Ok((data, size))
}

/// Build a FileContext from loaded file data
pub fn build_context<'a>(path: &'a Path, data: &'a [u8], size: u64) -> FileContext<'a> {
    let extension = path.extension().and_then(|e| e.to_str());
    let is_text = is_likely_text(data);

    FileContext {
        path,
        extension,
        size,
        data,
        is_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_likely_text() {
        assert!(is_likely_text(b"hello world\n"));
        assert!(is_likely_text(b"line1\r\nline2\ttab"));
        assert!(!is_likely_text(b"hello\x00world"));
        assert!(is_likely_text(b""));
    }
}
