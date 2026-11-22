//! Writing an archive: each member's header and data, then the end marker.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use std::io::{self, Read, Write};

use crate::encode::{Header, HeaderError};
use crate::header::BLOCK;

/// The most data read from a member's source at once.
const CHUNK: usize = 64 * 1024;

/// Writes a tar archive to any [`Write`]: each member's header, its data and
/// the padding to the next block, then, on [`finish`](Self::finish), the end
/// marker.
///
/// What goes into the archive, and in what order, is the caller's. A member
/// whose header cannot be encoded is refused before anything of it is
/// written, and the archive can go on. A failure while a member is being
/// written leaves the archive inside that member, so every later call fails
/// ([`WriteError::Broken`]).
///
/// ```
/// use ferrotape::{Header, Reader, Writer};
///
/// let mut writer = Writer::new(Vec::new());
/// writer.append(&Header::directory("docs/"), &b""[..])?;
/// writer.append(&Header::file("docs/readme.txt", 5), &b"hello"[..])?;
/// let archive = writer.finish()?;
///
/// let mut reader = Reader::new(&archive[..]);
/// let entry = reader.next_entry()?.expect("a directory");
/// assert_eq!(entry.path(), b"docs/");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Writer<W: Write> {
    inner: W,
    buffer: Vec<u8>,
    broken: bool,
}

impl<W: Write> Writer<W> {
    /// A writer appending to `inner`.
    pub fn new(inner: W) -> Writer<W> {
        Writer {
            inner,
            buffer: Vec::new(),
            broken: false,
        }
    }

    /// Appends a member: its header, then `data`, read until the header's
    /// size has been read, then the padding to the next block.
    ///
    /// A regular file's header states the size; every other kind of member
    /// carries no data, and `data` is not read. Bytes past the size are not
    /// read either, so `data` may go on to hold what follows.
    ///
    /// # Errors
    ///
    /// [`WriteError::Header`] where the header cannot be encoded, before
    /// anything is written; [`WriteError::Data`] where `data` fails or ends
    /// before the size, and [`WriteError::Io`] where the destination fails,
    /// each of which leaves the archive inside the member; and
    /// [`WriteError::Broken`] after either.
    pub fn append(&mut self, header: &Header, mut data: impl Read) -> Result<(), WriteError> {
        if self.broken {
            return Err(WriteError::Broken);
        }
        let blocks = header.encode().map_err(WriteError::Header)?;
        // From here until the padding, the archive is inside the member.
        self.broken = true;
        self.inner.write_all(&blocks).map_err(WriteError::Io)?;
        let size = header.size();
        if size > 0 {
            if self.buffer.is_empty() {
                self.buffer = vec![0; CHUNK];
            }
            let mut left = size;
            while left > 0 {
                let want = usize::try_from(left).map_or(CHUNK, |left| left.min(CHUNK));
                let chunk = self.buffer.get_mut(..want).ok_or(WriteError::Broken)?;
                let read = match data.read(chunk) {
                    Ok(0) => {
                        return Err(WriteError::Data(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            ShortData { size, left },
                        )));
                    }
                    Ok(read) => read,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(WriteError::Data(err)),
                };
                let written = chunk.get(..read).ok_or(WriteError::Broken)?;
                self.inner.write_all(written).map_err(WriteError::Io)?;
                left = left.saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
            }
            let padding = size.next_multiple_of(BLOCK as u64).saturating_sub(size);
            let zeros = [0u8; BLOCK];
            let padding = zeros
                .get(..usize::try_from(padding).unwrap_or(0))
                .unwrap_or_default();
            self.inner.write_all(padding).map_err(WriteError::Io)?;
        }
        self.broken = false;
        Ok(())
    }

    /// Ends the archive with its end marker, two zero blocks, flushes it, and
    /// returns the destination.
    ///
    /// [`into_inner`](Self::into_inner) returns the destination without the
    /// end marker, for a caller that writes what follows itself. Readers read
    /// an archive without one as ending after its last member.
    ///
    /// # Errors
    ///
    /// [`WriteError::Io`] where the destination fails, and
    /// [`WriteError::Broken`] where an earlier failure left the archive inside
    /// a member.
    pub fn finish(mut self) -> Result<W, WriteError> {
        if self.broken {
            return Err(WriteError::Broken);
        }
        self.inner
            .write_all(&[0u8; 2 * BLOCK])
            .and_then(|()| self.inner.flush())
            .map_err(WriteError::Io)?;
        Ok(self.inner)
    }

    /// Flushes the archive and returns the destination without the end
    /// marker, for a caller that goes on writing to it: another archive's
    /// members and that archive's end marker, for one.
    ///
    /// # Errors
    ///
    /// [`WriteError::Io`] where the destination fails to flush, and
    /// [`WriteError::Broken`] where an earlier failure left the archive inside
    /// a member.
    pub fn into_inner(mut self) -> Result<W, WriteError> {
        if self.broken {
            return Err(WriteError::Broken);
        }
        self.inner.flush().map_err(WriteError::Io)?;
        Ok(self.inner)
    }

    /// The destination.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
}

impl<W: Write> fmt::Debug for Writer<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer")
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

/// A member's data that ended before its size.
#[derive(Debug)]
struct ShortData {
    size: u64,
    left: u64,
}

impl fmt::Display for ShortData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the data ended {} bytes short of the member's size of {}",
            self.left, self.size,
        )
    }
}

impl core::error::Error for ShortData {}

/// Why a [`Writer`] could not write.
#[derive(Debug)]
#[non_exhaustive]
pub enum WriteError {
    /// The member's header cannot be encoded. Nothing of the member was
    /// written, and the archive can go on.
    Header(HeaderError),
    /// The member's data failed, or ended before its size
    /// ([`io::ErrorKind::UnexpectedEof`]).
    Data(io::Error),
    /// The destination failed.
    Io(io::Error),
    /// An earlier failure left the archive inside a member.
    Broken,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::Header(err) => write!(f, "the header cannot be written: {err}"),
            WriteError::Data(err) => write!(f, "the member's data could not be read: {err}"),
            WriteError::Io(err) => write!(f, "the archive could not be written: {err}"),
            WriteError::Broken => {
                f.write_str("an earlier failure left the archive inside a member")
            }
        }
    }
}

impl core::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            WriteError::Header(err) => Some(err),
            WriteError::Data(err) | WriteError::Io(err) => Some(err),
            WriteError::Broken => None,
        }
    }
}

impl From<WriteError> for io::Error {
    /// The destination's or the data's own error as it was; any other as
    /// [`io::ErrorKind::InvalidInput`], carrying the [`WriteError`].
    fn from(err: WriteError) -> io::Error {
        match err {
            WriteError::Data(err) | WriteError::Io(err) => err,
            other => io::Error::new(io::ErrorKind::InvalidInput, other),
        }
    }
}
