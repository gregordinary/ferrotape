//! The reader: a [`Decoder`] driven over a byte source, and the data of the
//! member it has reached.

use alloc::vec::Vec;
use std::io::{self, Read, Seek, SeekFrom};

use crate::decoder::{Chunk, Decoder, Step};
use crate::entry::Entry;
use crate::error::{Error, ErrorKind};
use crate::pax::PaxRecords;
use crate::settings::{GlobalHeaders, Level, Limits};

/// The most [`Reader::read_entry`] reserves before a member's data arrives.
///
/// A declared size is the archive's claim until the bytes arrive, so the
/// reservation is the smaller of it and this. The buffer grows from there with
/// what the archive holds. Members read whole are a few kilobytes in
/// practice, so this covers them in one allocation.
const RESERVE: usize = 64 * 1024;

/// The most read at once from a source to pass over bytes of it.
const SCRATCH: usize = 4096;

/// Passes over bytes of the source by seeking: up to the count asked for,
/// and no further than the source's end. Returns how many it passed over.
type SeekPast<R> = fn(&mut R, u64) -> io::Result<u64>;

/// A tar archive reader over any byte source.
///
/// [`next_entry`](Self::next_entry) yields each member in turn, and
/// [`data`](Self::data) reads the data of the member it yielded last. Long
/// names, long links, pax extended headers and global ones are read
/// internally. Every [`Entry`] is a member, with what its metadata states
/// already applied.
///
/// The source is read through as it arrives, and nothing is read twice. A read
/// a signal interrupts is retried. An archive can itself be a member of
/// another archive, read through [`Data`]. Its source fails with the outer
/// archive's [`Error`] where the outer archive fails, and that error is
/// returned as it was. A source that can seek can be passed over instead of
/// read through: [`seeking`](Self::seeking).
///
/// Settings are made on the reader before it reads:
///
/// - Its level, how strictly it reads: [`with_level`](Self::with_level)
/// - Its global-header mode, for a global extended header:
///   [`with_global_headers`](Self::with_global_headers)
/// - Its [`Limits`] on what it holds in memory: [`with_limits`](Self::with_limits)
///
/// Once a call fails, every later call fails with the same kind and offset.
/// The stream is then not at a place a header can be read from. A reader that
/// resumed past a refusal would read members no other reader sees. The
/// one exception is [`ErrorKind::EntryLimit`], a refusal made before anything
/// is read.
///
/// A reader is a [`Decoder`] driven over its source: a source that is not a
/// [`Read`] is read by driving a decoder directly.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    decoder: Decoder,
    /// Set where the source is passed over by seeking rather than read.
    seek: Option<SeekPast<R>>,
    /// The first failure, which every later call repeats.
    failed: Option<(u64, ErrorKind)>,
}

impl<R: Read> Reader<R> {
    /// A reader of the archive `inner` holds, from where `inner` stands. It
    /// reads at [`Level::Strict`], refuses a global header holding any record
    /// but `comment` ([`GlobalHeaders::Refuse`]), and has the default
    /// [`Limits`].
    ///
    /// Offsets are counted from where `inner` stands, the archive's start.
    pub fn new(inner: R) -> Reader<R> {
        Reader {
            inner,
            decoder: Decoder::new(),
            seek: None,
            failed: None,
        }
    }

    /// The same reader, reading at `level`.
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Reader<R> {
        self.decoder = self.decoder.with_level(level);
        self
    }

    /// The same reader, reading global extended headers as `globals` says.
    #[must_use]
    pub fn with_global_headers(mut self, globals: GlobalHeaders) -> Reader<R> {
        self.decoder = self.decoder.with_global_headers(globals);
        self
    }

    /// The same reader, held to `limits`.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Reader<R> {
        self.decoder = self.decoder.with_limits(limits);
        self
    }

    /// The next member, or `None` at the end of the archive.
    ///
    /// Whatever the previous member's data held that was not read is skipped
    /// first. At most one metadata member of each kind may precede a member:
    /// a second is refused, as is metadata the archive ends after.
    ///
    /// The archive ends at its first zero block. The second the format
    /// specifies is not insisted on, nor is either where the stream ends at a
    /// header boundary, as GNU tar tolerates. At [`Level::Strict`], the block
    /// after the first zero block is read, and refused where it holds
    /// anything but zeros ([`ErrorKind::TrailingData`]). A stream that ends
    /// before its first header is not an archive: [`ErrorKind::NotATar`].
    ///
    /// # Errors
    ///
    /// An [`Error`] naming what the archive breaks, or the source's failure.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        self.guarded(Reader::advance)
    }

    /// The current member's data, as a [`Read`] that ends where the data
    /// does.
    ///
    /// The next call to [`next_entry`](Self::next_entry) skips what is not
    /// read. Before the first member, and for a member that has no data, it
    /// reads nothing.
    ///
    /// For a [sparse](Entry::sparse) member, the file it stands for, of its
    /// [size](Entry::size). The stored regions are in place, with zeros in the
    /// holes between them, which the archive does not hold. The file can be
    /// far longer than the archive. [`stored_data`](Self::stored_data) reads
    /// the regions alone.
    pub fn data(&mut self) -> Data<'_, R> {
        Data {
            reader: self,
            stored: false,
        }
    }

    /// The current member's data as the archive stores it, as a [`Read`].
    ///
    /// For a [sparse](Entry::sparse) member, its regions' bytes in order,
    /// the holes passed over. An extractor that keeps holes copies each
    /// region's [length](crate::Region::length) to its
    /// [offset](crate::Region::offset) in the file. It then sets the file's
    /// length to the [real size](crate::Sparse::real_size). For any other
    /// member, the same as [`data`](Self::data).
    ///
    /// The two read through one position in the member's file: what one has
    /// passed, the other does not deliver. After the first region is read
    /// here, [`data`](Self::data) delivers the file from the end of that
    /// region.
    pub fn stored_data(&mut self) -> Data<'_, R> {
        Data {
            reader: self,
            stored: true,
        }
    }

    /// What remains of the current member's data, read whole, where it is at
    /// most `limit` bytes.
    ///
    /// For members a caller acts on as a unit, such as a manifest or a control
    /// file. Only the caller knows how large such a member can be. A member
    /// larger is refused on the size its header declares, before any of it is
    /// read. The reader can then go on to the next member. Otherwise what is returned
    /// is the whole of it, never a part: an archive that ends inside it is
    /// refused.
    ///
    /// A `limit` above half the largest allocation the target allows, 1 GiB
    /// on a 32-bit target, is read as that half.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::EntryLimit`] for a member larger than `limit`. Otherwise
    /// as [`next_entry`](Self::next_entry).
    pub fn read_entry(&mut self, limit: u64) -> Result<Vec<u8>, Error> {
        // A buffer that doubles as it grows asks for twice what it holds, so
        // what it may hold is bounded by half the largest allocation.
        let limit = limit.min(crate::settings::allocation_bound());
        self.guarded(|reader| {
            let size = reader.decoder.data_remaining();
            if size > limit {
                return Err(Error::new(
                    reader.decoder.offset(),
                    ErrorKind::EntryLimit { size, limit },
                ));
            }
            let reserve = usize::try_from(size).map_or(RESERVE, |size| size.min(RESERVE));
            let mut data = Vec::with_capacity(reserve);
            let mut chunk = [0u8; 8192];
            // Reading stops at the size checked against `limit`, where the
            // data ends, so what is held never passes the limit.
            let mut left = size;
            while left > 0 {
                let want = usize::try_from(left).map_or(chunk.len(), |left| left.min(chunk.len()));
                let got = reader.read_member(chunk.get_mut(..want).unwrap_or_default(), false)?;
                if got == 0 {
                    break;
                }
                data.extend(chunk.iter().take(got));
                left = left.saturating_sub(got as u64);
            }
            Ok(data)
        })
    }

    /// Reads the rest of the archive, then the stream after it to its end,
    /// refusing more than `limit` bytes there. The stream after the archive
    /// begins after its first zero block, or where the archive ends without
    /// one.
    ///
    /// Each member left is read as [`next_entry`](Self::next_entry) reads it,
    /// its data skipped. Nothing after the archive's end is part of the
    /// archive, but the stream it is read from can go on. The rest of the last
    /// record is padding. A compressed stream closes with the check over what
    /// it decoded, which covers the end marker and the members before it.
    /// Stopping at the marker leaves that check unread. Reading on to the end
    /// of the stream has the decoder beneath compare it.
    ///
    /// At [`Level::Strict`], what follows the end must be zeros
    /// ([`ErrorKind::TrailingData`]): GNU tar with `--ignore-zeros` reads
    /// members there.
    ///
    /// The stream after the end is decoded only to be checked or discarded.
    /// `limit` bounds what a stream can make that cost, since a little input
    /// can decompress to far more than any padding. A stream with more is
    /// refused at the offset just past the first byte over the limit.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::TrailingLimit`] for more than `limit` bytes after the
    /// archive. Otherwise as [`next_entry`](Self::next_entry).
    pub fn finish(&mut self, limit: u64) -> Result<(), Error> {
        self.guarded(|reader| {
            reader.decoder.finish(limit);
            // Once finishing, the decoder delivers no member, and ends where
            // the stream does.
            while reader.advance()?.is_some() {}
            Ok(())
        })
    }

    /// The records of a global extended header that follows the archive's
    /// last member, once [`next_entry`](Self::next_entry) has returned
    /// `None`. Empty where there is none.
    ///
    /// A global header before a member reaches the caller on that member,
    /// through [`Entry::global`]. One after the last member reaches the caller
    /// here.
    #[must_use]
    pub fn trailing_global(&self) -> &PaxRecords {
        self.decoder.trailing_global()
    }

    /// Runs `op`, unless an earlier call failed, and records its failure.
    fn guarded<T>(
        &mut self,
        op: impl FnOnce(&mut Reader<R>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if let Some((offset, kind)) = &self.failed {
            return Err(Error::new(*offset, kind.clone()));
        }
        let result = op(self);
        if let Err(err) = &result
            && !matches!(err.kind(), ErrorKind::EntryLimit { .. })
        {
            self.failed = Some((err.offset(), err.kind().clone()));
        }
        result
    }

    /// [`next_entry`](Self::next_entry), unguarded: the decoder driven until
    /// it yields a member or the archive ends.
    fn advance(&mut self) -> Result<Option<Entry>, Error> {
        loop {
            match self.decoder.step()? {
                Step::Read(buf) => match read(&mut self.inner, buf) {
                    Ok(got) => self.decoder.filled(got),
                    Err(err) => return Err(Error::from_source(self.decoder.offset(), err)),
                },
                Step::Skip(count) => {
                    let skipped = match self.seek {
                        Some(seek_past) => seek_past(&mut self.inner, count),
                        None => read_past(&mut self.inner, count),
                    };
                    match skipped {
                        Ok(skipped) => self.decoder.skipped(skipped),
                        Err(err) => return Err(Error::from_source(self.decoder.offset(), err)),
                    }
                }
                Step::Entry(entry) => return Ok(Some(entry)),
                Step::End => return Ok(None),
            }
        }
    }

    /// Reads the current member's data into `buf`: for a sparse member, its
    /// file with the holes, or, where `stored`, its regions alone.
    ///
    /// The part of `buf` the data's next stored bytes go to is filled whole,
    /// unless the stream ends inside it, which is refused.
    fn read_member(&mut self, buf: &mut [u8], stored: bool) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let chunk = if stored {
            self.decoder.stored_data()?
        } else {
            self.decoder.data()?
        };
        let room = buf.len() as u64;
        match chunk {
            Chunk::End => Ok(0),
            Chunk::Zeros(count) => {
                let count = usize::try_from(count.min(room)).unwrap_or(buf.len());
                let zeros = buf.get_mut(..count).unwrap_or_default();
                zeros.fill(0);
                self.decoder.data_read(zeros.len() as u64);
                Ok(zeros.len())
            }
            Chunk::Read(count) => {
                let count = usize::try_from(count.min(room)).unwrap_or(buf.len());
                let within = buf.get_mut(..count).unwrap_or_default();
                let mut filled = 0;
                while let Some(rest) = within.get_mut(filled..)
                    && !rest.is_empty()
                {
                    let got = read(&mut self.inner, rest)
                        .map_err(|err| Error::from_source(self.decoder.offset(), err))?;
                    self.decoder.data_read(got as u64);
                    if got == 0 {
                        // The stream has ended inside the data, which the
                        // decoder now refuses.
                        self.decoder.data()?;
                        break;
                    }
                    filled = filled.saturating_add(got);
                }
                Ok(filled)
            }
        }
    }
}

impl<R: Read + Seek> Reader<R> {
    /// A reader of the archive `inner` holds, from where `inner` stands, that
    /// seeks past what it does not deliver rather than reading it. It passes
    /// over the data of members the caller does not read, and padding.
    /// Otherwise as [`new`](Self::new).
    ///
    /// For an archive in a file, where most members' data is not wanted, or
    /// where a caller reads members' data later from
    /// [`Entry::data_offset`]. Seeking past a source's end succeeds where
    /// reading past it does not, so each seek is checked against the source's
    /// length. A member whose data the source does not hold is refused as
    /// reading would refuse it ([`ErrorKind::Truncated`]).
    pub fn seeking(inner: R) -> Reader<R> {
        let mut reader = Reader::new(inner);
        reader.seek = Some(seek_past::<R>);
        reader
    }
}

/// Reads from `inner` into `buf`, retrying a read a signal interrupted. The
/// archive can arrive over a pipe or a socket, in a process whose signal
/// handlers do not restart the calls they interrupt. An interruption is not a
/// broken archive. Returns how many bytes arrived, zero where the source has
/// ended.
fn read<R: Read>(inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match inner.read(buf) {
            Ok(got) => return Ok(got.min(buf.len())),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// Reads past up to `count` bytes of `inner`, at most [`SCRATCH`] at once.
/// Returns how many it passed over, zero where the source has ended.
fn read_past<R: Read>(inner: &mut R, count: u64) -> io::Result<u64> {
    let mut scratch = [0u8; SCRATCH];
    let want = usize::try_from(count).map_or(SCRATCH, |count| count.min(SCRATCH));
    let buf = scratch.get_mut(..want).unwrap_or_default();
    read(inner, buf).map(|got| got as u64)
}

/// Seeks `inner` past up to `count` bytes, no further than its end, and
/// returns how many it passed over.
///
/// The length is taken at each seek rather than once. A source that grows
/// while it is read is then limited to what it holds when the reader reaches
/// it, as reading would be.
fn seek_past<R: Seek>(inner: &mut R, count: u64) -> io::Result<u64> {
    let here = inner.stream_position()?;
    let end = inner.seek(SeekFrom::End(0))?;
    let skipped = end.saturating_sub(here).min(count);
    // `here + skipped` is at most `end`, so it cannot overflow.
    inner.seek(SeekFrom::Start(here.saturating_add(skipped)))?;
    Ok(skipped)
}

/// The data of a [`Reader`]'s current member, as a [`Read`]: as
/// [`Reader::data`] delivers it, or [`Reader::stored_data`].
///
/// A failure is the reader's [`Error`], converted by [`From`] into an
/// [`io::Error`] that carries it. The reader fails every later call as it
/// does.
#[derive(Debug)]
pub struct Data<'a, R> {
    reader: &'a mut Reader<R>,
    /// Whether a sparse member's regions are read alone.
    stored: bool,
}

impl<R: Read> Read for Data<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let stored = self.stored;
        self.reader
            .guarded(|reader| reader.read_member(buf, stored))
            .map_err(io::Error::from)
    }
}
