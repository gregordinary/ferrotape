//! The reader: the parser driven over a byte source, and the data of the
//! member it has reached.

use alloc::vec::Vec;
use std::io::{self, Read, Seek, SeekFrom};

use crate::entry::Entry;
use crate::error::{Error, ErrorKind, Truncation};
use crate::header::BLOCK;
use crate::parser::{Parser, Step};
use crate::pax::PaxRecords;
use crate::settings::{GlobalHeaders, Level, Limits};
use crate::sparse::Region;

/// [`BLOCK`] as the type sizes and offsets are counted in.
const BLOCK_LEN: u64 = BLOCK as u64;

/// The most [`Reader::read_entry`] reserves before a member's data arrives.
///
/// A declared size is the archive's claim until the bytes arrive, so the
/// reservation is the smaller of it and this, and the buffer grows from there
/// with what the archive holds. Members read whole are a few kilobytes in
/// practice, so this covers them in one allocation.
const RESERVE: usize = 64 * 1024;

/// Passes over bytes of the source by seeking: up to the count asked for,
/// and no further than the source's end. Returns how many it passed over.
type SeekPast<R> = fn(&mut R, u64) -> io::Result<u64>;

/// A tar archive reader over any byte source.
///
/// [`next_entry`](Self::next_entry) yields each member in turn, and
/// [`data`](Self::data) reads the data of the member it yielded last. Long
/// names, long links, pax extended headers and global ones are read
/// internally, so every [`Entry`] is a member, with what its metadata states
/// already applied.
///
/// The source is read through as it arrives, and nothing is read twice. A read
/// a signal interrupts is retried. A source of an archive that is itself a
/// member of another archive, read through [`Data`], fails with that archive's
/// [`Error`] where the outer archive fails, and that error is returned as it
/// was. A source that can seek can be passed over instead of read through:
/// [`seeking`](Self::seeking).
///
/// How strictly the archive is read, and what is done with global extended
/// headers, are set on the reader before it reads:
/// [`with_level`](Self::with_level),
/// [`with_global_headers`](Self::with_global_headers), and the [`Limits`] of
/// [`with_limits`](Self::with_limits).
///
/// Once a call fails, every later call fails with the same kind and offset:
/// the stream is no longer at a place a header can be read from, and a reader
/// that resumed past a refusal would read members no other reader sees. The
/// one exception is [`ErrorKind::EntryLimit`], a refusal made before anything
/// is read.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    parser: Parser,
    /// Set where the source is passed over by seeking rather than read.
    seek: Option<SeekPast<R>>,
    /// Bytes consumed from the stream.
    offset: u64,
    /// The current member's data not yet read.
    data_remaining: u64,
    /// The padding after the current member's data.
    padding: u64,
    /// The first failure, which every later call repeats.
    failed: Option<(u64, ErrorKind)>,
    /// Where reading the current member's file stands, for a sparse member.
    expand: Option<Expand>,
}

/// Where reading a sparse member's file stands: the position in the file,
/// which both [`Reader::data`] and [`Reader::stored_data`] move.
#[derive(Debug)]
struct Expand {
    regions: Vec<Region>,
    /// The first region that does not end at or before `position`.
    next: usize,
    position: u64,
    real_size: u64,
}

/// What the next read of a sparse member's file delivers.
enum Next {
    /// This many zeros, of a hole.
    Zeros(u64),
    /// Up to this many stored bytes, of a region.
    Stored(u64),
    /// Nothing: the file, or what is stored of it, has been read.
    End,
}

impl Expand {
    /// What a read delivers next: the file with its holes, or, where
    /// `stored`, its regions alone, the holes passed over.
    fn next(&mut self, stored: bool) -> Next {
        while self
            .regions
            .get(self.next)
            .is_some_and(|region| region.end() <= self.position)
        {
            self.next = self.next.saturating_add(1);
        }
        match self.regions.get(self.next) {
            Some(region) => {
                if stored {
                    self.position = self.position.max(region.offset);
                } else if self.position < region.offset {
                    return Next::Zeros(region.offset.saturating_sub(self.position));
                }
                Next::Stored(region.end().saturating_sub(self.position))
            }
            None if !stored && self.position < self.real_size => {
                Next::Zeros(self.real_size.saturating_sub(self.position))
            }
            None => Next::End,
        }
    }

    /// What remains of the file past the position.
    fn remaining(&self) -> u64 {
        self.real_size.saturating_sub(self.position)
    }
}

impl<R: Read> Reader<R> {
    /// A reader of the archive `inner` holds, from where `inner` stands, at
    /// [`Level::Strict`], refusing global headers that set any record but
    /// `comment` ([`GlobalHeaders::Refuse`]), with the default [`Limits`].
    ///
    /// Offsets are counted from where `inner` stands, the archive's start.
    pub fn new(inner: R) -> Reader<R> {
        Reader {
            inner,
            parser: Parser::new(),
            seek: None,
            offset: 0,
            data_remaining: 0,
            padding: 0,
            failed: None,
            expand: None,
        }
    }

    /// The same reader, reading at `level`.
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Reader<R> {
        self.parser.set_level(level);
        self
    }

    /// The same reader, reading global extended headers as `globals` says.
    #[must_use]
    pub fn with_global_headers(mut self, globals: GlobalHeaders) -> Reader<R> {
        self.parser.set_globals(globals);
        self
    }

    /// The same reader, held to `limits`.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Reader<R> {
        self.parser.set_limits(limits);
        self
    }

    /// The next member, or `None` at the end of the archive.
    ///
    /// Whatever the previous member's data held that was not read is skipped
    /// first. At most one metadata member of each kind may precede a member:
    /// a second is refused, as is metadata the archive ends after.
    ///
    /// The archive ends at its first zero block; the second the format
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
    /// What is not read is skipped by the next call to
    /// [`next_entry`](Self::next_entry). Before the first member, and for a
    /// member that carries no data, it reads nothing.
    ///
    /// For a [sparse](Entry::sparse) member, the file it stands for: its
    /// [size](Entry::size), the stored regions in place and zeros in the
    /// holes between them, which the archive does not hold. That can be far
    /// more than the archive's length; [`stored_data`](Self::stored_data)
    /// reads the regions alone.
    pub fn data(&mut self) -> Data<'_, R> {
        Data {
            reader: self,
            stored: false,
        }
    }

    /// The current member's data as the archive stores it, as a [`Read`].
    ///
    /// For a [sparse](Entry::sparse) member, its regions' bytes in order,
    /// the holes passed over: an extractor that keeps holes copies each
    /// region's [length](crate::Region::length) to its
    /// [offset](crate::Region::offset) in the file, then sets the file's
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
    /// For members a caller acts on as a unit, a manifest or a control file;
    /// only the caller knows how large such a member may be. A member larger
    /// is refused on the size its header declares, before any of it is read,
    /// and the reader can go on to the next member. Otherwise what is returned
    /// is the whole of it, never a part: an archive that ends inside it is
    /// refused.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::EntryLimit`] for a member larger than `limit`; otherwise
    /// as [`next_entry`](Self::next_entry).
    pub fn read_entry(&mut self, limit: u64) -> Result<Vec<u8>, Error> {
        self.guarded(|reader| {
            let size = reader
                .expand
                .as_ref()
                .map_or(reader.data_remaining, Expand::remaining);
            if size > limit {
                return Err(Error::new(
                    reader.offset,
                    ErrorKind::EntryLimit { size, limit },
                ));
            }
            reader.read_member_whole()
        })
    }

    /// Reads the rest of the archive, then the stream after it to its end,
    /// refusing more than `limit` bytes there: after the archive's first zero
    /// block, or where it ends without one.
    ///
    /// Each member left is read as [`next_entry`](Self::next_entry) reads it,
    /// its data skipped. Nothing after the archive's end is part of the
    /// archive, but the stream it is read from may go on: the rest of the
    /// last record is padding, and a compressed stream closes with the check
    /// over what it decoded, which covers the end marker and the members
    /// before it. Stopping at the marker leaves that check unread. Reading on
    /// to the end of the stream has the decoder beneath compare it.
    ///
    /// At [`Level::Strict`], what follows the end must be zeros
    /// ([`ErrorKind::TrailingData`]): GNU tar with `--ignore-zeros` reads
    /// members there.
    ///
    /// What follows the end is decoded only to be checked or discarded, so
    /// `limit` bounds what a stream can make that cost: a little input can
    /// decompress to far more than any padding.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::TrailingLimit`] for more than `limit` bytes after the
    /// archive; otherwise as [`next_entry`](Self::next_entry).
    pub fn finish(&mut self, limit: u64) -> Result<(), Error> {
        self.guarded(|reader| {
            while reader.advance()?.is_some() {}
            let zeros_only = reader.parser.level() == Level::Strict;
            // At Strict the parser has read a block past the end already.
            let over = || Error::new(reader.offset, ErrorKind::TrailingLimit { limit });
            let mut remaining = limit
                .checked_sub(reader.offset.saturating_sub(reader.parser.end()))
                .ok_or_else(over)?;
            let mut scratch = [0u8; 4096];
            loop {
                let at = reader.offset;
                let got = match reader.inner.read(&mut scratch) {
                    Ok(0) => return Ok(()),
                    Ok(got) => got.min(scratch.len()),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(Error::from_source(reader.offset, err)),
                };
                reader.offset = reader.offset.saturating_add(got as u64);
                if zeros_only
                    && let Some(first) = scratch.iter().take(got).position(|byte| *byte != 0)
                {
                    return Err(Error::new(
                        at.saturating_add(first as u64),
                        ErrorKind::TrailingData,
                    ));
                }
                remaining = remaining
                    .checked_sub(got as u64)
                    .ok_or_else(|| Error::new(reader.offset, ErrorKind::TrailingLimit { limit }))?;
            }
        })
    }

    /// The records of a global extended header that follows the archive's
    /// last member, once [`next_entry`](Self::next_entry) has returned
    /// `None`. Empty where there is none.
    ///
    /// A global header before a member reaches the caller on that member,
    /// through [`Entry::global`]; one after the last member has none to reach
    /// the caller on.
    #[must_use]
    pub fn trailing_global(&self) -> &PaxRecords {
        self.parser.trailing_global()
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

    /// [`next_entry`](Self::next_entry), unguarded: the parser driven until
    /// it yields a member or the archive ends.
    fn advance(&mut self) -> Result<Option<Entry>, Error> {
        if self.parser.ended() {
            return Ok(None);
        }
        self.skip_current()?;
        let mut step = Step::Block;
        loop {
            step = match step {
                Step::Block => {
                    let at = self.offset;
                    let mut block = [0u8; BLOCK];
                    let got = self.fill(&mut block)?;
                    let bytes = block.get(..got).unwrap_or(&block);
                    self.parser.block(at, bytes)?
                }
                Step::Metadata(request) => {
                    self.expect(request.size());
                    let data = self.read_remaining()?;
                    self.skip_current()?;
                    self.parser.metadata(request, data)?
                }
                Step::Member(entry) => {
                    self.expect(entry.stored_len());
                    self.expand = entry.sparse().map(|map| Expand {
                        regions: map.regions().to_vec(),
                        next: 0,
                        position: 0,
                        real_size: map.real_size(),
                    });
                    return Ok(Some(entry));
                }
                Step::End => return Ok(None),
            };
        }
    }

    /// Frames what follows a header that declares `size` bytes of data: the
    /// data, and the padding to the next block.
    fn expect(&mut self, size: u64) {
        self.data_remaining = size;
        // The distance to the next multiple of the block size. 2^64 is a
        // multiple of it, so the negation's remainder is that distance.
        self.padding = size.wrapping_neg() % BLOCK_LEN;
    }

    /// What remains of the current member's data, as [`data`](Self::data)
    /// delivers it, held whole.
    fn read_member_whole(&mut self) -> Result<Vec<u8>, Error> {
        if self.expand.is_none() {
            return self.read_remaining();
        }
        let remaining = self.expand.as_ref().map_or(0, Expand::remaining);
        let reserve = usize::try_from(remaining).map_or(RESERVE, |size| size.min(RESERVE));
        let mut data = Vec::with_capacity(reserve);
        let mut chunk = [0u8; 8192];
        loop {
            let got = self.read_member(&mut chunk, false)?;
            if got == 0 {
                return Ok(data);
            }
            data.extend(chunk.iter().take(got));
        }
    }

    /// Reads the current member's data into `buf`: for a sparse member, its
    /// file with the holes, or, where `stored`, its regions alone.
    fn read_member(&mut self, buf: &mut [u8], stored: bool) -> Result<usize, Error> {
        let Some(expand) = self.expand.as_mut() else {
            return self.read_data(buf);
        };
        let room = buf.len() as u64;
        match expand.next(stored) {
            Next::End => Ok(0),
            Next::Zeros(count) => {
                let count = count.min(room);
                let zeros = usize::try_from(count).unwrap_or(buf.len());
                let filled = buf.get_mut(..zeros).unwrap_or_default();
                filled.fill(0);
                expand.position = expand.position.saturating_add(count);
                Ok(filled.len())
            }
            Next::Stored(count) => {
                let count = usize::try_from(count.min(room)).unwrap_or(buf.len());
                let within = buf.get_mut(..count).unwrap_or_default();
                let got = self.read_data(within)?;
                if let Some(expand) = self.expand.as_mut() {
                    expand.position = expand.position.saturating_add(got as u64);
                }
                Ok(got)
            }
        }
    }

    /// What remains of the current member's data, held whole.
    fn read_remaining(&mut self) -> Result<Vec<u8>, Error> {
        let reserve =
            usize::try_from(self.data_remaining).map_or(RESERVE, |size| size.min(RESERVE));
        let mut data = Vec::with_capacity(reserve);
        let mut chunk = [0u8; 8192];
        // Each read delivers at least one byte or fails, so this ends.
        while self.data_remaining > 0 {
            let got = self.read_data(&mut chunk)?;
            data.extend(chunk.iter().take(got));
        }
        Ok(data)
    }

    /// Reads the current member's data into `buf`, as far as either reaches.
    fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let remaining = usize::try_from(self.data_remaining).unwrap_or(usize::MAX);
        let buf = match buf.split_at_mut_checked(remaining) {
            Some((within, _)) => within,
            None => buf,
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let got = self.fill(buf)?;
        self.data_remaining = self.data_remaining.saturating_sub(got as u64);
        // Every byte asked for is one the member declares.
        if got < buf.len() {
            return Err(Error::new(
                self.offset,
                ErrorKind::Truncated(Truncation::Data),
            ));
        }
        Ok(got)
    }

    /// Skips what remains of the current member: its unread data, then its
    /// padding.
    fn skip_current(&mut self) -> Result<(), Error> {
        self.expand = None;
        let data = core::mem::take(&mut self.data_remaining);
        let padding = core::mem::take(&mut self.padding);
        // At most a header's size field and a block, which a `u64` holds.
        self.skip(data.saturating_add(padding))
    }

    /// Passes over `count` bytes of the member's data and padding: by seeking
    /// where the reader was made to, and otherwise by reading them.
    fn skip(&mut self, count: u64) -> Result<(), Error> {
        if count == 0 {
            return Ok(());
        }
        let skipped = match self.seek {
            Some(seek_past) => {
                let skipped = seek_past(&mut self.inner, count)
                    .map_err(|err| Error::from_source(self.offset, err))?;
                self.offset = self.offset.saturating_add(skipped);
                skipped
            }
            None => self.read_past(count)?,
        };
        if skipped < count {
            return Err(Error::new(
                self.offset,
                ErrorKind::Truncated(Truncation::Data),
            ));
        }
        Ok(())
    }

    /// Reads past up to `count` bytes, returning how many the source held.
    fn read_past(&mut self, count: u64) -> Result<u64, Error> {
        let mut scratch = [0u8; 4096];
        let mut skipped: u64 = 0;
        while skipped < count {
            let want = usize::try_from(count.saturating_sub(skipped)).unwrap_or(usize::MAX);
            let buf = match scratch.split_at_mut_checked(want) {
                Some((within, _)) => within,
                None => scratch.as_mut_slice(),
            };
            let got = self.fill(buf)?;
            skipped = skipped.saturating_add(got as u64);
            if got < buf.len() {
                break;
            }
        }
        Ok(skipped)
    }

    /// Fills `buf` from the source as far as it reaches, retrying a read a
    /// signal interrupted: the archive may arrive over a pipe or a socket, in
    /// a process whose signal handlers do not restart the calls they
    /// interrupt, and an interruption is not a broken archive.
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut filled = 0;
        while let Some(rest) = buf.get_mut(filled..)
            && !rest.is_empty()
        {
            match self.inner.read(rest) {
                Ok(0) => break,
                Ok(got) => {
                    let got = got.min(rest.len());
                    filled = filled.saturating_add(got);
                    self.offset = self.offset.saturating_add(got as u64);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(Error::from_source(self.offset, err)),
            }
        }
        Ok(filled)
    }
}

impl<R: Read + Seek> Reader<R> {
    /// A reader of the archive `inner` holds, from where `inner` stands,
    /// that passes over what it does not deliver by seeking rather than
    /// reading: the data of members the caller does not read, and padding.
    /// Otherwise as [`new`](Self::new).
    ///
    /// For an archive in a file, where most members' data is not wanted, or
    /// where a caller reads members' data later from
    /// [`Entry::data_offset`]. Seeking past a source's end succeeds where
    /// reading past it does not, so each seek is checked against the source's
    /// length, and a member whose data the source does not hold is refused as
    /// reading would refuse it ([`ErrorKind::Truncated`]).
    pub fn seeking(inner: R) -> Reader<R> {
        let mut reader = Reader::new(inner);
        reader.seek = Some(seek_past::<R>);
        reader
    }
}

/// Seeks `inner` past up to `count` bytes, no further than its end, and
/// returns how many it passed over.
///
/// The length is taken at each seek rather than once, so a source that grows
/// while it is read is held to what it holds when the reader reaches it, as
/// reading would be.
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
/// A failure is the reader's [`Error`], carried in the [`io::Error`] its
/// [`From`] conversion makes, and the reader fails every later call as it
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
