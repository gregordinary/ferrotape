//! The reader without I/O: an archive handed over as its bytes arrive, every
//! member and its data framed by the decoder, never by its caller.

use alloc::vec::Vec;

use crate::entry::Entry;
use crate::error::{Error, ErrorKind, Truncation};
use crate::header::BLOCK;
use crate::parser::{self, Parser, Request};
use crate::pax::PaxRecords;
use crate::settings::{GlobalHeaders, Level, Limits};
use crate::sparse::Region;

/// [`BLOCK`] as the type sizes and offsets are counted in.
const BLOCK_LEN: u64 = BLOCK as u64;

/// The most room made at once for a metadata member's data.
///
/// A declared size is the archive's claim until the bytes arrive. The buffer
/// grows by this much at a time, with what the archive holds. Metadata
/// is a few kilobytes in practice, so this covers it in one step.
const RESERVE: u64 = 64 * 1024;

/// A tar archive reader that performs no I/O: its caller moves the bytes.
///
/// A [`Reader`](crate::Reader) is a `Decoder` driven over a
/// [`Read`](std::io::Read). A source that a `Read` does not fit (an
/// asynchronous stream, a buffer an interrupt fills, an archive in memory in
/// a build without `std`) is read by driving a `Decoder` directly. Its
/// [`step`](Self::step) says what to do:
///
/// - [`Step::Read`]: copy the stream's next bytes into the buffer it lends,
///   as many as are at hand, and report how many with
///   [`filled`](Self::filled).
/// - [`Step::Skip`]: pass over the stream's next bytes, by reading them or by
///   seeking, and report how many with [`skipped`](Self::skipped).
/// - [`Step::Entry`]: a member, whose data follows in the stream. The next
///   call to [`step`](Self::step) passes over whatever of it was not read.
/// - [`Step::End`]: the archive has ended.
///
/// A member's data is read by asking [`data`](Self::data) how much of it to
/// read now, or how many zeros a sparse member's hole holds. What was read is
/// reported with [`data_read`](Self::data_read).
///
/// A count of zero reports that the stream has ended. The decoder counts
/// every byte, and itself frames every member's data and the padding after
/// it. A driver never computes a size or an offset, so it cannot fall out of
/// step with the archive however its reads are split. Asking again
/// before reporting anything asks for the same thing, so a driver whose read
/// is not ready can ask again when it is.
///
/// Every reading rule of [`Reader`](crate::Reader) is the decoder's, with
/// the same refusals at the same offsets, and the same settings:
/// [`with_level`](Self::with_level),
/// [`with_global_headers`](Self::with_global_headers) and
/// [`with_limits`](Self::with_limits). Once a call refuses the archive, every
/// later call fails with the same kind and offset.
///
/// An archive in memory, read without `std`:
///
/// ```
/// use ferrotape::{Chunk, Decoder, Step};
///
/// /// The regular files of an archive held in memory, as (path, data).
/// fn files(archive: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ferrotape::Error> {
///     let mut decoder = Decoder::new();
///     let mut rest = archive;
///     let mut files = Vec::new();
///     loop {
///         match decoder.step()? {
///             Step::Read(buf) => {
///                 let count = buf.len().min(rest.len());
///                 let (bytes, after) = rest.split_at(count);
///                 buf[..count].copy_from_slice(bytes);
///                 rest = after;
///                 decoder.filled(count);
///             }
///             Step::Skip(count) => {
///                 let count = usize::try_from(count).map_or(rest.len(), |c| c.min(rest.len()));
///                 rest = &rest[count..];
///                 decoder.skipped(count as u64);
///             }
///             Step::Entry(entry) if entry.kind() == ferrotape::EntryKind::File => {
///                 let mut data = Vec::new();
///                 loop {
///                     match decoder.data()? {
///                         Chunk::Read(count) => {
///                             let count = usize::try_from(count)
///                                 .map_or(rest.len(), |c| c.min(rest.len()));
///                             let (bytes, after) = rest.split_at(count);
///                             data.extend_from_slice(bytes);
///                             rest = after;
///                             decoder.data_read(count as u64);
///                         }
///                         Chunk::Zeros(count) => {
///                             data.resize(data.len() + count as usize, 0);
///                             decoder.data_read(count);
///                         }
///                         Chunk::End => break,
///                     }
///                 }
///                 files.push((entry.path().to_vec(), data));
///             }
///             Step::Entry(_) => {}
///             Step::End => return Ok(files),
///         }
///     }
/// }
/// # use ferrotape::{Header, Writer};
/// # let mut writer = Writer::new(Vec::new());
/// # writer.append(&Header::directory("docs/"), std::io::empty())?;
/// # writer.append(&Header::file("docs/a.txt", 2), &b"hi"[..])?;
/// # let archive = writer.finish()?;
/// # assert_eq!(files(&archive)?, [(b"docs/a.txt".to_vec(), b"hi".to_vec())]);
/// # let refused = files(&archive[..1000]).expect_err("cut inside a's data");
/// # assert_eq!(refused.offset(), 1000);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Decoder {
    parser: Parser,
    /// Bytes of the stream reported so far: filled, passed over, or read as
    /// a member's data.
    offset: u64,
    /// What the decoder waits for.
    want: Want,
    /// The block being filled: a header, the block after the archive's end
    /// at [`Level::Strict`], a block of a sparse map, or what follows the
    /// archive.
    block: [u8; BLOCK],
    /// How much of `block` has been filled.
    filled: usize,
    /// Set when [`step`](Self::step) answers [`Step::Read`], until
    /// [`filled`](Self::filled) answers it.
    reading: bool,
    /// Set by a count of zero: the stream has ended.
    ended: bool,
    /// The limit [`finish`](Self::finish) set, until the archive's end is
    /// reached and what follows it is read.
    finish: Option<u64>,
    /// The first refusal, which every later call repeats.
    failed: Option<(u64, ErrorKind)>,
}

/// What the decoder waits for.
#[derive(Debug)]
enum Want {
    /// A block for the parser, beginning at this offset, filled into
    /// [`Decoder::block`].
    Block { at: u64 },
    /// The data of the metadata member the request describes. `data` is the
    /// room made so far, of which `filled` bytes have arrived.
    Metadata {
        request: Request,
        data: Vec<u8>,
        filled: usize,
    },
    /// Bytes to pass over, then what comes after them.
    Skip { remaining: u64, then: Then },
    /// A member, delivered, whose data is being read.
    Member(Member),
    /// What follows the archive's end, after [`Decoder::finish`]. It is read
    /// in blocks of at most the bytes left within the limit and one more. A
    /// stream with more than the limit is then refused at the same offset
    /// however its reads are split.
    Trailing {
        limit: u64,
        /// Bytes still allowed.
        remaining: u64,
        zeros_only: bool,
        /// The offset of the block being filled.
        at: u64,
    },
    /// The archive has ended, and after [`Decoder::finish`] the stream too.
    End,
}

/// What comes after bytes passed over.
#[derive(Debug)]
enum Then {
    /// The next block.
    Block,
    /// The metadata member's data, now that its padding is passed, handed to
    /// the parser.
    Metadata { request: Request, data: Vec<u8> },
}

/// A member whose data is being read.
#[derive(Debug)]
struct Member {
    /// Its data as the archive stores it, not yet read.
    remaining: u64,
    /// The padding after its data.
    padding: u64,
    /// For a sparse member, where reading its file stands.
    expand: Option<Expand>,
    /// What [`Decoder::data`] or [`Decoder::stored_data`] answered last,
    /// less what has been reported read of it since.
    asked: Chunk,
}

impl Member {
    /// What a read delivers next: the file with its holes, or, where
    /// `stored`, its stored data alone.
    fn chunk(&mut self, stored: bool) -> Chunk {
        let Some(expand) = self.expand.as_mut() else {
            return match self.remaining {
                0 => Chunk::End,
                remaining => Chunk::Read(remaining),
            };
        };
        match expand.next(stored) {
            Piece::Zeros(count) => Chunk::Zeros(count),
            // A map's regions add up to the data stored, so a region's bytes
            // are never more than remain of it; the bound holds regardless.
            Piece::Stored(count) => match count.min(self.remaining) {
                0 => Chunk::End,
                count => Chunk::Read(count),
            },
            Piece::End => Chunk::End,
        }
    }
}

/// Where reading a sparse member's file stands: the position in the file,
/// which both [`Decoder::data`] and [`Decoder::stored_data`] move.
#[derive(Debug)]
struct Expand {
    regions: Vec<Region>,
    /// The first region that does not end at or before `position`.
    next: usize,
    position: u64,
    real_size: u64,
}

/// What the next read of a sparse member's file delivers.
enum Piece {
    /// This many zeros, of a hole.
    Zeros(u64),
    /// Up to this many stored bytes, of a region.
    Stored(u64),
    /// Nothing: the file, or what is stored of it, has been read.
    End,
}

impl Expand {
    /// What a read delivers next: the file with its holes, or, where
    /// `stored`, its regions alone, the holes passed over. Asked twice
    /// without the position moving, it answers the same.
    fn next(&mut self, stored: bool) -> Piece {
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
                    return Piece::Zeros(region.offset.saturating_sub(self.position));
                }
                Piece::Stored(region.end().saturating_sub(self.position))
            }
            None if !stored && self.position < self.real_size => {
                Piece::Zeros(self.real_size.saturating_sub(self.position))
            }
            None => Piece::End,
        }
    }

    /// What remains of the file past the position.
    fn remaining(&self) -> u64 {
        self.real_size.saturating_sub(self.position)
    }
}

/// What [`Decoder::step`] asks of its caller, or has found.
///
/// These four are every step reading an archive takes: a driver that
/// handles them reads every archive the decoder reads.
#[derive(Debug)]
// The lint's threshold is in bytes, and a member's size follows the
// width of a pointer: it is past the threshold on 64-bit targets alone.
#[cfg_attr(
    target_pointer_width = "64",
    expect(
        clippy::large_enum_variant,
        reason = "a step is acted on at once, so the member's size is a copy, not memory held"
    )
)]
pub enum Step<'a> {
    /// Copy the stream's next bytes into this buffer, from its start, as
    /// many as are at hand and at most its length. Report how many with
    /// [`Decoder::filled`], zero where the stream has ended. Never empty.
    Read(&'a mut [u8]),
    /// Pass over the stream's next bytes, up to this many, and report how
    /// many with [`Decoder::skipped`]: zero where the stream has ended.
    /// Never zero.
    ///
    /// They are the data of a member the caller did not read, and padding. A
    /// driver over a source that can seek passes over them by seeking.
    /// Seeking past a source's end succeeds where reading past it does not,
    /// so such a driver reports no more than the source holds.
    Skip(u64),
    /// A member. Its data follows in the stream: [`Decoder::data`] reads it,
    /// and the next call to [`Decoder::step`] passes over what was not read.
    Entry(Entry),
    /// The archive has ended.
    End,
}

/// What [`Decoder::data`] or [`Decoder::stored_data`] says a member's data
/// holds next.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Chunk {
    /// The stream's next bytes, up to this many, are the member's data. Read
    /// any number of them, and report how many with
    /// [`Decoder::data_read`], zero where the stream has ended. Never zero.
    Read(u64),
    /// The member's data holds this many zeros next, a hole in a sparse
    /// member's file, which the stream does not hold. Deliver any number of
    /// them, and report how many with [`Decoder::data_read`]. Never zero.
    Zeros(u64),
    /// The member's data has all been delivered.
    End,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder at the start of an archive. It reads at [`Level::Strict`],
    /// refuses a global header holding any record but `comment`
    /// ([`GlobalHeaders::Refuse`]), and has the default [`Limits`].
    #[must_use]
    pub fn new() -> Decoder {
        Decoder {
            parser: Parser::new(),
            offset: 0,
            want: Want::Block { at: 0 },
            block: [0; BLOCK],
            filled: 0,
            reading: false,
            ended: false,
            finish: None,
            failed: None,
        }
    }

    /// The same decoder, reading at `level`.
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Decoder {
        self.parser.set_level(level);
        self
    }

    /// The same decoder, reading global extended headers as `globals` says.
    #[must_use]
    pub fn with_global_headers(mut self, globals: GlobalHeaders) -> Decoder {
        self.parser.set_globals(globals);
        self
    }

    /// The same decoder, held to `limits`.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Decoder {
        self.parser.set_limits(limits);
        self
    }

    /// What to do next, or the next member.
    ///
    /// Whatever the previous member's data held that was not read is passed
    /// over first, through [`Step::Skip`]. The archive ends as
    /// [`Reader::next_entry`](crate::Reader::next_entry) describes.
    ///
    /// # Errors
    ///
    /// An [`Error`] naming what the archive breaks, and the same error from
    /// every later call.
    pub fn step(&mut self) -> Result<Step<'_>, Error> {
        if let Some((offset, kind)) = &self.failed {
            return Err(Error::new(*offset, kind.clone()));
        }
        match self.advance() {
            Ok(Ready::Read) => {
                self.reading = true;
                Ok(Step::Read(self.window()))
            }
            Ok(Ready::Skip(count)) => Ok(Step::Skip(count)),
            Ok(Ready::Entry(entry)) => Ok(Step::Entry(entry)),
            Ok(Ready::End) => Ok(Step::End),
            Err(err) => Err(self.fail(err)),
        }
    }

    /// Reports that `count` bytes of the stream were copied into the start of
    /// the buffer [`Step::Read`] lent. A `count` of zero reports that the
    /// stream has ended.
    ///
    /// A count beyond the buffer's length is taken as its length. Each
    /// [`Step::Read`] is answered once. Without one to answer, before the
    /// first or after its answer, it does nothing.
    pub fn filled(&mut self, count: usize) {
        if !core::mem::take(&mut self.reading) {
            return;
        }
        let room = match &self.want {
            Want::Block { .. } => BLOCK.saturating_sub(self.filled),
            Want::Trailing { remaining, .. } => {
                trailing_window(*remaining).saturating_sub(self.filled)
            }
            Want::Metadata { data, filled, .. } => data.len().saturating_sub(*filled),
            Want::Skip { .. } | Want::Member(_) | Want::End => return,
        };
        let count = count.min(room);
        if count == 0 {
            self.ended = true;
            return;
        }
        if let Want::Metadata { filled, .. } = &mut self.want {
            *filled = filled.saturating_add(count);
        } else {
            self.filled = self.filled.saturating_add(count);
        }
        self.offset = self.offset.saturating_add(count as u64);
    }

    /// Reports that `count` bytes of the stream were passed over, or, where
    /// `count` is zero, that the stream has ended.
    ///
    /// A count beyond the [`Step::Skip`] it answers is taken as that. Without
    /// one to answer, it does nothing.
    pub fn skipped(&mut self, count: u64) {
        let Want::Skip { remaining, .. } = &mut self.want else {
            return;
        };
        let count = count.min(*remaining);
        if count == 0 {
            self.ended = true;
            return;
        }
        *remaining = remaining.saturating_sub(count);
        self.offset = self.offset.saturating_add(count);
    }

    /// What the current member's data holds next: bytes to read from the
    /// stream, or zeros, of a sparse member's hole.
    ///
    /// For a [sparse](Entry::sparse) member, the file it stands for: the
    /// stored regions in place and zeros in the holes between them, as
    /// [`Reader::data`](crate::Reader::data) delivers it. Before the first
    /// member, after [`step`](Self::step) has moved past the last one, and
    /// for a member that has no data, [`Chunk::End`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Truncated`] where the stream has ended inside the data.
    /// Otherwise the error an earlier call returned.
    pub fn data(&mut self) -> Result<Chunk, Error> {
        self.chunk(false)
    }

    /// What the current member's data holds next as the archive stores it.
    /// For a [sparse](Entry::sparse) member, its regions alone, the holes
    /// passed over, as [`Reader::stored_data`](crate::Reader::stored_data)
    /// delivers them. For any other, the same as [`data`](Self::data).
    ///
    /// The two read through one position in the member's file: what one has
    /// passed, the other does not deliver.
    ///
    /// # Errors
    ///
    /// As [`data`](Self::data).
    pub fn stored_data(&mut self) -> Result<Chunk, Error> {
        self.chunk(true)
    }

    /// Reports that `count` bytes of what [`data`](Self::data) or
    /// [`stored_data`](Self::stored_data) answered last were delivered. They
    /// were read from the stream for [`Chunk::Read`], zero where the stream
    /// has ended, or written for [`Chunk::Zeros`].
    ///
    /// A count beyond what remains of the answer is taken as that, and
    /// several reports can answer one chunk. Without a chunk to answer, it
    /// does nothing.
    pub fn data_read(&mut self, count: u64) {
        let Want::Member(member) = &mut self.want else {
            return;
        };
        match &mut member.asked {
            Chunk::Read(asked) => {
                let count = count.min(*asked);
                if count == 0 {
                    self.ended = true;
                    return;
                }
                *asked = asked.saturating_sub(count);
                member.remaining = member.remaining.saturating_sub(count);
                self.offset = self.offset.saturating_add(count);
                if let Some(expand) = member.expand.as_mut() {
                    expand.position = expand.position.saturating_add(count);
                }
            }
            Chunk::Zeros(asked) => {
                let count = count.min(*asked);
                *asked = asked.saturating_sub(count);
                if let Some(expand) = member.expand.as_mut() {
                    expand.position = expand.position.saturating_add(count);
                }
            }
            Chunk::End => {}
        }
        if matches!(member.asked, Chunk::Read(0) | Chunk::Zeros(0)) {
            member.asked = Chunk::End;
        }
    }

    /// What remains of the current member's data, as [`data`](Self::data)
    /// delivers it: for a sparse member, its file, holes included. Zero
    /// where there is no current member.
    #[must_use]
    pub fn data_remaining(&self) -> u64 {
        match &self.want {
            Want::Member(member) => member
                .expand
                .as_ref()
                .map_or(member.remaining, Expand::remaining),
            _ => 0,
        }
    }

    /// Has [`step`](Self::step) read the rest of the archive, then the stream
    /// after it to its end, refusing more than `limit` bytes there. The stream
    /// after the archive begins after its first zero block, or where the
    /// archive ends without one.
    ///
    /// From here, `step` delivers no more members. Each one left is read as
    /// it would be, its data passed over. What follows the archive is read
    /// through [`Step::Read`] until a count of zero, after which `step`
    /// answers [`Step::End`]. The rules are
    /// [`Reader::finish`](crate::Reader::finish)'s. At [`Level::Strict`],
    /// what follows must be zeros ([`ErrorKind::TrailingData`]). More than
    /// `limit` bytes is [`ErrorKind::TrailingLimit`], at the offset just past
    /// the first byte over it.
    pub fn finish(&mut self, limit: u64) {
        self.finish = Some(limit);
    }

    /// How many bytes of the stream have been reported, from its start: the
    /// offset of the byte the decoder needs next.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The records of a global extended header that follows the archive's
    /// last member, once [`step`](Self::step) has answered [`Step::End`].
    /// Empty where there is none.
    #[must_use]
    pub fn trailing_global(&self) -> &PaxRecords {
        self.parser.trailing_global()
    }

    /// The buffer [`Step::Read`] lends. It is the rest of the block, or the
    /// room made for a metadata member's data. After the archive, it is the
    /// part of the block that what follows may fill.
    fn window(&mut self) -> &mut [u8] {
        match &mut self.want {
            Want::Metadata { data, filled, .. } => data.get_mut(*filled..).unwrap_or_default(),
            Want::Trailing { remaining, .. } => {
                let window = trailing_window(*remaining);
                self.block.get_mut(..window).unwrap_or_default()
            }
            _ => self.block.get_mut(self.filled..).unwrap_or_default(),
        }
    }

    /// Records `err` as the refusal every later call repeats.
    fn fail(&mut self, err: Error) -> Error {
        self.failed = Some((err.offset(), err.kind().clone()));
        err
    }

    /// What [`data`](Self::data) and [`stored_data`](Self::stored_data)
    /// answer.
    fn chunk(&mut self, stored: bool) -> Result<Chunk, Error> {
        if let Some((offset, kind)) = &self.failed {
            return Err(Error::new(*offset, kind.clone()));
        }
        let Want::Member(member) = &mut self.want else {
            return Ok(Chunk::End);
        };
        let chunk = member.chunk(stored);
        if self.ended && matches!(chunk, Chunk::Read(_)) {
            let err = Error::new(self.offset, ErrorKind::Truncated(Truncation::Data));
            return Err(self.fail(err));
        }
        member.asked = chunk;
        Ok(chunk)
    }

    /// Runs the parser over what has arrived, until the decoder needs more of
    /// the stream, or has a member or the end to deliver.
    fn advance(&mut self) -> Result<Ready, Error> {
        loop {
            match &mut self.want {
                Want::Block { at } => {
                    if self.filled < BLOCK && !self.ended {
                        return Ok(Ready::Read);
                    }
                    let at = *at;
                    let filled = core::mem::take(&mut self.filled);
                    let bytes = self.block.get(..filled).unwrap_or_default();
                    let step = self.parser.block(at, bytes)?;
                    if let Some(ready) = self.take(step) {
                        return Ok(ready);
                    }
                }
                Want::Metadata {
                    request,
                    data,
                    filled,
                } => {
                    let size = request.size();
                    let arrived = *filled as u64;
                    if arrived < size {
                        if self.ended {
                            return Err(Error::new(
                                self.offset,
                                ErrorKind::Truncated(Truncation::Data),
                            ));
                        }
                        let end = size.min(arrived.saturating_add(RESERVE));
                        let end = usize::try_from(end).unwrap_or(usize::MAX);
                        if data.len() < end {
                            data.resize(end, 0);
                        }
                        return Ok(Ready::Read);
                    }
                    let padding = size.wrapping_neg() % BLOCK_LEN;
                    let Want::Metadata { request, data, .. } =
                        core::mem::replace(&mut self.want, Want::End)
                    else {
                        continue;
                    };
                    self.want = Want::Skip {
                        remaining: padding,
                        then: Then::Metadata { request, data },
                    };
                }
                Want::Skip { remaining, then } => {
                    if *remaining > 0 {
                        if self.ended {
                            return Err(Error::new(
                                self.offset,
                                ErrorKind::Truncated(Truncation::Data),
                            ));
                        }
                        return Ok(Ready::Skip(*remaining));
                    }
                    match core::mem::replace(then, Then::Block) {
                        Then::Block => self.want = Want::Block { at: self.offset },
                        Then::Metadata { request, data } => {
                            let step = self.parser.metadata(request, data)?;
                            if let Some(ready) = self.take(step) {
                                return Ok(ready);
                            }
                        }
                    }
                }
                Want::Member(member) => {
                    // The caller has moved on: what remains of the data is
                    // passed over with the padding after it.
                    let count = member.remaining.saturating_add(member.padding);
                    self.want = Want::Skip {
                        remaining: count,
                        then: Then::Block,
                    };
                }
                Want::Trailing {
                    limit,
                    remaining,
                    zeros_only,
                    at,
                } => {
                    let filled = core::mem::take(&mut self.filled);
                    if filled == 0 {
                        if self.ended {
                            self.want = Want::End;
                            continue;
                        }
                        return Ok(Ready::Read);
                    }
                    let bytes = self.block.get(..filled).unwrap_or_default();
                    if *zeros_only && let Some(first) = bytes.iter().position(|byte| *byte != 0) {
                        return Err(Error::new(
                            at.saturating_add(first as u64),
                            ErrorKind::TrailingData,
                        ));
                    }
                    let limit = *limit;
                    *remaining = remaining.checked_sub(filled as u64).ok_or_else(|| {
                        Error::new(self.offset, ErrorKind::TrailingLimit { limit })
                    })?;
                    *at = self.offset;
                }
                Want::End => {
                    let Some(limit) = self.finish.take() else {
                        return Ok(Ready::End);
                    };
                    // What follows the archive counts from just past its
                    // first zero block; at Strict the parser has read a block
                    // past it already. Where that block is over the limit,
                    // the refusal is where it would be had the block been
                    // read here: just past the first byte over the limit.
                    let end = self.parser.end();
                    let past = self.offset.saturating_sub(end);
                    let remaining = limit.checked_sub(past).ok_or_else(|| {
                        Error::new(
                            end.saturating_add(limit).saturating_add(1),
                            ErrorKind::TrailingLimit { limit },
                        )
                    })?;
                    self.filled = 0;
                    self.want = Want::Trailing {
                        limit,
                        remaining,
                        zeros_only: self.parser.level() == Level::Strict,
                        at: self.offset,
                    };
                }
            }
        }
    }

    /// Acts on what the parser asks for, returning what is ready to deliver.
    fn take(&mut self, step: parser::Step) -> Option<Ready> {
        match step {
            parser::Step::Block => {
                self.want = Want::Block { at: self.offset };
                None
            }
            parser::Step::Metadata(request) => {
                self.want = Want::Metadata {
                    request,
                    data: Vec::new(),
                    filled: 0,
                };
                None
            }
            parser::Step::Member(entry) => {
                let stored = entry.stored_len();
                self.want = Want::Member(Member {
                    remaining: stored,
                    // The distance to the next multiple of the block size.
                    // 2^64 is a multiple of it, so the negation's remainder is
                    // that distance.
                    padding: stored.wrapping_neg() % BLOCK_LEN,
                    expand: entry.sparse().map(|map| Expand {
                        regions: map.regions().to_vec(),
                        next: 0,
                        position: 0,
                        real_size: map.real_size(),
                    }),
                    asked: Chunk::End,
                });
                if self.finish.is_some() {
                    None
                } else {
                    Some(Ready::Entry(entry))
                }
            }
            parser::Step::End => {
                self.want = Want::End;
                None
            }
        }
    }
}

/// What [`Decoder::advance`] has ready: [`Step`] without the buffer it lends.
// The lint's threshold is in bytes, and a member's size follows the
// width of a pointer: it is past the threshold on 64-bit targets alone.
#[cfg_attr(
    target_pointer_width = "64",
    expect(
        clippy::large_enum_variant,
        reason = "an answer is delivered at once, so the member's size is a copy, not memory held"
    )
)]
enum Ready {
    Read,
    Skip(u64),
    Entry(Entry),
    End,
}

/// How much of the block what follows the archive may fill at once. It is
/// the bytes still allowed and one more, so that the byte over the limit is
/// the last one asked for.
fn trailing_window(remaining: u64) -> usize {
    usize::try_from(remaining.saturating_add(1)).map_or(BLOCK, |window| window.min(BLOCK))
}
