//! The reader's core, which performs no I/O: it is handed the archive's
//! header blocks and metadata, and says what to read, skip or yield next.
//!
//! A driver runs it. It asks for a [`Step`] and acts on it in one of three
//! ways:
//!
//! - It reads the next block, or a metadata member's data, and hands it over.
//! - It skips the bytes it is told to.
//! - It delivers the member it is given, and serves that member's data until
//!   it moves on.
//!
//! Every reading rule lives here, so each way of
//! moving bytes (a source read through, a source sought past) is a driver
//! and nothing more.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::entry::{Entry, EntryKind, Timestamp};
use crate::error::{Error, ErrorKind, Keyword, Metadata, SparseFlaw, Truncation};
use crate::header::{self, BLOCK, Fields, Flaw};
use crate::pax::{self, Applied, PaxRecords};
use crate::settings::{GlobalHeaders, Level, Limits};
use crate::sparse::{self, MapReader, PaxForm, Region};

/// [`BLOCK`] as the type sizes and offsets are counted in.
const BLOCK_LEN: u64 = BLOCK as u64;

/// GNU's magic and version, which an old GNU sparse header holds.
const GNU_MAGIC: &[u8] = b"ustar  \0";

/// POSIX's magic and version, which a pax sparse member's header holds.
const POSIX_MAGIC: &[u8] = b"ustar\x0000";

/// star's record of a file's real size, which bsdtar reads as the size of a
/// member that is not sparse.
const REAL_SIZE: &[u8] = b"SCHILY.realsize";

/// What the driver does next.
#[derive(Debug)]
// The lint's threshold is in bytes, and a member's size follows the
// width of a pointer: it is past the threshold on 64-bit targets alone.
#[cfg_attr(
    target_pointer_width = "64",
    expect(
        clippy::large_enum_variant,
        reason = "a step is acted on and dropped at once, so the member's size is a copy, not memory held"
    )
)]
pub(crate) enum Step {
    /// Read the next block, or as much of it as the stream holds, and hand it
    /// to [`Parser::block`].
    Block,
    /// Read the data of the metadata member the request describes, skip the
    /// padding after it, and hand the data to [`Parser::metadata`].
    Metadata(Request),
    /// Deliver this member, whose data follows: [`Entry::size`] bytes, then
    /// the padding after them.
    Member(Entry),
    /// The archive has ended.
    End,
}

/// A metadata member whose data the parser needs.
#[derive(Debug)]
pub(crate) struct Request {
    /// The offset of its header.
    at: u64,
    kind: Metadata,
    /// The length of its data, within the metadata limit.
    size: u64,
    /// Whether the first byte of the padding after the data is read with it:
    /// for a GNU long name or long link, where padding follows.
    peek: bool,
}

impl Request {
    /// The length of the data to read: the member's, and the byte after it
    /// where the parser asks for that too.
    pub(crate) fn size(&self) -> u64 {
        self.size.saturating_add(u64::from(self.peek))
    }
}

/// Where the parser is in the archive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// At a header boundary.
    Header,
    /// Past the archive's first zero block, at [`Level::Strict`], where the
    /// next block must hold nothing but zeros.
    AfterEnd,
    /// Past the archive's end.
    Ended,
    /// Reading a sparse member's map, a block at a time
    /// ([`Parser::sparse`]).
    Map,
}

/// A sparse member whose map is still being read.
#[derive(Debug)]
struct PendingMap {
    entry: Entry,
    source: MapSource,
}

/// Where the rest of a sparse member's map is.
#[derive(Debug)]
enum MapSource {
    /// In the old GNU extension blocks after its header: the regions read so
    /// far, and the bytes of map, the header's block included.
    Extensions {
        regions: Vec<Region>,
        real_size: u64,
        read: u64,
    },
    /// At the start of its data, in GNU's format 1.0.
    Data { reader: MapReader, real_size: u64 },
}

/// The metadata read since the last member, for the next.
#[derive(Debug, Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax: Option<(PaxRecords, Applied)>,
    global: Option<PaxRecords>,
}

impl Pending {
    /// Whether metadata waits that describes the next member alone.
    fn waiting(&self) -> bool {
        self.long_name.is_some() || self.long_link.is_some() || self.pax.is_some()
    }
}

/// The reading rules, as a machine the driver feeds.
#[derive(Debug)]
pub(crate) struct Parser {
    level: Level,
    globals: GlobalHeaders,
    limits: Limits,
    state: State,
    pending: Pending,
    /// With [`GlobalHeaders::Apply`], what a global header states for every
    /// member after it.
    global_fields: Applied,
    /// Whether a global header has stated a member's field, after which
    /// [`GlobalHeaders::Apply`] refuses another.
    global_applied: bool,
    /// The records of a global header that follows the last member.
    trailing_global: PaxRecords,
    /// Where the archive ended: just past its first zero block, or where the
    /// stream did.
    end: u64,
    /// The sparse member whose map is being read.
    map: Option<Box<PendingMap>>,
}

impl Parser {
    pub(crate) fn new() -> Parser {
        Parser {
            level: Level::default(),
            globals: GlobalHeaders::default(),
            limits: Limits::default(),
            state: State::Header,
            pending: Pending::default(),
            global_fields: Applied::default(),
            global_applied: false,
            trailing_global: PaxRecords::default(),
            end: 0,
            map: None,
        }
    }

    pub(crate) fn set_level(&mut self, level: Level) {
        self.level = level;
    }

    pub(crate) fn set_globals(&mut self, globals: GlobalHeaders) {
        self.globals = globals;
    }

    pub(crate) fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    pub(crate) fn level(&self) -> Level {
        self.level
    }

    pub(crate) fn trailing_global(&self) -> &PaxRecords {
        &self.trailing_global
    }

    /// Where the archive ended, once it has: just past its first zero block,
    /// or where the stream did. What follows is not part of it, though at
    /// [`Level::Strict`] the parser reads a block more.
    pub(crate) fn end(&self) -> u64 {
        self.end
    }

    /// The block at offset `at` in the stream: [`BLOCK`] bytes, or fewer
    /// where the stream ends inside it, none where it ends before it.
    pub(crate) fn block(&mut self, at: u64, bytes: &[u8]) -> Result<Step, Error> {
        match self.state {
            State::Header => self.header(at, bytes),
            State::AfterEnd => {
                self.state = State::Ended;
                match bytes.iter().position(|byte| *byte != 0) {
                    // GNU tar reading on with `--ignore-zeros`, and `tar-core`
                    // 0.1, read the members after the zero block.
                    Some(first) => Err(Error::new(
                        at.saturating_add(first as u64),
                        ErrorKind::TrailingData,
                    )),
                    None => Ok(Step::End),
                }
            }
            State::Ended => Ok(Step::End),
            State::Map => self.map_block(at, bytes),
        }
    }

    /// The data of the metadata member `request` describes.
    pub(crate) fn metadata(&mut self, request: Request, mut data: Vec<u8>) -> Result<Step, Error> {
        let at = request.at;
        let refuse = |kind| Error::new(at, kind);
        match request.kind {
            Metadata::LongName | Metadata::LongLink => {
                // GNU tar and Python read a long name to its first NUL, past
                // its size and into the padding where the data holds none;
                // bsdtar and Go read as far as its size.
                let next = if request.peek { data.pop() } else { None };
                if !data.contains(&0) && next.is_some_and(|byte| byte != 0) {
                    return Err(refuse(ErrorKind::LongNameOverrun(request.kind)));
                }
                let name = long_name(&data, self.level)
                    .ok_or_else(|| refuse(ErrorKind::LongNameNul(request.kind)))?;
                // An empty long link is the link target to GNU tar and Python,
                // and no target at all to bsdtar and Go, who take the one in
                // the member's header. An empty long name leaves the member no
                // name, which is refused as that (`ErrorKind::EmptyName`).
                if request.kind == Metadata::LongLink && name.is_empty() {
                    return Err(refuse(ErrorKind::EmptyMetadata(request.kind)));
                }
                if request.kind == Metadata::LongName {
                    self.pending.long_name = Some(name);
                } else {
                    self.pending.long_link = Some(name);
                }
            }
            Metadata::PaxHeader => {
                self.pending.pax = Some(pax::parse(data, self.level).map_err(refuse)?);
            }
            Metadata::GlobalHeader => {
                let (records, applied) =
                    pax::parse_global(data, self.globals, self.level).map_err(refuse)?;
                if applied.sets_a_field() {
                    self.global_fields = applied;
                    self.global_applied = true;
                }
                self.pending.global = Some(records);
            }
        }
        Ok(Step::Block)
    }

    /// A block at a header boundary.
    fn header(&mut self, at: u64, bytes: &[u8]) -> Result<Step, Error> {
        let Ok(block) = <&[u8; BLOCK]>::try_from(bytes) else {
            // A stream that ends before its first header is whole is a file
            // of some other format, or an empty one; the tolerance of a
            // missing end marker presupposes an archive.
            if at == 0 {
                return Err(Error::new(0, ErrorKind::NotATar));
            }
            if bytes.is_empty() {
                return self.ending(at, at);
            }
            return Err(Error::new(
                at.saturating_add(bytes.len() as u64),
                ErrorKind::Truncated(Truncation::Header),
            ));
        };
        if block.iter().all(|byte| *byte == 0) {
            let step = self.ending(at, at.saturating_add(BLOCK as u64))?;
            // At Strict the archive ends here all the same, and the block after
            // is read to see that it holds nothing more.
            if self.level == Level::Strict {
                self.state = State::AfterEnd;
                return Ok(Step::Block);
            }
            return Ok(step);
        }

        let header = header::parse(block).map_err(|flaw| {
            Error::new(
                at,
                match flaw {
                    Flaw::NotAHeader if at == 0 => ErrorKind::NotATar,
                    Flaw::NotAHeader => ErrorKind::NotAHeader,
                    Flaw::Checksum => ErrorKind::Checksum,
                    Flaw::Field(field, problem) => ErrorKind::HeaderField { field, problem },
                },
            )
        })?;
        let refuse = |kind| Err(Error::new(at, kind));

        let kind = match header.typeflag {
            b'L' => Metadata::LongName,
            b'K' => Metadata::LongLink,
            b'x' => Metadata::PaxHeader,
            b'g' => Metadata::GlobalHeader,
            b'X' => return refuse(ErrorKind::SolarisExtendedHeader),
            b'A' => return refuse(ErrorKind::SolarisAcl),
            b'M' => return refuse(ErrorKind::VolumeContinuation),
            // A GNU volume label names the archive, not a member, but Python
            // extracts it as a file (`ErrorKind::VolumeLabel`).
            b'V' => return refuse(ErrorKind::VolumeLabel),
            _ => return self.member(at, block, header),
        };

        // A v7 global header is read as a global header by every reader, but
        // the others, without POSIX's or GNU's magic and version exactly, are
        // members to some (`MetadataWithoutMagic`).
        if self.level == Level::Strict && !header.exact_magic && kind != Metadata::GlobalHeader {
            return refuse(ErrorKind::MetadataWithoutMagic(kind));
        }
        // One metadata member of each kind describes the member after it. No
        // writer emits a second, and the readers part ways over one
        // (`ErrorKind::RepeatedMetadata`). A global header states records for
        // every member after it, which the readers apply differently or not at
        // all; where one falls is held as well (`GlobalBetweenMetadata`), so at
        // most one precedes a member.
        let repeated = match kind {
            Metadata::LongName => self.pending.long_name.is_some(),
            Metadata::LongLink => self.pending.long_link.is_some(),
            Metadata::PaxHeader => self.pending.pax.is_some(),
            Metadata::GlobalHeader => {
                if self.pending.waiting() {
                    return refuse(ErrorKind::GlobalBetweenMetadata);
                }
                self.pending.global.is_some()
            }
        };
        if repeated {
            return refuse(ErrorKind::RepeatedMetadata(kind));
        }
        if kind == Metadata::GlobalHeader
            && self.globals == GlobalHeaders::Apply
            && self.global_applied
        {
            return refuse(ErrorKind::SecondGlobal);
        }
        let size = header.size;
        let limit = self.limits.metadata;
        if size > limit {
            return refuse(ErrorKind::MetadataLimit { size, limit });
        }
        // bsdtar fails on a pax or global header with no records, reading
        // nothing after it, where the others read on.
        let extended = matches!(kind, Metadata::PaxHeader | Metadata::GlobalHeader);
        if extended && size == 0 {
            return refuse(ErrorKind::EmptyMetadata(kind));
        }
        let peek = !extended && !size.is_multiple_of(BLOCK as u64);
        Ok(Step::Metadata(Request {
            at,
            kind,
            size,
            peek,
        }))
    }

    /// The archive's end at `at`, the archive ending just before `end`. These
    /// are a zero block's offset and the offset past it, or where the stream
    /// ends for both. Refused where metadata waits for a member it never gets.
    fn ending(&mut self, at: u64, end: u64) -> Result<Step, Error> {
        if self.pending.waiting() {
            return Err(Error::new(at, ErrorKind::Truncated(Truncation::Member)));
        }
        if let Some(global) = self.pending.global.take() {
            self.trailing_global = global;
        }
        self.end = end;
        self.state = State::Ended;
        Ok(Step::End)
    }

    /// The member `header` describes, at `at`, with the metadata read before
    /// it applied. A pax record takes precedence over a GNU long name or long
    /// link, and either over the header's own field. A global record applies
    /// beneath the member's own, where one applies.
    fn member(&mut self, at: u64, block: &[u8; BLOCK], header: Fields) -> Result<Step, Error> {
        let refuse = |kind| Error::new(at, kind);
        let flawed = |flaw| Error::new(at, ErrorKind::Sparse(flaw));
        let pending = core::mem::take(&mut self.pending);
        let (records, own) = pending.pax.unwrap_or_default();
        // A link target of the member's own, from a long link or a pax record
        // rather than its header. A global one is applied only for GNU tar
        // and Python, which pass over a target on a member that is not a link.
        let stated_target = own.link_target.is_some() || pending.long_link.is_some();
        let applied = own.over(&self.global_fields);

        // Whether the header's own name and prefix name the member, no pax
        // record or long name replacing them.
        let named_by_header = applied.path.is_none() && pending.long_name.is_none();
        let mut path =
            resolve(applied.path, pending.long_name, header.path, Keyword::Path).map_err(refuse)?;
        // A pax record cannot state an empty name (`ErrorKind::EmptyPaxValue`),
        // so this is the header's own name or a long name.
        if path.is_empty() {
            return Err(refuse(ErrorKind::EmptyName));
        }
        let link_target = resolve(
            applied.link_target,
            pending.long_link,
            header.link_target,
            Keyword::Linkpath,
        )
        .map_err(refuse)?;
        let declared_size = applied.size.unwrap_or(header.size);

        let pax_sparse = sparse::pax(&records).map_err(flawed)?;
        let old_sparse = header.typeflag == b'S';
        if old_sparse || pax_sparse.is_some() {
            // `tar` reads a pax sparse member as a regular member of its
            // stored data, under the header's name.
            if self.level == Level::Strict && pax_sparse.is_some() {
                return Err(flawed(SparseFlaw::PaxForm));
            }
            if old_sparse && (pax_sparse.is_some() || block.get(257..265) != Some(GNU_MAGIC)) {
                return Err(flawed(if pax_sparse.is_some() {
                    SparseFlaw::Records
                } else {
                    SparseFlaw::Magic
                }));
            }
            if !old_sparse && header.typeflag != b'0' {
                return Err(flawed(SparseFlaw::NotRegular));
            }
            // GNU tar reads a pax sparse member under GNU's magic, or none,
            // as other data, and reads no member after it.
            if !old_sparse && block.get(257..265) != Some(POSIX_MAGIC) {
                return Err(flawed(SparseFlaw::Magic));
            }
            if applied.size.is_some() {
                return Err(flawed(SparseFlaw::SizeRecord));
            }
            // Python applies no global record to an old GNU sparse member,
            // where GNU tar applies them all.
            if old_sparse
                && self.globals == GlobalHeaders::Apply
                && self.global_fields.sets_a_field()
            {
                return Err(flawed(SparseFlaw::Global));
            }
            // GNU tar, bsdtar and Go name a pax sparse member by
            // `GNU.sparse.name` over a `path` record, and Python by whichever
            // comes last; Python takes a long name over it.
            if let Some(name) = pax_sparse.as_ref().and_then(|found| found.name.as_ref()) {
                // GNU tar and bsdtar cut a name at a NUL; Go and Python keep
                // it.
                if name.is_empty() || name.contains(&0) || (!named_by_header && *name != path) {
                    return Err(flawed(SparseFlaw::Name));
                }
                path.clone_from(name);
            }
            // GNU tar and bsdtar extract a sparse member named so as a
            // directory, Go and Python as a file.
            if path.last() == Some(&b'/') {
                return Err(flawed(SparseFlaw::Name));
            }
        }
        if header.stray_prefix {
            return Err(refuse(ErrorKind::PrefixArea));
        }
        // bsdtar reads a GNU header's old sparse fields whatever its
        // typeflag: a real size as a regular file's size, and a slot as a
        // map it fails on. GNU tar, Go and Python read the header's own.
        if !old_sparse && block.get(257..265) == Some(GNU_MAGIC) {
            let slots = block
                .get(386..482)
                .is_some_and(|slots| slots.iter().any(|byte| *byte != 0));
            let real_size = block
                .get(483..495)
                .is_some_and(|field| field.iter().any(|byte| *byte != 0));
            if slots || (real_size && !matches!(header.typeflag, b'1'..=b'6')) {
                return Err(refuse(ErrorKind::SparseFields));
            }
        }
        if header.unknown_magic {
            return Err(refuse(ErrorKind::UnknownMagic));
        }
        if header.prefix_slash && named_by_header {
            return Err(refuse(ErrorKind::PrefixSlash));
        }
        // Go reads a header ending in star's trailer as star's, its prefix
        // the first 131 bytes.
        if header.star_prefix && named_by_header {
            return Err(refuse(ErrorKind::StarPrefix));
        }

        // A trailing separator marks a directory, whatever the regular file's
        // typeflag says, as in the oldest archives. It is read from the
        // resolved path, never from the header's own name where a long name or
        // pax record replaced that: GNU tar fills the name field with the
        // first 100 bytes of such a path, and where the cut lands just after a
        // separator, a rule read from the field would make a regular file a
        // directory, and read its data as the next header.
        let kind = EntryKind::of(header.typeflag, &path);
        // bsdtar takes a `SCHILY.realsize` record as the size of a file or a
        // hard link, where the others ignore it. Every reader takes a sparse
        // member's real size from its map, and ignores the record on any
        // other kind of member.
        if matches!(kind, EntryKind::File | EntryKind::HardLink)
            && !old_sparse
            && pax_sparse.is_none()
        {
            let states_size = |value: &[u8]| pax::decimal(value) == Ok(declared_size);
            if records
                .iter()
                .any(|(keyword, value)| keyword == REAL_SIZE && !states_size(value))
            {
                return Err(refuse(ErrorKind::RealSizeRecord));
            }
        }
        // bsdtar takes a trailing separator to mark a directory whatever the
        // typeflag, where GNU tar and Python extract a typeflag GNU tar does
        // not know as a regular file.
        if !gnu_knows(header.typeflag) && path.last() == Some(&b'/') {
            return Err(refuse(ErrorKind::UnknownTypeSlash {
                typeflag: header.typeflag,
            }));
        }
        // A regular member is a directory by its trailing separator, and
        // bsdtar forgets that after any record it fails to parse: an access
        // list, a creation time, a symbolic link's type, a character set. So
        // such a member has only the records every reader reads alike.
        if matches!(header.typeflag, b'0' | 0 | b'7') && kind == EntryKind::Directory {
            let other = records.iter().find(|(keyword, _)| {
                Keyword::of(keyword).is_none()
                    && *keyword != b"comment"
                    && *keyword != b"hdrcharset"
            });
            if let Some((keyword, _)) = other {
                return Err(refuse(ErrorKind::DirectoryWithRecord {
                    keyword: keyword.to_vec(),
                }));
            }
        }
        // bsdtar makes a member that is not a link into a hard link to such a
        // target, and writes the member's data into it.
        if stated_target && !matches!(kind, EntryKind::HardLink | EntryKind::Symlink) {
            return Err(refuse(ErrorKind::TargetWithoutLink { kind }));
        }
        // A default list is a directory's. bsdtar takes the mode of any other
        // member with one from the lists' text, `000`, where GNU tar, Go
        // and Python read the header's.
        if kind != EntryKind::Directory && records.get(b"SCHILY.acl.default").is_some() {
            return Err(refuse(ErrorKind::DefaultAclWithoutDirectory { kind }));
        }
        // GNU tar links an empty target as `.`, the others as the empty name.
        if kind == EntryKind::HardLink && link_target.is_empty() {
            return Err(refuse(ErrorKind::HardLinkWithoutTarget));
        }
        let carries_data = !matches!(header.typeflag, b'1'..=b'6');
        if declared_size != 0 {
            // GNU tar reads no data after such a member where its header
            // declares the size, and reads data where a pax record does.
            let by_record = applied.size.is_some();
            if !carries_data
                && (kind == EntryKind::HardLink || self.level == Level::Strict || by_record)
            {
                return Err(refuse(ErrorKind::SizeWithoutData { kind }));
            }
            if carries_data && kind == EntryKind::Directory && header.typeflag != b'D' {
                return Err(refuse(ErrorKind::DirectoryWithData));
            }
        }

        // GNU tar keeps setuid, setgid and sticky beside an access list, and
        // bsdtar drops all three. Compatible reads the header's mode, as GNU
        // tar extracts it.
        if self.level == Level::Strict
            && header.mode & 0o7000 != 0
            && records.get(b"SCHILY.acl.access").is_some()
        {
            return Err(refuse(ErrorKind::SpecialBitsWithAcl));
        }

        // bsdtar takes a device's numbers from these records, where GNU tar,
        // Go and Python read the header's.
        if matches!(kind, EntryKind::CharDevice | EntryKind::BlockDevice)
            && !records.device_records_agree(header.device.unwrap_or((0, 0)))
        {
            return Err(refuse(ErrorKind::DeviceConflict));
        }

        // A header with no device fields gives a device 0,0, as every reader
        // reports and extracts it.
        let device = match kind {
            EntryKind::CharDevice | EntryKind::BlockDevice => Some(header.device.unwrap_or((0, 0))),
            _ => None,
        };
        let entry = Entry {
            path,
            link_target,
            typeflag: header.typeflag,
            kind,
            mode: header.mode,
            uid: applied.uid.unwrap_or(header.uid),
            gid: applied.gid.unwrap_or(header.gid),
            uname: applied.uname.unwrap_or(header.uname),
            gname: applied.gname.unwrap_or(header.gname),
            size: if carries_data { declared_size } else { 0 },
            declared_size,
            mtime: applied
                .mtime
                .unwrap_or_else(|| Timestamp::from_secs(header.mtime)),
            atime: applied.atime,
            ctime: applied.ctime,
            device,
            header: Box::new(*block),
            header_offset: at,
            data_offset: at.saturating_add(BLOCK_LEN),
            sparse: None,
            pax: records,
            global: pending.global.unwrap_or_default(),
        };

        let declared = entry.declared_size;
        let data_offset = entry.data_offset;
        if old_sparse {
            // The header's block is the first of the map's blocks.
            if BLOCK_LEN > self.limits.metadata {
                return Err(flawed(SparseFlaw::MapLimit));
            }
            let (regions, real_size, more) = sparse::old_header(block).map_err(flawed)?;
            if more {
                let read = BLOCK_LEN;
                return Ok(self.await_map(
                    entry,
                    MapSource::Extensions {
                        regions,
                        real_size,
                        read,
                    },
                ));
            }
            return finish(entry, regions, real_size, declared, data_offset).map_err(flawed);
        }
        match pax_sparse.map(|found| (found.form, found.real_size)) {
            Some((PaxForm::Records(regions), real_size)) => {
                finish(entry, regions, real_size, declared, data_offset).map_err(flawed)
            }
            Some((PaxForm::Data, real_size)) => {
                // The map's first block is the start of the member's data.
                if declared < BLOCK_LEN {
                    return Err(flawed(SparseFlaw::StoredSize));
                }
                let reader = MapReader::default();
                Ok(self.await_map(entry, MapSource::Data { reader, real_size }))
            }
            None => Ok(Step::Member(entry)),
        }
    }

    /// Reads the rest of `entry`'s map from the blocks after its header.
    fn await_map(&mut self, entry: Entry, source: MapSource) -> Step {
        self.map = Some(Box::new(PendingMap { entry, source }));
        self.state = State::Map;
        Step::Block
    }

    /// The next block of a sparse member's map, at `at`: an old GNU
    /// extension block, or a block of a format 1.0 map.
    fn map_block(&mut self, at: u64, bytes: &[u8]) -> Result<Step, Error> {
        self.state = State::Header;
        let Some(pending) = self.map.take() else {
            return Ok(Step::Block);
        };
        let PendingMap { entry, source } = *pending;
        let header_at = entry.header_offset;
        let flawed = |flaw| Error::new(header_at, ErrorKind::Sparse(flaw));
        let truncated = |truncation| {
            Error::new(
                at.saturating_add(bytes.len() as u64),
                ErrorKind::Truncated(truncation),
            )
        };
        let declared = entry.declared_size;
        let data_offset = at.saturating_add(BLOCK_LEN);
        let limit = self.limits.metadata;
        match source {
            MapSource::Extensions {
                mut regions,
                real_size,
                read,
            } => {
                let block =
                    <&[u8; BLOCK]>::try_from(bytes).map_err(|_| truncated(Truncation::Header))?;
                let read = read.saturating_add(BLOCK_LEN);
                if read > limit {
                    return Err(flawed(SparseFlaw::MapLimit));
                }
                let more = sparse::old_extension(block, &mut regions).map_err(flawed)?;
                if more {
                    let source = MapSource::Extensions {
                        regions,
                        real_size,
                        read,
                    };
                    return Ok(self.await_map(entry, source));
                }
                finish(entry, regions, real_size, declared, data_offset).map_err(flawed)
            }
            MapSource::Data {
                mut reader,
                real_size,
            } => {
                let block =
                    <&[u8; BLOCK]>::try_from(bytes).map_err(|_| truncated(Truncation::Data))?;
                let found = reader.block(block).map_err(flawed)?;
                if reader.read() > limit {
                    return Err(flawed(SparseFlaw::MapLimit));
                }
                if let Some((regions, map_len)) = found {
                    let stored = declared
                        .checked_sub(map_len)
                        .ok_or_else(|| flawed(SparseFlaw::StoredSize))?;
                    return finish(entry, regions, real_size, stored, data_offset).map_err(flawed);
                }
                // The member's data ends before the map's next block.
                if reader.read().saturating_add(BLOCK_LEN) > declared {
                    return Err(flawed(SparseFlaw::StoredSize));
                }
                Ok(self.await_map(entry, MapSource::Data { reader, real_size }))
            }
        }
    }
}

/// A sparse member, its map read. The map is checked against the rules every
/// reference reader extracts alike. The member is then delivered with the
/// real size as its size, and its stored data beginning at `data_offset`.
fn finish(
    mut entry: Entry,
    regions: Vec<Region>,
    real_size: u64,
    stored: u64,
    data_offset: u64,
) -> Result<Step, SparseFlaw> {
    let map = sparse::checked(regions, real_size, stored)?;
    entry.size = map.real_size;
    entry.data_offset = data_offset;
    entry.sparse = Some(Box::new(map));
    Ok(Step::Member(entry))
}

/// The name a member takes from a pax record, a GNU long name, and its own
/// header, in that order. Refused where the first two both state one and
/// differ ([`ErrorKind::LongNameConflict`]).
fn resolve(
    pax: Option<Vec<u8>>,
    long: Option<Vec<u8>>,
    own: Vec<u8>,
    keyword: Keyword,
) -> Result<Vec<u8>, ErrorKind> {
    match (pax, long) {
        (Some(pax), Some(long)) if pax != long => Err(ErrorKind::LongNameConflict { keyword }),
        (Some(name), _) | (None, Some(name)) => Ok(name),
        (None, None) => Ok(own),
    }
}

/// Whether GNU tar knows `typeflag`, listing a member of it as other than
/// unknown: every other byte it extracts as a regular file.
fn gnu_knows(typeflag: u8) -> bool {
    matches!(
        typeflag,
        0 | b'0'..=b'7' | b'D' | b'K' | b'L' | b'M' | b'S' | b'V' | b'X' | b'g' | b'x'
    )
}

/// The name a GNU long name or long link's data states, as the C string GNU
/// tar writes: up to its first NUL.
///
/// `None` at [`Level::Strict`] for data holding a NUL before its last byte,
/// which some readers keep as part of the name
/// ([`ErrorKind::LongNameNul`]).
fn long_name(data: &[u8], level: Level) -> Option<Vec<u8>> {
    let name = header::text(data);
    // `name` ends at the first NUL, so a byte past the one after it is past
    // that NUL.
    let past_nul = name
        .len()
        .checked_add(1)
        .is_some_and(|end| end < data.len());
    if level == Level::Strict && past_nul {
        return None;
    }
    Some(name.to_vec())
}
