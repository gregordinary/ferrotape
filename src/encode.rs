//! Writing a member's header. The fields a caller states are encoded as a
//! POSIX ustar header block, preceded by a pax extended header for whatever
//! the block cannot hold.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::entry::{EntryKind, Timestamp};
use crate::error::Keyword;
use crate::escaped::Escaped;
use crate::header::{BLOCK, Draft, Number, SIZE_LIMIT, Text};
use crate::pax::push_record;
use crate::settings::Limits;

/// The header of a member to write: its path, its kind, and its metadata.
///
/// Each constructor makes one kind of member, with the fields that kind has:
/// a file its size, a link its target, a device its numbers. The rest start
/// empty or zero (owner root, modification time the epoch). The mode starts as
/// `0o644`, `0o755` for a directory or `0o777` for a symbolic link. Each field
/// is set with its own method. Paths, link targets and owner names are bytes,
/// written as given. The caller decides whether a path is acceptable.
///
/// [`encode`](Self::encode) writes the header as a POSIX ustar block. A field
/// the block cannot hold exactly (a long path, a large size or id, a time
/// before 1970 or finer than a second, an access or change time, an extended
/// attribute) goes into a pax extended header written before it. Every reader
/// of the pax format applies that header. The block then holds a placeholder
/// for readers that do not. [`Writer`](crate::Writer) writes headers with their
/// members' data.
///
/// ```
/// use ferrotape::{Header, Timestamp};
///
/// let mut header = Header::file("docs/readme.txt", 5);
/// header
///     .set_mode(0o600)
///     .set_owner(1000, 1000)
///     .set_mtime(Timestamp::from_secs(1_700_000_000));
/// let blocks = header.encode()?;
/// assert_eq!(blocks.len(), 512);
/// # Ok::<(), ferrotape::HeaderError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    kind: EntryKind,
    path: Vec<u8>,
    link_target: Vec<u8>,
    size: u64,
    device: (u32, u32),
    mode: u32,
    uid: u32,
    gid: u32,
    uname: Vec<u8>,
    gname: Vec<u8>,
    mtime: Timestamp,
    atime: Option<Timestamp>,
    ctime: Option<Timestamp>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Header {
    fn new(kind: EntryKind, path: Vec<u8>, mode: u32) -> Header {
        Header {
            kind,
            path,
            link_target: Vec::new(),
            size: 0,
            device: (0, 0),
            mode,
            uid: 0,
            gid: 0,
            uname: Vec::new(),
            gname: Vec::new(),
            mtime: Timestamp::from_secs(0),
            atime: None,
            ctime: None,
            xattrs: Vec::new(),
            records: Vec::new(),
        }
    }

    /// A regular file at `path` whose data is `size` bytes long.
    #[must_use]
    pub fn file(path: impl Into<Vec<u8>>, size: u64) -> Header {
        Header {
            size,
            ..Header::new(EntryKind::File, path.into(), 0o644)
        }
    }

    /// A directory at `path`. Writers conventionally end a directory's path
    /// with `/`. The path is written as given.
    #[must_use]
    pub fn directory(path: impl Into<Vec<u8>>) -> Header {
        Header::new(EntryKind::Directory, path.into(), 0o755)
    }

    /// A symbolic link at `path` pointing at `target`.
    #[must_use]
    pub fn symlink(path: impl Into<Vec<u8>>, target: impl Into<Vec<u8>>) -> Header {
        Header {
            link_target: target.into(),
            ..Header::new(EntryKind::Symlink, path.into(), 0o777)
        }
    }

    /// A hard link at `path` to `target`, the path of an earlier member of
    /// the archive. It has no data: the data is the earlier member's.
    #[must_use]
    pub fn hard_link(path: impl Into<Vec<u8>>, target: impl Into<Vec<u8>>) -> Header {
        Header {
            link_target: target.into(),
            ..Header::new(EntryKind::HardLink, path.into(), 0o644)
        }
    }

    /// A character device at `path` with the device numbers `major` and
    /// `minor`.
    #[must_use]
    pub fn char_device(path: impl Into<Vec<u8>>, major: u32, minor: u32) -> Header {
        Header {
            device: (major, minor),
            ..Header::new(EntryKind::CharDevice, path.into(), 0o644)
        }
    }

    /// A block device at `path` with the device numbers `major` and `minor`.
    #[must_use]
    pub fn block_device(path: impl Into<Vec<u8>>, major: u32, minor: u32) -> Header {
        Header {
            device: (major, minor),
            ..Header::new(EntryKind::BlockDevice, path.into(), 0o644)
        }
    }

    /// A FIFO at `path`.
    #[must_use]
    pub fn fifo(path: impl Into<Vec<u8>>) -> Header {
        Header::new(EntryKind::Fifo, path.into(), 0o644)
    }

    /// Sets the permission bits, setuid, setgid and sticky included: at most
    /// `0o7777`. The member's type is its kind, not part of its mode.
    pub fn set_mode(&mut self, mode: u32) -> &mut Header {
        self.mode = mode;
        self
    }

    /// Sets the owning user's and group's ids.
    pub fn set_owner(&mut self, uid: u32, gid: u32) -> &mut Header {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Sets the owning user's and group's names. An empty name is none, and
    /// is not written.
    pub fn set_owner_names(
        &mut self,
        uname: impl Into<Vec<u8>>,
        gname: impl Into<Vec<u8>>,
    ) -> &mut Header {
        self.uname = uname.into();
        self.gname = gname.into();
        self
    }

    /// Sets the modification time.
    pub fn set_mtime(&mut self, mtime: Timestamp) -> &mut Header {
        self.mtime = mtime;
        self
    }

    /// Sets the access time, which a pax `atime` record states.
    pub fn set_atime(&mut self, atime: Timestamp) -> &mut Header {
        self.atime = Some(atime);
        self
    }

    /// Sets the time of the last change to the member's metadata, which a
    /// pax `ctime` record states.
    pub fn set_ctime(&mut self, ctime: Timestamp) -> &mut Header {
        self.ctime = Some(ctime);
        self
    }

    /// Adds the extended attribute `name` with `value`, written as a
    /// `SCHILY.xattr.` record, which GNU tar, bsdtar and Go read.
    ///
    /// The name is written as its bytes. A name no spelling writes so that
    /// every reader reads it back alike is refused when the header is
    /// encoded ([`HeaderError::XattrName`]).
    pub fn add_xattr(
        &mut self,
        name: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> &mut Header {
        self.xattrs.push((name.into(), value.into()));
        self
    }

    /// Adds a pax record of the caller's own, written after the records the
    /// header's fields need: a `SCHILY.acl.access` list, a `comment`, a
    /// vendor's keyword.
    ///
    /// A keyword the writer derives from the header's fields is refused when
    /// the header is encoded ([`HeaderError::ReservedKeyword`]). A keyword the
    /// readers apply to the member in ways that differ is refused alike. A
    /// default access control list on a member that is not a directory is
    /// refused too ([`HeaderError::DefaultAclWithoutDirectory`]). Each reader
    /// decides what it makes of any other record.
    pub fn add_record(
        &mut self,
        keyword: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> &mut Header {
        self.records.push((keyword.into(), value.into()));
        self
    }

    /// The header as the archive holds it: a pax extended header, where the
    /// fields need one, then the ustar header block. A whole number of
    /// 512-byte blocks.
    ///
    /// This crate's reader reads every header encoded as the member it
    /// describes, every field as set. It does so at
    /// [`Level::Compatible`](crate::Level::Compatible), in every
    /// [`GlobalHeaders`](crate::GlobalHeaders) mode. At
    /// [`Level::Strict`](crate::Level::Strict) it reads them as well, but for
    /// a member whose mode has setuid, setgid or sticky beside an access
    /// control list (a `SCHILY.acl.access` record). Such a member is written
    /// as GNU tar writes it, and Strict refuses it
    /// ([`ErrorKind::SpecialBitsWithAcl`](crate::ErrorKind::SpecialBitsWithAcl)).
    /// A caller that reads its own archives at Strict drops the bits or the
    /// list.
    ///
    /// # Errors
    ///
    /// A [`HeaderError`] where a field cannot be written so that it reads
    /// back as set. [`HeaderError`] lists each case, such as an empty path, a
    /// NUL in a name, or a mode beyond the permission bits.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        self.check()?;
        let directory = self.kind == EntryKind::Directory;
        let mut draft = Draft::new(typeflag(self.kind));
        let mut extended = Extended::default();

        // A text field goes in the block wherever it fits, whatever its bytes:
        // every reader reads the block's bytes as they are, silently, where a
        // pax record of bytes that are not UTF-8 makes bsdtar fail.
        let (prefix, name) = match ustar_split(&self.path) {
            Some((prefix, name)) => (prefix, name.to_vec()),
            None => {
                extended.text(b"path", &self.path)?;
                placeholder(&self.path, directory)
            }
        };
        draft.text(Text::Name, &name);
        draft.text(Text::Prefix, prefix);

        if matches!(self.kind, EntryKind::Symlink | EntryKind::HardLink)
            && !draft.text(Text::Linkname, &self.link_target)
        {
            // Too long for the field, which stays empty rather than holding
            // a target the link does not have.
            extended.text(b"linkpath", &self.link_target)?;
        }

        if !draft.octal(Number::Size, self.size) {
            extended.push(b"size", self.size.to_string().as_bytes())?;
            // The size frames the archive, so the block holds it exactly, in
            // GNU's base-256, which every reader reads beside the record.
            draft.base256(Number::Size, i128::from(self.size));
        }

        draft.octal(Number::Mode, u64::from(self.mode));
        for (field, keyword, id) in [
            (Number::Uid, &b"uid"[..], self.uid),
            (Number::Gid, b"gid", self.gid),
        ] {
            if !draft.octal(field, u64::from(id)) {
                extended.push(keyword, id.to_string().as_bytes())?;
                // An id the field cannot hold, clamped: a reader without the
                // record takes the member for an unprivileged owner's rather
                // than root's.
                draft.octal(field, field.octal_max());
            }
        }
        for (field, keyword, owner) in [
            (Text::Uname, &b"uname"[..], &self.uname),
            (Text::Gname, b"gname", &self.gname),
        ] {
            if !owner.is_empty() && !draft.text(field, owner) {
                extended.text(keyword, owner)?;
            }
        }

        // The block holds whole seconds from the epoch on; a time it cannot
        // hold exactly is the record's, and the block holds the nearest it
        // can.
        let seconds = u64::try_from(self.mtime.secs()).unwrap_or(0);
        let block_mtime = seconds.min(Number::Mtime.octal_max());
        if self.mtime.nanos() != 0 || i64::try_from(block_mtime) != Ok(self.mtime.secs()) {
            extended.push(b"mtime", pax_time(self.mtime).as_bytes())?;
        }
        draft.octal(Number::Mtime, block_mtime);
        if let Some(atime) = self.atime {
            extended.push(b"atime", pax_time(atime).as_bytes())?;
        }
        if let Some(ctime) = self.ctime {
            extended.push(b"ctime", pax_time(ctime).as_bytes())?;
        }

        if matches!(self.kind, EntryKind::CharDevice | EntryKind::BlockDevice) {
            // Seven digits and a NUL, or eight filling the field where seven
            // do not hold the number; `check` refused one eight do not.
            let (major, minor) = self.device;
            for (field, number) in [(Number::DevMajor, major), (Number::DevMinor, minor)] {
                let number = u64::from(number);
                if !draft.octal(field, number) {
                    draft.octal_filling(field, number);
                }
            }
        }

        for (name, value) in &self.xattrs {
            extended.push(&[XATTR, name.as_slice()].concat(), value)?;
        }
        for (keyword, value) in &self.records {
            extended.push(keyword, value)?;
        }

        let records = extended.finish()?;
        let mut out = Vec::with_capacity(BLOCK);
        if !records.is_empty() {
            let size = u64::try_from(records.len()).map_err(|_| HeaderError::MetadataTooLarge)?;
            if size > Limits::default().metadata {
                return Err(HeaderError::MetadataTooLarge);
            }
            let mut pax_block = Draft::new(b'x');
            let (prefix, name) = pax_header_name(&self.path, directory);
            pax_block.text(Text::Name, &name);
            pax_block.text(Text::Prefix, prefix);
            pax_block.octal(Number::Mode, 0o644);
            pax_block.octal(Number::Size, size);
            pax_block.octal(Number::Mtime, block_mtime);
            out.extend_from_slice(&pax_block.seal());
            out.extend_from_slice(&records);
            out.resize(out.len().next_multiple_of(BLOCK), 0);
        }
        out.extend_from_slice(&draft.seal());
        Ok(out)
    }

    /// The length of the member's data.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// Refuses a header whose fields cannot be written to read back as set.
    fn check(&self) -> Result<(), HeaderError> {
        if self.path.is_empty() {
            return Err(HeaderError::EmptyPath);
        }
        for (field, text) in [
            (TextField::Path, &self.path),
            (TextField::LinkTarget, &self.link_target),
            (TextField::Uname, &self.uname),
            (TextField::Gname, &self.gname),
        ] {
            if text.contains(&0) {
                return Err(HeaderError::Nul(field));
            }
        }
        if self.kind != EntryKind::Directory && self.path.ends_with(b"/") {
            return Err(HeaderError::TrailingSlash);
        }
        if matches!(self.kind, EntryKind::Symlink | EntryKind::HardLink)
            && self.link_target.is_empty()
        {
            return Err(HeaderError::EmptyLinkTarget);
        }
        if self.mode > 0o7777 {
            return Err(HeaderError::Mode(self.mode));
        }
        if self.size >= SIZE_LIMIT {
            return Err(HeaderError::SizeOutOfRange(self.size));
        }
        // Past eight octal digits, GNU tar fails on the base-256 form, and
        // only bsdtar applies a `SCHILY.devmajor` record.
        let (major, minor) = self.device;
        let device_max = Number::DevMajor.filling_max();
        if u64::from(major) > device_max || u64::from(minor) > device_max {
            return Err(HeaderError::DeviceOutOfRange { major, minor });
        }
        // bsdtar reads a pax time's fraction forward from the second its
        // digits name, so before 1970 it reads another instant than GNU tar,
        // Go and Python do.
        for (keyword, time) in [
            (Keyword::Mtime, Some(self.mtime)),
            (Keyword::Atime, self.atime),
            (Keyword::Ctime, self.ctime),
        ] {
            if time.is_some_and(|time| time.secs() < 0 && time.nanos() != 0) {
                return Err(HeaderError::FractionBeforeEpoch(keyword));
            }
        }
        for (name, value) in &self.xattrs {
            let escapes = name
                .windows(3)
                .any(|escape| escape == b"%3D" || escape == b"%25");
            if !writable_keyword(name) || escapes {
                return Err(HeaderError::XattrName { name: name.clone() });
            }
            if value.is_empty() {
                return Err(HeaderError::EmptyXattr { name: name.clone() });
            }
        }
        if let Some(name) = repeated(self.xattrs.iter().map(|(name, _)| name.as_slice())) {
            return Err(HeaderError::RepeatedXattr {
                name: name.to_vec(),
            });
        }
        for (keyword, _) in &self.records {
            if !writable_keyword(keyword) {
                return Err(HeaderError::Keyword {
                    keyword: keyword.clone(),
                });
            }
            if reserved(keyword) {
                return Err(HeaderError::ReservedKeyword {
                    keyword: keyword.clone(),
                });
            }
            // The reader refuses a default list on any member but a directory
            // (`ErrorKind::DefaultAclWithoutDirectory`).
            if keyword == b"SCHILY.acl.default" && self.kind != EntryKind::Directory {
                return Err(HeaderError::DefaultAclWithoutDirectory);
            }
        }
        if let Some(keyword) = repeated(self.records.iter().map(|(keyword, _)| keyword.as_slice()))
        {
            return Err(HeaderError::RepeatedKeyword {
                keyword: keyword.to_vec(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("kind", &self.kind)
            .field("path", &Escaped(&self.path))
            .field("link_target", &Escaped(&self.link_target))
            .field("size", &self.size)
            .field("device", &self.device)
            .field("mode", &format_args!("{:#o}", self.mode))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("uname", &Escaped(&self.uname))
            .field("gname", &Escaped(&self.gname))
            .field("mtime", &self.mtime)
            .field("atime", &self.atime)
            .field("ctime", &self.ctime)
            .field(
                "xattrs",
                &self
                    .xattrs
                    .iter()
                    .map(|(name, value)| (Escaped(name), Escaped(value)))
                    .collect::<Vec<_>>(),
            )
            .field(
                "records",
                &self
                    .records
                    .iter()
                    .map(|(keyword, value)| (Escaped(keyword), Escaped(value)))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The records of a member's pax extended header, as they are gathered.
#[derive(Default)]
struct Extended {
    records: Vec<u8>,
    /// Whether a text value (a path, a link target, an owner name) is not
    /// UTF-8, which POSIX has a header declare.
    binary: bool,
}

impl Extended {
    fn push(&mut self, keyword: &[u8], value: &[u8]) -> Result<(), HeaderError> {
        push_record(&mut self.records, keyword, value).ok_or(HeaderError::MetadataTooLarge)
    }

    /// A text value, which POSIX reads as UTF-8 unless the header says
    /// otherwise.
    fn text(&mut self, keyword: &[u8], value: &[u8]) -> Result<(), HeaderError> {
        self.binary |= core::str::from_utf8(value).is_err();
        self.push(keyword, value)
    }

    /// The records, `hdrcharset=BINARY` first where a text value is not
    /// UTF-8. bsdtar fails on such a value without it, and reads it with it.
    /// Python takes it as bytes either way. GNU tar and Go read the bytes as
    /// they are, GNU tar warning that it does not know the keyword.
    fn finish(self) -> Result<Vec<u8>, HeaderError> {
        if !self.binary {
            return Ok(self.records);
        }
        let mut records = Vec::new();
        push_record(&mut records, b"hdrcharset", b"BINARY").ok_or(HeaderError::MetadataTooLarge)?;
        records.extend_from_slice(&self.records);
        Ok(records)
    }
}

/// The keyword prefix of a record holding an extended attribute.
const XATTR: &[u8] = b"SCHILY.xattr.";

/// The typeflag of a member of `kind`.
fn typeflag(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::File => b'0',
        EntryKind::HardLink => b'1',
        EntryKind::Symlink => b'2',
        EntryKind::CharDevice => b'3',
        EntryKind::BlockDevice => b'4',
        EntryKind::Directory => b'5',
        EntryKind::Fifo => b'6',
    }
}

/// `path` as the block's prefix and name, where it fits. It goes in the name
/// alone, or is split at a `/` into a prefix and a name, neither empty. A
/// reader joins the two with that `/`. The prefix never ends in `/`. bsdtar joins
/// such a prefix to the name without adding one, reading `a//b` as `a/b`,
/// where the other readers keep both. A name that begins with `/` is read
/// alike.
fn ustar_split(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= Text::Name.capacity() {
        return Some((&[], path));
    }
    // The longest prefix that fits, so the shortest name.
    path.iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'/')
        .find_map(|(at, _)| {
            let (prefix, rest) = path.split_at_checked(at)?;
            let name = rest.get(1..)?;
            let fits = !prefix.is_empty()
                && !prefix.ends_with(b"/")
                && prefix.len() <= Text::Prefix.capacity()
                && !name.is_empty()
                && name.len() <= Text::Name.capacity();
            fits.then_some((prefix, name))
        })
}

/// The block's prefix and name for a `path` that a pax `path` record states.
///
/// As bsdtar's placeholder does, it keeps the path's leading components in
/// the prefix and its last in the name. A reader without the record then puts
/// the member in a directory it belongs under. The name is the last
/// component, cut to fit, ending in `/` where a directory's path does. The
/// prefix is as many leading components as fit. GNU tar, Go and Python write
/// the path's first 100 bytes instead. Unlike those, the name never ends in
/// `/` but a directory's, which a reader without the record would extract as
/// a directory.
fn placeholder(path: &[u8], directory: bool) -> (&[u8], Vec<u8>) {
    let slash = directory && path.ends_with(b"/");
    let trimmed = trim_slashes(path);
    let (dir, last) = match trimmed.iter().rposition(|byte| *byte == b'/') {
        Some(at) => (
            trimmed.get(..at).unwrap_or_default(),
            trimmed.get(at.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (&[][..], trimmed),
    };
    let room = if slash {
        Text::Name.capacity().saturating_sub(1)
    } else {
        Text::Name.capacity()
    };
    // Not empty: a path that does not end in `/` ends in another byte, and
    // one that does keeps its `/`.
    let mut name = last.get(..room).unwrap_or(last).to_vec();
    if slash {
        name.push(b'/');
    }
    (leading_components(dir, Text::Prefix.capacity()), name)
}

/// The block's prefix and name for the pax extended header before a member at
/// `path`.
///
/// `PaxHeader/` and the member's last component, in the placeholder's
/// prefix, as bsdtar names it. A reader that does not know typeflag `x`
/// extracts it as a file beside the member rather than over it.
fn pax_header_name(path: &[u8], directory: bool) -> (&[u8], Vec<u8>) {
    let (prefix, name) = placeholder(path, directory);
    let base = trim_slashes(&name);
    let mut header_name = b"PaxHeader/".to_vec();
    let room = Text::Name.capacity().saturating_sub(header_name.len());
    header_name.extend_from_slice(base.get(..room).unwrap_or(base));
    (prefix, header_name)
}

/// `path` without the `/`s it ends in.
fn trim_slashes(path: &[u8]) -> &[u8] {
    let end = path
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |at| at.saturating_add(1));
    path.get(..end).unwrap_or_default()
}

/// The longest run of `dir`'s leading components, `/`s between them, of at
/// most `room` bytes. It has no `/` at its end, which bsdtar would not
/// separate from the name.
fn leading_components(dir: &[u8], room: usize) -> &[u8] {
    if dir.len() <= room {
        return trim_slashes(dir);
    }
    let end = dir
        .iter()
        .take(room.saturating_add(1))
        .rposition(|byte| *byte == b'/')
        .unwrap_or(0);
    trim_slashes(dir.get(..end).unwrap_or_default())
}

/// A pax time: seconds since the epoch, and the fraction of a second where
/// there is one. The fraction has as few digits as hold it exactly, as GNU
/// tar, bsdtar and Go write it. A time before 1970 with a fraction is refused before this
/// ([`HeaderError::FractionBeforeEpoch`]).
fn pax_time(time: Timestamp) -> String {
    let (secs, nanos) = (time.secs(), time.nanos());
    if nanos == 0 {
        return secs.to_string();
    }
    let digits = alloc::format!("{nanos:09}");
    alloc::format!("{secs}.{}", digits.trim_end_matches('0'))
}

/// Whether `keyword` can be written as a record's keyword. It is not empty,
/// and holds no `=`, which ends a keyword. It holds no NUL either, which ends
/// one for GNU tar and bsdtar and which Go refuses. A record's length frames it, so a newline
/// is read alike by every reader.
fn writable_keyword(keyword: &[u8]) -> bool {
    !keyword.is_empty() && !keyword.iter().any(|byte| matches!(byte, b'=' | 0))
}

/// Whether `keyword` is one a caller's record may not use. The writer derives
/// such a keyword from the header's fields, or the readers apply it to a
/// member in ways that differ.
fn reserved(keyword: &[u8]) -> bool {
    const FIELDS: [&[u8]; 13] = [
        b"path",
        b"linkpath",
        b"size",
        b"uid",
        b"gid",
        b"uname",
        b"gname",
        b"mtime",
        b"atime",
        b"ctime",
        b"hdrcharset",
        b"SCHILY.devmajor",
        b"SCHILY.devminor",
    ];
    // The fields, and bsdtar's device numbers, which the other readers do not
    // apply; extended attributes, which `add_xattr` writes; bsdtar's second
    // spelling of them, and SELinux's, which readers apply differently; and
    // GNU's sparse, volume and dump records.
    const PREFIXES: [&[u8]; 4] = [b"SCHILY.xattr.", b"LIBARCHIVE.xattr.", b"RHT.", b"GNU."];
    FIELDS.contains(&keyword) || PREFIXES.iter().any(|prefix| keyword.starts_with(prefix))
}

/// A name `names` holds more than once.
fn repeated<'a>(names: impl Iterator<Item = &'a [u8]>) -> Option<&'a [u8]> {
    let mut names: Vec<&[u8]> = names.collect();
    names.sort_unstable();
    names.windows(2).find_map(|pair| match pair {
        [one, other] if one == other => Some(*one),
        _ => None,
    })
}

/// A text field of a [`Header`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum TextField {
    /// The member's path.
    Path,
    /// A link's target.
    LinkTarget,
    /// The owning user's name.
    Uname,
    /// The owning group's name.
    Gname,
}

impl fmt::Display for TextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TextField::Path => "path",
            TextField::LinkTarget => "link target",
            TextField::Uname => "user name",
            TextField::Gname => "group name",
        })
    }
}

/// Why a [`Header`] cannot be encoded: a field that no encoding writes so
/// that it reads back as set.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum HeaderError {
    /// The path is empty.
    EmptyPath,
    /// A symbolic or hard link's target is empty.
    EmptyLinkTarget,
    /// A path, link target or owner name holds a NUL byte, which ends it for
    /// every reader that reads it as a C string.
    Nul(TextField),
    /// The path ends in `/`, and the member is not a directory. GNU tar and
    /// bsdtar read a regular file named so as a directory.
    TrailingSlash,
    /// The mode has bits set beyond the permission bits, setuid, setgid and
    /// sticky (`0o7777`).
    Mode(u32),
    /// The size is 2^60 or more, past which bsdtar stops at the member.
    SizeOutOfRange(u64),
    /// A time before 1970 with a fraction of a second, which bsdtar reads
    /// otherwise than the other readers
    /// ([`ErrorKind::FractionBeforeEpoch`](crate::ErrorKind::FractionBeforeEpoch)).
    FractionBeforeEpoch(Keyword),
    /// A device number is larger than eight octal digits hold (16,777,215).
    /// GNU tar fails on a larger one in GNU's base-256 form, and only bsdtar
    /// applies a `SCHILY.devmajor` record.
    DeviceOutOfRange {
        /// The major number.
        major: u32,
        /// The minor number.
        minor: u32,
    },
    /// An extended attribute's name cannot be written so that every reader
    /// reads it back alike. It is empty, or holds `=`, a NUL, or `%3D` or
    /// `%25`, which GNU tar decodes and bsdtar and Go do not.
    XattrName {
        /// The name.
        name: Vec<u8>,
    },
    /// An extended attribute's value is empty, which Go reads otherwise than
    /// GNU tar and bsdtar
    /// ([`ErrorKind::EmptyXattr`](crate::ErrorKind::EmptyXattr)).
    EmptyXattr {
        /// The attribute's name.
        name: Vec<u8>,
    },
    /// Two extended attributes have one name.
    RepeatedXattr {
        /// The name.
        name: Vec<u8>,
    },
    /// A record's keyword cannot be written: it is empty, or holds `=` or a
    /// NUL.
    Keyword {
        /// The keyword.
        keyword: Vec<u8>,
    },
    /// A record's keyword is reserved. The writer derives it from the
    /// header's fields (`path`, `size`, `mtime` and the like, and
    /// `SCHILY.xattr.` records, which [`Header::add_xattr`] writes), or the
    /// readers apply it to the member in ways that differ (`SCHILY.devmajor`,
    /// `SCHILY.devminor`, `LIBARCHIVE.xattr.`, `RHT.`, `GNU.`).
    ReservedKeyword {
        /// The keyword.
        keyword: Vec<u8>,
    },
    /// Two records have one keyword.
    RepeatedKeyword {
        /// The keyword.
        keyword: Vec<u8>,
    },
    /// A default access control list, a `SCHILY.acl.default` record, is given
    /// for a member that is not a directory. bsdtar reads such a member with
    /// mode `000`, and the other readers with the header's mode.
    DefaultAclWithoutDirectory,
    /// The pax extended header the fields need is larger than a reader reads
    /// by default ([`Limits::metadata`](crate::Limits::metadata)).
    MetadataTooLarge,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::EmptyPath => f.write_str("the path is empty"),
            HeaderError::EmptyLinkTarget => f.write_str("the link target is empty"),
            HeaderError::Nul(field) => write!(f, "the {field} holds a NUL"),
            HeaderError::TrailingSlash => {
                f.write_str("the path ends in `/`, and the member is not a directory")
            }
            HeaderError::Mode(mode) => {
                write!(f, "the mode {mode:#o} has bits beyond the permission bits")
            }
            HeaderError::SizeOutOfRange(size) => write!(f, "the size {size} is too large"),
            HeaderError::FractionBeforeEpoch(keyword) => write!(
                f,
                "the {keyword} is before 1970 and has a fraction of a second",
            ),
            HeaderError::DeviceOutOfRange { major, minor } => {
                write!(f, "the device numbers {major},{minor} are too large")
            }
            HeaderError::XattrName { name } => write!(
                f,
                "the extended attribute name `{}` cannot be written alike for every reader",
                name.escape_ascii(),
            ),
            HeaderError::EmptyXattr { name } => write!(
                f,
                "the extended attribute `{}` has an empty value",
                name.escape_ascii(),
            ),
            HeaderError::RepeatedXattr { name } => write!(
                f,
                "the extended attribute `{}` is given twice",
                name.escape_ascii(),
            ),
            HeaderError::Keyword { keyword } => write!(
                f,
                "`{}` cannot be written as a pax keyword",
                keyword.escape_ascii(),
            ),
            HeaderError::ReservedKeyword { keyword } => write!(
                f,
                "the pax keyword `{}` is not the caller's to write",
                keyword.escape_ascii(),
            ),
            HeaderError::RepeatedKeyword { keyword } => write!(
                f,
                "the pax keyword `{}` is given twice",
                keyword.escape_ascii(),
            ),
            HeaderError::DefaultAclWithoutDirectory => f.write_str(
                "a default access control list is given for a member that is not a directory",
            ),
            HeaderError::MetadataTooLarge => {
                f.write_str("the pax extended header is larger than a reader reads by default")
            }
        }
    }
}

impl core::error::Error for HeaderError {}
