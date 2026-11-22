//! A member of an archive, as the reader reads it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::escaped::Escaped;
use crate::header::BLOCK;
use crate::pax::PaxRecords;
use crate::sparse::Sparse;

/// A member of an archive, its long name, long link and pax records already
/// applied.
///
/// Paths, link targets and owner names are the archive's bytes: nothing is
/// decoded or checked as a path. Whether an absolute path or a `..` component
/// is acceptable is the caller's to decide.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub(crate) path: Vec<u8>,
    pub(crate) link_target: Vec<u8>,
    pub(crate) typeflag: u8,
    pub(crate) kind: EntryKind,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) uname: Vec<u8>,
    pub(crate) gname: Vec<u8>,
    pub(crate) size: u64,
    pub(crate) declared_size: u64,
    pub(crate) mtime: Timestamp,
    pub(crate) atime: Option<Timestamp>,
    pub(crate) ctime: Option<Timestamp>,
    pub(crate) device: Option<(u32, u32)>,
    pub(crate) header: Box<[u8; BLOCK]>,
    pub(crate) header_offset: u64,
    pub(crate) data_offset: u64,
    pub(crate) sparse: Option<Box<Sparse>>,
    pub(crate) pax: PaxRecords,
    pub(crate) global: PaxRecords,
}

impl Entry {
    /// The member's path: a pax `path` record, a GNU long name, or the
    /// header's own name and, in a POSIX header, its prefix. Never empty.
    ///
    /// A global `path` record is the member's path where the reader applies
    /// global headers ([`GlobalHeaders::Apply`](crate::GlobalHeaders::Apply))
    /// and the member's own records state none.
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// A link's target: a pax `linkpath` record, a GNU long link, or the
    /// header's own link name. Empty where the archive states none.
    #[must_use]
    pub fn link_target(&self) -> &[u8] {
        &self.link_target
    }

    /// What kind of member this is: its typeflag, as GNU tar and bsdtar read
    /// it.
    #[must_use]
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The typeflag, as the header holds it: `0` (or NUL, in a v7 header)
    /// for a regular file, `1` a hard link, `2` a symbolic link, `3` a
    /// character device, `4` a block device, `5` a directory, `6` a FIFO, or
    /// another byte. [`kind`](Self::kind) says what the reader takes it for.
    #[must_use]
    pub fn typeflag(&self) -> u8 {
        self.typeflag
    }

    /// The permission bits, setuid, setgid and sticky included.
    #[must_use]
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// The owning user's id: a pax `uid` record, or the header's own.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The owning group's id: a pax `gid` record, or the header's own.
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The owning user's name: a pax `uname` record, or the header's own.
    /// Empty where the archive states none, as a v7 header cannot.
    #[must_use]
    pub fn uname(&self) -> &[u8] {
        &self.uname
    }

    /// The owning group's name: a pax `gname` record, or the header's own.
    /// Empty where the archive states none, as a v7 header cannot.
    #[must_use]
    pub fn gname(&self) -> &[u8] {
        &self.gname
    }

    /// The length of the data the reader delivers for the member, in bytes.
    ///
    /// The [declared size](Self::declared_size) for a member that carries
    /// data, and zero for a hard link, a symbolic link, a device, a directory
    /// or a FIFO, which carry none whatever their header declares. A GNU
    /// dumpdir (typeflag `D`) is a directory that carries data: the names of
    /// the files in it when it was archived.
    ///
    /// For a [sparse](Self::sparse) member, the real size of the file it
    /// stands for, which may be far larger than what the archive stores, up
    /// to 2^60 - 1 bytes: a caller copying the data to a file checks this
    /// first, or writes the holes as holes ([`Reader::stored_data`]).
    ///
    /// [`Reader::stored_data`]: crate::Reader::stored_data
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The size the archive declares for the member: a pax `size` record, or
    /// the header's own. For a sparse member, what it stores: the regions'
    /// data and, in GNU's format 1.0, the map before it.
    #[must_use]
    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }

    /// The modification time: a pax `mtime` record, or the header's own,
    /// which is whole seconds.
    #[must_use]
    pub fn mtime(&self) -> Timestamp {
        self.mtime
    }

    /// The access time, where a pax `atime` record states it.
    #[must_use]
    pub fn atime(&self) -> Option<Timestamp> {
        self.atime
    }

    /// The time of the last change to the member's metadata, where a pax
    /// `ctime` record states it.
    #[must_use]
    pub fn ctime(&self) -> Option<Timestamp> {
        self.ctime
    }

    /// A device's major and minor numbers, for a character or block device,
    /// and `None` for any other kind of member.
    ///
    /// A header with no device fields, a v7 one, gives 0,0, as every reader
    /// reports and extracts it.
    #[must_use]
    pub fn device(&self) -> Option<(u32, u32)> {
        self.device
    }

    /// The member's own header block, as the archive holds it.
    ///
    /// The metadata before it, long names and pax records, may have replaced
    /// any of its fields; the block shows what it stated itself.
    #[must_use]
    pub fn header_block(&self) -> &[u8; BLOCK] {
        &self.header
    }

    /// Where the member's own header block begins, in bytes from the start
    /// of the stream. Metadata describing the member comes before it.
    #[must_use]
    pub fn header_offset(&self) -> u64 {
        self.header_offset
    }

    /// Where the member's data begins, in bytes from the start of the
    /// stream: just past its header block, or for a sparse member, where its
    /// stored data begins, past an old GNU header's extension blocks or a
    /// format 1.0 map.
    #[must_use]
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }

    /// The length of the member's data as the archive stores it: for a
    /// sparse member, its regions' bytes, and otherwise its size.
    pub(crate) fn stored_len(&self) -> u64 {
        self.sparse
            .as_deref()
            .map_or(self.size, |map| map.stored_size)
    }

    /// The map of a sparse member: where the data the archive stores lies
    /// in the file the member stands for. `None` for any other member.
    ///
    /// A sparse member is a regular file ([`EntryKind::File`]): an old GNU
    /// one has typeflag `S`, a pax one typeflag `0` and `GNU.sparse.`
    /// records, which [`pax_records`](Self::pax_records) holds as the
    /// archive spells them. Its path is the file's: for GNU's pax formats 0.1
    /// and 1.0, the `GNU.sparse.name` record, where the header's own name is
    /// `GNUSparseFile.<n>/` and the name.
    #[must_use]
    pub fn sparse(&self) -> Option<&Sparse> {
        self.sparse.as_deref()
    }

    /// The records of the pax extended header that preceded the member.
    #[must_use]
    pub fn pax_records(&self) -> &PaxRecords {
        &self.pax
    }

    /// The records of the global extended header between the member before
    /// this one, or the archive's start, and this member. Empty where there
    /// is none.
    ///
    /// Each global header's records reach the caller here once, on the member
    /// after it, whether or not the reader applies them
    /// ([`GlobalHeaders`](crate::GlobalHeaders)). A global header that
    /// follows the last member is
    /// [`Reader::trailing_global`](crate::Reader::trailing_global).
    #[must_use]
    pub fn global(&self) -> &PaxRecords {
        &self.global
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("path", &Escaped(&self.path))
            .field("link_target", &Escaped(&self.link_target))
            .field("kind", &self.kind)
            .field("typeflag", &char::from(self.typeflag))
            .field("mode", &format_args!("{:#o}", self.mode))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("uname", &Escaped(&self.uname))
            .field("gname", &Escaped(&self.gname))
            .field("size", &self.size)
            .field("declared_size", &self.declared_size)
            .field("mtime", &self.mtime)
            .field("atime", &self.atime)
            .field("ctime", &self.ctime)
            .field("device", &self.device)
            .field("header_offset", &self.header_offset)
            .field("data_offset", &self.data_offset)
            .field("sparse", &self.sparse)
            .field("pax_records", &self.pax)
            .field("global", &self.global)
            .finish_non_exhaustive()
    }
}

/// What kind of member an [`Entry`] is.
///
/// Read from the typeflag as GNU tar and bsdtar read it. A regular file's
/// typeflag (`0`, a v7 NUL, or `7`, a contiguous file) on a path ending in
/// `/` is a directory, as the oldest archives mark one. A GNU dumpdir (`D`)
/// is a directory. Any typeflag the reader does not know is a regular file,
/// as POSIX specifies. A few it knows are refused rather than read: see
/// [`ErrorKind`](crate::ErrorKind).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A hard link to an earlier member, named by the link target.
    HardLink,
    /// A symbolic link.
    Symlink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A directory.
    Directory,
    /// A FIFO.
    Fifo,
}

impl EntryKind {
    /// The kind of a member of `typeflag` at `path`.
    pub(crate) fn of(typeflag: u8, path: &[u8]) -> EntryKind {
        match typeflag {
            b'1' => EntryKind::HardLink,
            b'2' => EntryKind::Symlink,
            b'3' => EntryKind::CharDevice,
            b'4' => EntryKind::BlockDevice,
            b'5' | b'D' => EntryKind::Directory,
            b'6' => EntryKind::Fifo,
            b'0' | 0 | b'7' if path.last() == Some(&b'/') => EntryKind::Directory,
            _ => EntryKind::File,
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::File => "regular file",
            EntryKind::HardLink => "hard link",
            EntryKind::Symlink => "symbolic link",
            EntryKind::CharDevice => "character device",
            EntryKind::BlockDevice => "block device",
            EntryKind::Directory => "directory",
            EntryKind::Fifo => "FIFO",
        })
    }
}

/// An instant, as seconds and nanoseconds since the Unix epoch.
///
/// A time before 1970 has negative seconds; the nanoseconds always count
/// forward from the second, so -1.5 seconds is -2 seconds and 500,000,000
/// nanoseconds. A pax time more precise than a nanosecond is floored to one.
/// Timestamps order chronologically.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timestamp {
    secs: i64,
    nanos: u32,
}

impl Timestamp {
    /// The instant `secs` seconds and `nanos` nanoseconds after the epoch, or
    /// `None` where `nanos` is a second or more.
    ///
    /// Before 1970 the nanoseconds still count forward: 1.5 seconds before
    /// the epoch is `Timestamp::new(-2, 500_000_000)`.
    #[must_use]
    pub fn new(secs: i64, nanos: u32) -> Option<Timestamp> {
        (nanos < 1_000_000_000).then_some(Timestamp { secs, nanos })
    }

    /// The instant `secs` whole seconds after the epoch.
    #[must_use]
    pub fn from_secs(secs: i64) -> Timestamp {
        Timestamp { secs, nanos: 0 }
    }

    /// The whole seconds since the epoch, floored: negative before 1970.
    #[must_use]
    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// The nanoseconds past [`secs`](Self::secs), less than a second.
    #[must_use]
    pub fn nanos(&self) -> u32 {
        self.nanos
    }
}
