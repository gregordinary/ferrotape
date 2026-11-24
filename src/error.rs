//! The error a read fails with: where in the stream, and which rule the
//! archive breaks.

use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "std")]
use std::io;

use crate::entry::EntryKind;

/// Why reading an archive failed, and where.
///
/// [`kind`](Self::kind) names the rule the archive breaks, or says that the
/// source beneath it failed. [`offset`](Self::offset) says where in the
/// stream. For [`ErrorKind::Io`], [`source`](core::error::Error::source) is
/// the source's own failure.
///
/// An `Error` converts into an [`io::Error`] that carries it, which is what
/// [`Data`](crate::Data) returns. A [`Reader`](crate::Reader) whose source
/// fails with one returns the error it carries, as it was. An archive read
/// from another archive's member thus reports the outer archive's failure as
/// that, and not as its own source failing.
#[derive(Debug)]
pub struct Error {
    offset: u64,
    kind: ErrorKind,
    #[cfg(feature = "std")]
    source: Option<io::Error>,
}

impl Error {
    /// An error of `kind` at `offset`, which nothing beneath the archive
    /// caused.
    pub(crate) fn new(offset: u64, kind: ErrorKind) -> Error {
        Error {
            offset,
            kind,
            #[cfg(feature = "std")]
            source: None,
        }
    }

    /// `err`, a failed read of the source `offset` bytes into the stream.
    ///
    /// An [`io::Error`] carrying the error a reader failed with is that
    /// reader's failure, and is returned as it was.
    /// Any other is the source failing to deliver what it holds:
    /// [`ErrorKind::Io`], with `err` as its source. A caller that retries such
    /// a failure can tell it from a refused archive, which a retry will not
    /// mend.
    #[cfg(feature = "std")]
    pub(crate) fn from_source(offset: u64, err: io::Error) -> Error {
        match err.downcast::<Error>() {
            Ok(carried) => carried,
            Err(err) => Error {
                offset,
                kind: ErrorKind::Io,
                source: Some(err),
            },
        }
    }

    /// What failed: the rule the archive breaks, or the source.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Where in the stream it failed, in bytes from its start.
    ///
    /// For a refusal of a header or of the records a header holds, the offset
    /// of that header's block. For an archive that ends early, or a
    /// source that fails, the offset the stream had reached.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at offset {}", self.kind, self.offset)
    }
}

impl core::error::Error for Error {
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|err| err as &(dyn core::error::Error + 'static))
    }
}

#[cfg(feature = "std")]
impl From<Error> for io::Error {
    /// The source's own failure, for [`ErrorKind::Io`]. For any other kind,
    /// an [`io::Error`] that carries it, which `io::Error::downcast` recovers.
    /// Its kind is [`UnexpectedEof`](io::ErrorKind::UnexpectedEof) for an
    /// archive that ends early, and [`InvalidData`](io::ErrorKind::InvalidData)
    /// for any other refusal.
    fn from(err: Error) -> io::Error {
        match err {
            Error {
                kind: ErrorKind::Io,
                source: Some(source),
                ..
            } => source,
            err => {
                let kind = match err.kind {
                    ErrorKind::Truncated(_) => io::ErrorKind::UnexpectedEof,
                    _ => io::ErrorKind::InvalidData,
                };
                io::Error::new(kind, err)
            }
        }
    }
}

/// What is wrong with an archive the reader refuses, or what else failed.
///
/// Where the reader refuses an archive that some other reader reads, the
/// variant's documentation says what the readers disagree about. The readers
/// are GNU tar, bsdtar, Go's `archive/tar` and Python's `tarfile`, which
/// ferrotape is measured against.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Reading the source failed. The error's
    /// [`source`](core::error::Error::source) is the failure, as the source
    /// returned it.
    Io,
    /// The stream is not a tar archive. It ends before its first block is
    /// whole, or its first block holds neither magic nor a checksum that
    /// matches. The first 512 bytes of a file in another format are such a
    /// block.
    ///
    /// A first header that holds the magic and fails its checksum is a
    /// damaged archive, [`Checksum`](Self::Checksum). A first header refused
    /// for what it declares keeps the kind it was refused for.
    NotATar,
    /// The archive ends before what it declares is complete.
    Truncated(Truncation),
    /// A header holding the ustar or GNU magic fails its checksum. The stored
    /// value matches neither the unsigned sum of the block's bytes nor the
    /// signed sum some historical writers stored.
    ///
    /// The sum is octal. Python reads a header whose sum is written in GNU's
    /// base-256 form. GNU tar and bsdtar pass over it, and read the next block
    /// as a header.
    Checksum,
    /// A block where a header belongs, after the first, holds neither magic
    /// nor a checksum that matches.
    NotAHeader,
    /// A numeric header field does not read as a value it may hold.
    HeaderField {
        /// The field.
        field: HeaderField,
        /// What is wrong with it.
        problem: Numeric,
    },
    /// A pax extended header's records do not frame. A record's length
    /// decides where the next record begins, so past one that does not frame
    /// there is no boundary to read on from.
    PaxFraming(PaxFraming),
    /// A pax record the reader applies to its member holds a value the
    /// record may not hold.
    ///
    /// A number is decimal digits and nothing else. An integer parser's `+`
    /// is refused, since GNU tar refuses a `size` of `+5` and bsdtar misframes
    /// the archive on it. A `uid` or `gid` above 2^32 - 1 is out of range,
    /// which GNU tar refuses and the other readers read. Ids here are 32-bit.
    /// A `size` is out of range where the block padding after it would not
    /// fit in 64 bits.
    PaxValue {
        /// The record's keyword.
        keyword: Keyword,
        /// What is wrong with its value.
        problem: Numeric,
    },
    /// A pax `path`, `linkpath`, `uname` or `gname` record is empty.
    ///
    /// bsdtar and Go read an empty value as POSIX's deletion of the record,
    /// leaving the header's own field to stand. Python reads it as the empty
    /// value, and so does GNU tar for each of these but `path`. The readers
    /// name the member, its link target or its owner differently. An empty
    /// numeric record is [`PaxValue`](Self::PaxValue).
    EmptyPaxValue {
        /// The record's keyword.
        keyword: Keyword,
    },
    /// A pax `path`, `linkpath`, `uname` or `gname` record holds a NUL byte.
    ///
    /// A record's length, not a NUL, ends its value, so the byte is part of a
    /// name no file or owner can have. GNU tar and bsdtar cut the name there,
    /// Python keeps the byte, and Go refuses the archive.
    PaxNul {
        /// The record's keyword.
        keyword: Keyword,
    },
    /// One pax extended header, or one global header, holds a keyword twice,
    /// with different values. Refused at [`Level::Strict`](crate::Level::Strict),
    /// and at both levels in a global header whose records
    /// [`GlobalHeaders::Apply`](crate::GlobalHeaders::Apply) applies.
    ///
    /// POSIX gives the last record precedence, and the reference readers take
    /// the last in a member's own header. The `tar` crate takes the first, so
    /// a repeated `size` frames the member differently there.
    /// Of a global header's records, GNU tar applies the first and Python the
    /// last. Otherwise, at [`Level::Compatible`](crate::Level::Compatible),
    /// the last is read. A keyword repeated with one value is read at both
    /// levels.
    RepeatedKeyword {
        /// The keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// Two metadata members of one kind precede a member: two pax extended
    /// headers, two GNU long names or long links, or two global extended
    /// headers.
    ///
    /// No writer emits a second, and the readers part ways over one. GNU tar
    /// and Go take the last. Python takes the first long name and a merge of
    /// the pax records. bsdtar refuses, as it refuses two global headers with
    /// no member between them.
    RepeatedMetadata(Metadata),
    /// A GNU long name or long link holds a NUL before its last byte.
    /// Refused at [`Level::Strict`](crate::Level::Strict).
    ///
    /// The reference readers end the name at its first NUL. The `tar` and
    /// `tar-core` crates strip one trailing NUL and keep the rest, bytes after
    /// an inner NUL and a second NUL included. They name the member
    /// differently. At [`Level::Compatible`](crate::Level::Compatible)
    /// the name ends at its first NUL.
    LongNameNul(Metadata),
    /// A GNU long name or long link holds no NUL, and the padding after its
    /// data begins with a byte that is not one.
    ///
    /// GNU tar and Python read the name on past its size, into the padding,
    /// as far as the first NUL. bsdtar and Go read as far as its size, and so
    /// name the member, or its link target, differently. Where the data
    /// holds a NUL, or the padding begins with one, every reader reads the
    /// same name.
    LongNameOverrun(Metadata),
    /// A metadata member holds nothing: a pax extended header or a global one
    /// with no records, or a GNU long link whose value is empty.
    ///
    /// bsdtar fails on an empty pax or global header, having listed the
    /// members before it, where GNU tar, Go and Python read on. GNU tar and
    /// Python take an empty long link as the member's link target, and bsdtar
    /// and Go the target its own header names. An empty GNU long name leaves
    /// the member no name ([`EmptyName`](Self::EmptyName)).
    EmptyMetadata(Metadata),
    /// A header has the typeflag of a pax extended header, a GNU long name or
    /// a GNU long link. Its magic and version are not exactly POSIX's
    /// (`ustar\0` and `00`) or GNU's (`ustar ` and ` \0`), as in a v7 header,
    /// which has none. Refused at [`Level::Strict`](crate::Level::Strict).
    ///
    /// The reference readers apply it to the member after it, as they would
    /// under either pair. The `tar` and `tar-core` crates read it as a member
    /// of its own, and the member after it under its own name.
    /// At [`Level::Compatible`](crate::Level::Compatible) it is applied.
    MetadataWithoutMagic(Metadata),
    /// A pax `path` record names the member otherwise than a GNU long name,
    /// or a `linkpath` record its target otherwise than a long link.
    ///
    /// GNU tar and bsdtar take the pax record. Python and Go take the long
    /// name. Where the two agree, the member is read.
    LongNameConflict {
        /// The pax record's keyword: [`Keyword::Path`] or
        /// [`Keyword::Linkpath`].
        keyword: Keyword,
    },
    /// A `SCHILY.xattr.` record's attribute name is one the readers extract
    /// differently: it holds `%3D` or `%25`, or it is empty.
    ///
    /// A keyword ends at its first `=`, so GNU tar writes `=` in a name as
    /// `%3D`, and `%` as `%25`, and reads both back. bsdtar and Go read the
    /// name as spelled, and so extract or report the attribute under another
    /// name. No reader extracts an attribute with an empty name. Go reports
    /// one.
    XattrName {
        /// The record's keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// A pax `RHT.security.selinux` record, a second spelling of the SELinux
    /// label `security.selinux`, in a form the readers apply differently:
    ///
    /// - Beside another record of the label that it does not repeat as GNU
    ///   tar writes the two
    /// - Alone, and given twice, empty or holding a NUL
    ///
    /// GNU tar applies the record only with `--selinux`, after any
    /// `SCHILY.xattr.` record of the label, with a NUL appended. bsdtar
    /// applies every record of the label in the archive's order. Go reports
    /// only the `SCHILY.xattr.` record. The member is read in two forms. In
    /// one, a later `SCHILY.xattr.security.selinux` record, the last, holds the
    /// same context followed by one NUL, which every reader then extracts
    /// alike. In the other, the record is alone, given once with a context,
    /// which GNU tar with `--selinux` and bsdtar apply alike.
    SelinuxConflict,
    /// A device's `SCHILY.devmajor` or `SCHILY.devminor` record states other
    /// numbers than its header, or is not decimal digits. A missing record
    /// counts as 0.
    ///
    /// bsdtar takes a device's numbers from these records, a missing one
    /// as 0. GNU tar, Go and Python take them from the header, so the readers
    /// make different devices of it. For a number of 262,144 or more, bsdtar
    /// writes one record alone. It reads its own archive of such a device
    /// with the other number 0. Records that state the header's numbers are
    /// read.
    DeviceConflict,
    /// A pax `hdrcharset` record names neither of POSIX's two character
    /// sets, `BINARY` and `ISO-IR 10646 2000 UTF-8`.
    ///
    /// bsdtar reports another value as an error and reads on. It then reads a
    /// `path` ending in `/` over a regular file as a regular file. GNU tar,
    /// which ignores the record, reads a directory, as bsdtar does beside
    /// either of POSIX's values.
    UnknownCharset {
        /// The record's value.
        value: Vec<u8>,
    },
    /// A member whose mode has setuid, setgid or sticky has an access control
    /// list, a `SCHILY.acl.access` record. Refused at
    /// [`Level::Strict`](crate::Level::Strict).
    ///
    /// GNU tar, extracting the list, keeps the three bits the mode has.
    /// bsdtar takes the mode from the list and drops all three. A setgid
    /// directory extracts without setgid, and a sticky one, `1777`, as `777`,
    /// where anyone may remove another's files. At
    /// [`Level::Compatible`](crate::Level::Compatible) the member is read
    /// with the header's mode, as GNU tar extracts it. It is the one archive
    /// that level reads where the reference readers extract differently.
    SpecialBitsWithAcl,
    /// A pax `mtime`, `atime` or `ctime` record is before 1970 and has a
    /// fraction of a second.
    ///
    /// bsdtar reads the fraction forward from the second the digits name, so
    /// it reads `-1.5` as half a second before the epoch. GNU tar, Go and
    /// Python read a second and a half: another time, and another whole
    /// second. A time before 1970 in whole seconds is read alike.
    FractionBeforeEpoch {
        /// The record's keyword: [`Keyword::Mtime`], [`Keyword::Atime`] or
        /// [`Keyword::Ctime`].
        keyword: Keyword,
    },
    /// A `SCHILY.xattr.` record's value is empty.
    ///
    /// GNU tar and bsdtar set an empty attribute. Go reads an empty value as
    /// the record's deletion, as POSIX specifies for a pax record. It reports
    /// no attribute, so a Go-based extractor sets none.
    EmptyXattr {
        /// The record's keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// A `LIBARCHIVE.xattr.` record states an extended attribute that the
    /// `SCHILY.xattr.` records do not state alike.
    ///
    /// bsdtar writes each attribute in both kinds of record, and applies
    /// both, in the archive's order. GNU tar and Go apply only the
    /// `SCHILY.xattr.` records. The member is read where each
    /// `LIBARCHIVE.xattr.` record names an attribute a `SCHILY.xattr.` record
    /// also names, spelled alike and with no `%`. The record holds the base64
    /// of that attribute's value, padded or not. Every reader then extracts
    /// the same attributes.
    XattrConflict {
        /// The `LIBARCHIVE.xattr.` record's keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// A global extended header falls between metadata and the member the
    /// metadata describes. Go lets the global header consume the waiting
    /// metadata, which GNU tar, bsdtar and Python apply to the member.
    GlobalBetweenMetadata,
    /// A global extended header holds a record the reader's
    /// [`GlobalHeaders`](crate::GlobalHeaders) mode refuses: with
    /// [`Refuse`](crate::GlobalHeaders::Refuse), the default, any record but
    /// `comment`.
    ///
    /// GNU tar and Python apply a global header's records to every later
    /// member. They differ from each other over a second header, an empty
    /// value, a vendor keyword and `size`. bsdtar and Go apply none. A global
    /// `linkpath`, for one, points every symbolic link elsewhere for GNU tar
    /// and Python. `comment` changes no member: it is the record `git
    /// archive` writes, holding the commit an archive was made from.
    ///
    /// With [`Apply`](crate::GlobalHeaders::Apply), the records it applies
    /// are read, and this kind refuses any other record but `comment`. Such a
    /// record is a `size`, which the two frame members by differently, or a
    /// record not yet measured against both.
    /// [`Defer`](crate::GlobalHeaders::Defer) refuses none.
    GlobalRecord {
        /// The record's keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// With [`GlobalHeaders::Apply`](crate::GlobalHeaders::Apply), a global
    /// extended header follows one whose records apply to members. GNU tar
    /// replaces the earlier header's records with the later one's, and
    /// Python merges the two.
    SecondGlobal,
    /// A header of typeflag `X`, Solaris tar's extended header from before
    /// POSIX settled on `x`. GNU tar, bsdtar and Python apply its records to
    /// the member after it, and Go reads it as a file.
    SolarisExtendedHeader,
    /// A header of typeflag `A`, a Solaris access control list. bsdtar reads
    /// it as metadata for the member after it, and GNU tar, Go and Python as
    /// a member of its own.
    SolarisAcl,
    /// A header of typeflag `M`, GNU's continuation of a file begun in an
    /// earlier volume of a multi-volume archive. GNU tar, reading one volume,
    /// does not extract it. bsdtar and Python extract it as a regular file.
    VolumeContinuation,
    /// A header of typeflag `V`, a GNU volume label, which names the archive
    /// rather than a member. GNU tar and bsdtar extract nothing for it.
    /// Python extracts it as a regular file holding its data, and Go reports
    /// it as a member.
    VolumeLabel,
    /// A header without the POSIX magic, a GNU or a v7 one, has bytes where a
    /// POSIX header keeps its name prefix. GNU tar writes an incremental
    /// archive's access and change times there.
    ///
    /// Python joins those bytes to the member's name, as it would a prefix.
    /// GNU tar, bsdtar and Go never do, and name the member differently.
    PrefixArea,
    /// A header holds an owner name, or, for a character or block device, a
    /// device number other than 0. Its magic and version are neither POSIX's
    /// (`ustar\0`, with any version) nor GNU's (`ustar ` and ` \0`).
    ///
    /// The readers do not agree on which such headers hold those fields.
    /// Python reads the names and device numbers under any magic, and sets
    /// the owner of what it extracts from the names. bsdtar reads them where
    /// the magic begins `ustar`. GNU tar and Go read them only under the two
    /// pairs above, and use the ids. A header with any other magic and
    /// version is read, as a v7 header is, where those fields hold nothing.
    UnknownMagic,
    /// A POSIX header names its member with a prefix that ends in `/`, no
    /// pax record or long name replacing it.
    ///
    /// GNU tar, Go and Python join the prefix to the name with a `/`. They
    /// read prefix `a/` and name `b` as `a//b`, and prefix `/` and name `x` as
    /// `//x`. bsdtar adds no `/` after a prefix that ends in one, and
    /// reads `a/b` and `/x`. A leading `//` is a name POSIX leaves to the
    /// system, and on Windows a network share.
    PrefixSlash,
    /// A POSIX header ends in star's trailer, `tar` and a NUL in its last four
    /// bytes. Its prefix, longer than star's 131 bytes, names its member, no
    /// pax record or long name replacing it.
    ///
    /// Go reads such a header in star's format: its prefix is the first 131
    /// bytes, and the bytes after them are star's access and change times.
    /// GNU tar, bsdtar and Python join the whole prefix to the name, and so
    /// name the member differently.
    StarPrefix,
    /// A member's name, after any long name and pax record, is empty. GNU tar
    /// substitutes `.`, bsdtar skips the member, and Python and Go report the
    /// empty name. For an empty GNU long name, bsdtar and Go take the
    /// header's own name instead.
    EmptyName,
    /// A hard link names no target. GNU tar substitutes `.`, the directory
    /// it extracts into. bsdtar, Go and Python read the empty name.
    HardLinkWithoutTarget,
    /// A regular member whose name ends in a separator, which marks it a
    /// directory, declares data, which no directory has. Taking the name
    /// would read the data as the next header. Taking the size would write a
    /// file at a directory's name.
    DirectoryWithData,
    /// A regular member named as a directory, by a trailing separator, has a
    /// pax record other than those the reader applies, `comment` and
    /// `hdrcharset`.
    ///
    /// bsdtar reads the member as a directory, as GNU tar does, until it
    /// fails to parse one of the member's records (an access control list,
    /// `LIBARCHIVE.creationtime`, `LIBARCHIVE.symlinktype`). After that it
    /// reads a regular file. The records it fails on are open ended, so such
    /// a member may have only the records every reader reads alike.
    DirectoryWithRecord {
        /// The record's keyword, as the archive spells it.
        keyword: Vec<u8>,
    },
    /// A member of a typeflag GNU tar does not know is named with a trailing
    /// `/`.
    ///
    /// bsdtar reads it as a directory, and reads no data after it. GNU tar
    /// and Python extract a regular file, its data the body it declares, GNU
    /// tar naming it without the `/`. Where the member declares a body, the
    /// headers in it are members to bsdtar alone. GNU tar knows the typeflags
    /// NUL, `0` to `7`, `D`, `K`, `L`, `M`, `S`, `V`, `X`, `g` and `x`.
    UnknownTypeSlash {
        /// The member's typeflag.
        typeflag: u8,
    },
    /// A member of a type that has no data declares a size. A hard link is
    /// refused at every level. A symbolic link, a directory, a device or a
    /// FIFO is refused at [`Level::Strict`](crate::Level::Strict).
    ///
    /// Where the header's size field declares it, the reference readers read
    /// no data after any of them. POSIX lets a hard link in a pax archive
    /// have its file's data after it, and so reads the size as data. For the
    /// others the `tar` crate, and `tar-core` 0.1, read the size as data, and
    /// so read the headers after it as that data. At
    /// [`Level::Compatible`](crate::Level::Compatible) the others are read
    /// with no data, unless a pax `size` record declares the size. GNU tar
    /// then reads that much data after the member. bsdtar, Go and Python read
    /// none, so the headers in it are members to them alone.
    SizeWithoutData {
        /// The member's kind.
        kind: EntryKind,
    },
    /// A member that is not a link has a link target from a GNU long link or
    /// a pax `linkpath` record.
    ///
    /// bsdtar extracts such a member, whatever its kind, as a hard link to
    /// that target. It writes the member's data into the target through the
    /// link. GNU tar and Python make the member as its kind and leave the
    /// target as it was. A target in the header's own link name field is
    /// read, every reader passing over it on a member that is not a link.
    TargetWithoutLink {
        /// The member's kind.
        kind: EntryKind,
    },
    /// A member that is not a directory has a default access control list, a
    /// `SCHILY.acl.default` record, empty or not.
    ///
    /// A default list is a directory's, passed on to what is created in it.
    /// The kernel refuses one on any other kind of file, and neither GNU tar
    /// nor bsdtar writes one there. bsdtar, which takes a member's mode from
    /// its lists' text, lists and extracts such a member with mode `000`. GNU
    /// tar, Go and Python read the header's mode.
    DefaultAclWithoutDirectory {
        /// The member's kind.
        kind: EntryKind,
    },
    /// A GNU header that is not a sparse member (typeflag `S`) holds
    /// something in an old GNU sparse header's slots (bytes 386 to 481). For a
    /// member that has data, something in its real size field (483 to 494) is
    /// refused as well.
    ///
    /// bsdtar reads these fields whatever the typeflag. It reads a regular
    /// file's real size field as its size: 2048 bytes where the header
    /// says 512. It reads any slot as a map it fails on. GNU tar, Go and Python read the
    /// header's own fields.
    SparseFields,
    /// A file or a hard link that is not sparse has a `SCHILY.realsize` record
    /// that is not its size in decimal digits.
    ///
    /// bsdtar takes the record as the size of a file, a hard link, or a member
    /// of a typeflag it does not know. It
    /// extracts a file of that length: the data, then zeros to the size, or
    /// the data cut short. A record that is not a number reads to it as zero.
    /// GNU tar, Go and Python ignore the record. Every reader takes a sparse
    /// member's real size from its map. On a directory, a link, a device or a
    /// FIFO, every reader ignores the record, and it is read.
    RealSizeRecord,
    /// A sparse member whose map the reference readers would extract
    /// otherwise than one another, or which the reader would hold beyond its
    /// limits. [`SparseFlaw`] names the rule it breaks.
    Sparse(SparseFlaw),
    /// A metadata member (a GNU long name or long link, a pax extended
    /// header, or a global one) declares more data than
    /// [`Limits::metadata`](crate::Limits::metadata) accepts.
    MetadataLimit {
        /// The size it declares, in bytes.
        size: u64,
        /// The limit, in bytes.
        limit: u64,
    },
    /// With [`GlobalHeaders::Apply`](crate::GlobalHeaders::Apply), a global
    /// `path`, `linkpath`, `uname` or `gname` record holds a value longer than
    /// 4,095 bytes. Each member after the header would hold a copy of it.
    /// Linux's `PATH_MAX` is 4,096 bytes, its terminating NUL included.
    GlobalValueLimit {
        /// The record's keyword.
        keyword: Keyword,
        /// The value's length, in bytes.
        size: u64,
        /// The longest value read, in bytes.
        limit: u64,
    },
    /// The member [`Reader::read_entry`](crate::Reader::read_entry) was asked
    /// to read whole holds more than the limit it was given. Nothing of it has
    /// been read, so the reader can go on to the next member.
    EntryLimit {
        /// What remains of the member's data, in bytes.
        size: u64,
        /// The limit, in bytes.
        limit: u64,
    },
    /// More than the limit [`Reader::finish`](crate::Reader::finish) was
    /// given follows the archive's end.
    TrailingLimit {
        /// The limit, in bytes.
        limit: u64,
    },
    /// Bytes other than zeros follow the archive's end. Refused at
    /// [`Level::Strict`](crate::Level::Strict): by
    /// [`Reader::next_entry`](crate::Reader::next_entry) in the block after
    /// the archive's first zero block, and by
    /// [`Reader::finish`](crate::Reader::finish) in the stream after that.
    ///
    /// The reference readers stop at the end. GNU tar with
    /// `--ignore-zeros` reads on, as does `tar-core` 0.1 past a single zero
    /// block, and both read whatever members follow. Archives joined end to
    /// end with `cat` are refused for it. The offset is that of the first
    /// byte that is not zero.
    TrailingData,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io => f.write_str("reading the archive's source failed"),
            ErrorKind::NotATar => f.write_str("the stream is not a tar archive"),
            ErrorKind::Truncated(truncation) => write!(f, "the archive ends {truncation}"),
            ErrorKind::Checksum => f.write_str("the header checksum does not match"),
            ErrorKind::NotAHeader => f.write_str(
                "the block is not a tar header: it holds no ustar or GNU magic and its \
                 checksum does not match",
            ),
            ErrorKind::HeaderField {
                field,
                problem: Numeric::Unreadable,
            } => write!(
                f,
                "the header's {field} field is neither octal nor base-256"
            ),
            ErrorKind::HeaderField {
                field,
                problem: Numeric::OutOfRange,
            } => write!(
                f,
                "the header's {field} field holds a value out of its range"
            ),
            ErrorKind::PaxFraming(framing) => framing.fmt(f),
            ErrorKind::PaxValue {
                keyword,
                problem: Numeric::Unreadable,
            } => write!(f, "a pax `{keyword}` record is not a decimal number"),
            ErrorKind::PaxValue {
                keyword,
                problem: Numeric::OutOfRange,
            } => write!(f, "a pax `{keyword}` record holds a value out of its range"),
            ErrorKind::EmptyPaxValue { keyword } => write!(f, "a pax `{keyword}` record is empty"),
            ErrorKind::PaxNul { keyword } => {
                write!(f, "a pax `{keyword}` record holds a NUL byte")
            }
            ErrorKind::RepeatedKeyword { keyword } => write!(
                f,
                "an extended header sets `{}` twice, to different values",
                keyword.escape_ascii(),
            ),
            ErrorKind::RepeatedMetadata(metadata) => {
                write!(f, "two {metadata}s describe one member")
            }
            ErrorKind::LongNameNul(metadata) => {
                write!(f, "a {metadata} holds a NUL before its last byte")
            }
            ErrorKind::LongNameOverrun(metadata) => write!(
                f,
                "a {metadata} holds no NUL, and readers read on into the padding after it differently",
            ),
            ErrorKind::EmptyMetadata(metadata) => write!(f, "a {metadata} is empty"),
            ErrorKind::MetadataWithoutMagic(metadata) => write!(
                f,
                "a header whose magic and version are not exactly POSIX's or GNU's is a {metadata}",
            ),
            ErrorKind::LongNameConflict { keyword } => write!(
                f,
                "a pax `{keyword}` record and a {} disagree",
                match keyword {
                    Keyword::Linkpath => Metadata::LongLink,
                    _ => Metadata::LongName,
                },
            ),
            ErrorKind::XattrName { keyword } => write!(
                f,
                "readers extract the attribute `{}` names differently",
                keyword.escape_ascii(),
            ),
            ErrorKind::SelinuxConflict => f.write_str(
                "an `RHT.security.selinux` record is in a form the readers apply \
                 differently",
            ),
            ErrorKind::DeviceConflict => f.write_str(
                "a device's `SCHILY.devmajor` or `SCHILY.devminor` record states other \
                 numbers than its header, and readers read the two differently",
            ),
            ErrorKind::UnknownCharset { value } => write!(
                f,
                "a pax `hdrcharset` record names `{}`, neither of POSIX's character sets",
                value.escape_ascii(),
            ),
            ErrorKind::SpecialBitsWithAcl => f.write_str(
                "a member with setuid, setgid or sticky has an access control list, \
                 and readers extract it with different modes",
            ),
            ErrorKind::FractionBeforeEpoch { keyword } => write!(
                f,
                "a pax `{keyword}` record is before 1970 and has a fraction of a second",
            ),
            ErrorKind::EmptyXattr { keyword } => write!(
                f,
                "`{}` sets an empty attribute, which readers read as set and as deleted",
                keyword.escape_ascii(),
            ),
            ErrorKind::XattrConflict { keyword } => write!(
                f,
                "`{}` states an attribute no `SCHILY.xattr.` record states alike",
                keyword.escape_ascii(),
            ),
            ErrorKind::GlobalBetweenMetadata => f.write_str(
                "a global extended header separates a member from the metadata describing it",
            ),
            ErrorKind::GlobalRecord { keyword } => write!(
                f,
                "a global extended header sets `{}`, a record other than `comment`",
                keyword.escape_ascii(),
            ),
            ErrorKind::SecondGlobal => {
                f.write_str("a global extended header follows one whose records apply to members")
            }
            ErrorKind::SolarisExtendedHeader => {
                f.write_str("the archive holds a Solaris extended header (typeflag `X`)")
            }
            ErrorKind::SolarisAcl => {
                f.write_str("the archive holds a Solaris access control list (typeflag `A`)")
            }
            ErrorKind::VolumeContinuation => f.write_str(
                "the archive holds the continuation of a file from another volume (typeflag `M`)",
            ),
            ErrorKind::VolumeLabel => {
                f.write_str("the archive holds a GNU volume label (typeflag `V`)")
            }
            ErrorKind::PrefixArea => f.write_str(
                "a header without the POSIX magic has bytes where POSIX keeps a name prefix, \
                 as a GNU incremental archive's headers do",
            ),
            ErrorKind::UnknownMagic => f.write_str(
                "a header whose magic is neither POSIX's nor GNU's holds an owner name or a \
                 device number, which readers read differently",
            ),
            ErrorKind::PrefixSlash => {
                f.write_str("a member's name prefix ends in `/`, which readers join differently")
            }
            ErrorKind::StarPrefix => f.write_str(
                "a header ending in star's trailer has a name prefix longer than star's, \
                 which readers cut differently",
            ),
            ErrorKind::EmptyName => f.write_str("a member has an empty name"),
            ErrorKind::HardLinkWithoutTarget => f.write_str("a hard link names no target"),
            ErrorKind::DirectoryWithData => {
                f.write_str("a member names a directory and declares data")
            }
            ErrorKind::DirectoryWithRecord { keyword } => write!(
                f,
                "a regular member named as a directory has `{}`, after which readers part \
                 over its type",
                keyword.escape_ascii(),
            ),
            ErrorKind::UnknownTypeSlash { typeflag } => write!(
                f,
                "a member of typeflag `{}`, which GNU tar does not know, is named as a directory",
                typeflag.escape_ascii(),
            ),
            ErrorKind::SizeWithoutData { kind } => {
                write!(f, "a {kind}, which has no data, declares a size")
            }
            ErrorKind::TargetWithoutLink { kind } => write!(
                f,
                "a {kind}, which is not a link, has a link target from a long link or a pax record",
            ),
            ErrorKind::DefaultAclWithoutDirectory { kind } => write!(
                f,
                "a {kind}, which is not a directory, has a default access control list",
            ),
            ErrorKind::SparseFields => f.write_str(
                "a GNU header that is not a sparse member holds an old sparse header's fields",
            ),
            ErrorKind::RealSizeRecord => f.write_str(
                "a file that is not sparse has a `SCHILY.realsize` record other than its size",
            ),
            ErrorKind::Sparse(flaw) => write!(f, "a sparse member's map {flaw}"),
            ErrorKind::MetadataLimit { size, limit } => write!(
                f,
                "a metadata member of {size} bytes is more than the {limit} accepted",
            ),
            ErrorKind::GlobalValueLimit {
                keyword,
                size,
                limit,
            } => write!(
                f,
                "a global `{keyword}` record of {size} bytes is more than the {limit} applied to \
                 every member",
            ),
            ErrorKind::EntryLimit { size, limit } => write!(
                f,
                "a member of {size} bytes is more than the {limit} accepted for it",
            ),
            ErrorKind::TrailingLimit { limit } => {
                write!(f, "more than {limit} bytes follow the end of the archive")
            }
            ErrorKind::TrailingData => {
                f.write_str("bytes other than zeros follow the end of the archive")
            }
        }
    }
}

/// The rule a sparse member breaks.
///
/// GNU tar and bsdtar write a sparse member's map in a few shapes, which the
/// reference readers extract alike. They part ways over nearly every other
/// shape. Each kind is one such way, measured.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum SparseFlaw {
    /// Typeflag `S` under a magic and version other than GNU's. GNU tar and
    /// bsdtar read a regular member of its stored data, Python a sparse one,
    /// and Go refuses it.
    ///
    /// Pax sparse records on a header whose magic and version are not
    /// POSIX's are refused too. GNU tar reads other data, and no member after
    /// it, where the others read the file.
    Magic,
    /// Pax sparse records on a member whose typeflag is not `0`. bsdtar fails
    /// on it, and GNU tar extracts a symbolic link or a FIFO with such
    /// records as a regular file.
    NotRegular,
    /// Pax sparse records in a global extended header. bsdtar fails, and Go
    /// reads the next member as a file of its stored data.
    ///
    /// Where global headers are applied
    /// ([`GlobalHeaders::Apply`](crate::GlobalHeaders::Apply)), an old GNU
    /// sparse member after one that sets a field is refused too. Python
    /// applies none of its records to such a member, GNU tar all of them.
    Global,
    /// Sparse records not of exactly one of GNU's forms. Two forms are mixed,
    /// the version is other than 1.0, or a required record is missing. Or a
    /// record is of no form, a record is given twice, or pax records are
    /// beside typeflag `S`. The readers that read such a member read
    /// different files.
    Records,
    /// A number in the map that is not decimal digits, or, in a format 1.0
    /// map, more than 19 of them. Or a slot or real size of an old GNU map
    /// that does not read as a header's numeric field, or is negative.
    Number,
    /// A count (`GNU.sparse.numblocks`, or a format 1.0 map's first number)
    /// that is not the number of regions given, or a format 0.0 offset or
    /// length out of its pair.
    Count,
    /// An old GNU map whose slots are not used from the first, or whose
    /// extension flags are out of place. The flag is set exactly where another
    /// block of used slots follows a full one.
    Extension,
    /// A region that begins before the one before it ends: Go and bsdtar
    /// refuse it, and GNU tar and Python extract different files.
    Order,
    /// A region holding data that begins where the last region holding data
    /// ended: bsdtar fails on it.
    Adjacent,
    /// A map whose last region does not end at the real size. GNU tar
    /// extracts the file only to the end of that region, the others to the
    /// real size. A map of no region ends at zero.
    End,
    /// A map leaving no hole in a file of a real size above zero: bsdtar
    /// fails on it.
    NoHole,
    /// Regions whose lengths do not sum to the data the member stores, or a
    /// member whose data ends inside its format 1.0 map.
    StoredSize,
    /// A real size of 2^60 or more, at which bsdtar fails.
    RealSize,
    /// `GNU.sparse.name` empty, holding a NUL, ending in `/`, or naming the
    /// member otherwise than a `path` record or a GNU long name before it.
    /// Python takes the later of a record and the name, and extracts nothing
    /// for an empty one. It keeps a NUL that GNU tar and bsdtar cut at. bsdtar
    /// alone extracts a directory for one ending in `/`.
    Name,
    /// A pax `size` record on a sparse member, which Python reads as its
    /// data's length.
    SizeRecord,
    /// A map larger than [`Limits::metadata`](crate::Limits::metadata):
    /// its blocks, an old GNU header's and its extension blocks, or a format
    /// 1.0 map's.
    MapLimit,
    /// A pax sparse member at [`Level::Strict`](crate::Level::Strict). Rust's
    /// `tar` reads it as a regular member of its stored data, under its
    /// header's name, and for format 0.0 under the file's own name.
    PaxForm,
}

impl fmt::Display for SparseFlaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SparseFlaw::Magic => "is under a magic other than GNU's",
            SparseFlaw::NotRegular => "is on a member that is not a regular file",
            SparseFlaw::Global => "is in a global extended header",
            SparseFlaw::Records => "is not in exactly one of GNU's forms",
            SparseFlaw::Number => "holds a number in a form the readers read differently",
            SparseFlaw::Count => "gives a count other than its regions",
            SparseFlaw::Extension => "has slots or extension flags out of their order",
            SparseFlaw::Order => "has a region beginning before the one before it ends",
            SparseFlaw::Adjacent => "has a region beginning where the last one with data ended",
            SparseFlaw::End => "does not end at the file's real size",
            SparseFlaw::NoHole => "leaves no hole",
            SparseFlaw::StoredSize => "does not account for the data the member stores",
            SparseFlaw::RealSize => "gives a real size of 2^60 or more",
            SparseFlaw::Name => "names the member otherwise than its path",
            SparseFlaw::SizeRecord => "is beside a pax size record",
            SparseFlaw::MapLimit => "is larger than the metadata limit",
            SparseFlaw::PaxForm => "is in a pax form, which Strict does not read",
        })
    }
}

/// Where an archive that ends early ends.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Truncation {
    /// Inside a header block.
    Header,
    /// Inside a member's data, or the padding after it.
    Data,
    /// After metadata, before the member it describes: at the end of the
    /// stream, or at the archive's end marker.
    Member,
}

impl fmt::Display for Truncation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Truncation::Header => "inside a header block",
            Truncation::Data => "inside a member's data",
            Truncation::Member => "after metadata, before the member it describes",
        })
    }
}

/// A numeric field of a header block.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum HeaderField {
    /// The permission bits.
    Mode,
    /// The owning user's id.
    Uid,
    /// The owning group's id.
    Gid,
    /// The size of the member's data.
    Size,
    /// The modification time.
    Mtime,
    /// A device's major number.
    DevMajor,
    /// A device's minor number.
    DevMinor,
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HeaderField::Mode => "mode",
            HeaderField::Uid => "uid",
            HeaderField::Gid => "gid",
            HeaderField::Size => "size",
            HeaderField::Mtime => "mtime",
            HeaderField::DevMajor => "devmajor",
            HeaderField::DevMinor => "devminor",
        })
    }
}

/// What is wrong with a number a header field or a pax record holds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Numeric {
    /// It is not a number in the field's form: octal digits or base-256 in a
    /// header field, decimal digits in a pax record. Octal digits are ended
    /// by a space or a NUL, and after a space the field holds only spaces up
    /// to its first NUL. GNU tar reads digits followed by a space and more as
    /// the first digits. bsdtar does too, where the header is not the
    /// archive's first. Go and Python cannot read them, and Python ends the
    /// archive at that header.
    ///
    /// A header field of spaces alone does not read either, nor does one
    /// that begins with a NUL and holds anything but NULs after it. GNU tar
    /// reports a field of spaces as malformed and reads it as all bits set,
    /// a mode of `0o7777`, where the others read zero. After a leading NUL,
    /// GNU tar and Go read the digits that follow, and bsdtar and Python
    /// read zero. A field of NULs alone, or of spaces ending in a NUL, is
    /// zero to every reader. A device's numbers are held to this, and
    /// another member's are read as zero, since GNU tar reads them only for
    /// a device.
    Unreadable,
    /// It reads as a value the field cannot hold: a negative mode, id or size,
    /// or one too large for the field's type. A size of 2^60 or more is out
    /// of range too, since bsdtar stops at it where GNU tar, Go and Python
    /// read on.
    OutOfRange,
}

/// How a pax record fails to frame.
///
/// A record is `<length> <keyword>=<value>` and a newline, its decimal length
/// counting the whole record, its own digits included.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PaxFraming {
    /// No space follows the length.
    NoDelimiter,
    /// The length is not decimal digits.
    BadLength,
    /// The length reaches past the header's data, or ends before the
    /// record's keyword.
    LengthOutOfBounds,
    /// The record does not end in a newline.
    NoNewline,
    /// The record holds no `=` between its keyword and its value.
    NoEquals,
    /// The record's keyword holds a NUL. GNU tar and bsdtar end a keyword
    /// there, and Go refuses the archive.
    KeywordNul,
    /// The record's keyword is empty. GNU tar and bsdtar read on past the
    /// record. Python ends the archive at its member, having listed the
    /// members before it, and Go fails there.
    EmptyKeyword,
    /// A space or a tab follows the space after the record's length. GNU tar
    /// passes over them and applies the record by the keyword after them.
    /// bsdtar, Go and Python read the keyword as spelled, one no reader
    /// applies.
    BlankBeforeKeyword,
}

impl fmt::Display for PaxFraming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PaxFraming::NoDelimiter => "a pax record has no space after its length",
            PaxFraming::BadLength => "a pax record's length is not decimal",
            PaxFraming::LengthOutOfBounds => "a pax record's length is out of bounds",
            PaxFraming::NoNewline => "a pax record does not end in a newline",
            PaxFraming::NoEquals => "a pax record has no `=`",
            PaxFraming::KeywordNul => "a pax record's keyword holds a NUL",
            PaxFraming::EmptyKeyword => "a pax record's keyword is empty",
            PaxFraming::BlankBeforeKeyword => "a pax record's keyword begins with a space or a tab",
        })
    }
}

/// A pax keyword the reader applies to the member a record describes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Keyword {
    /// `path`: the member's name.
    Path,
    /// `linkpath`: a link's target.
    Linkpath,
    /// `size`: the size of the member's data.
    Size,
    /// `uid`: the owning user's id.
    Uid,
    /// `gid`: the owning group's id.
    Gid,
    /// `uname`: the owning user's name.
    Uname,
    /// `gname`: the owning group's name.
    Gname,
    /// `mtime`: the modification time.
    Mtime,
    /// `atime`: the access time.
    Atime,
    /// `ctime`: the time of the last change to the member's metadata.
    Ctime,
}

impl Keyword {
    /// The keyword `spelled` names, where it is one the reader applies.
    pub(crate) fn of(spelled: &[u8]) -> Option<Keyword> {
        Some(match spelled {
            b"path" => Keyword::Path,
            b"linkpath" => Keyword::Linkpath,
            b"size" => Keyword::Size,
            b"uid" => Keyword::Uid,
            b"gid" => Keyword::Gid,
            b"uname" => Keyword::Uname,
            b"gname" => Keyword::Gname,
            b"mtime" => Keyword::Mtime,
            b"atime" => Keyword::Atime,
            b"ctime" => Keyword::Ctime,
            _ => return None,
        })
    }
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Keyword::Path => "path",
            Keyword::Linkpath => "linkpath",
            Keyword::Size => "size",
            Keyword::Uid => "uid",
            Keyword::Gid => "gid",
            Keyword::Uname => "uname",
            Keyword::Gname => "gname",
            Keyword::Mtime => "mtime",
            Keyword::Atime => "atime",
            Keyword::Ctime => "ctime",
        })
    }
}

/// A kind of metadata member: a header whose data describes the member after
/// it, or every member after it, rather than being a member itself.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Metadata {
    /// A pax extended header (typeflag `x`).
    PaxHeader,
    /// A GNU long name (typeflag `L`).
    LongName,
    /// A GNU long link (typeflag `K`).
    LongLink,
    /// A pax global extended header (typeflag `g`).
    GlobalHeader,
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Metadata::PaxHeader => "pax extended header",
            Metadata::LongName => "GNU long name",
            Metadata::LongLink => "GNU long link",
            Metadata::GlobalHeader => "global extended header",
        })
    }
}
