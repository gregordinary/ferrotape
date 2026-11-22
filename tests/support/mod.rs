//! The tar writer the tests build their archives with, and the reads they
//! share.
//!
//! The writer is deliberately byte-level: a name, a link target and a size are
//! written as given and never checked, so a test can build what no
//! well-behaved writer emits (a size its data does not match, an unknown
//! typeflag, a header whose checksum is wrong, metadata with no member after
//! it).

#![allow(dead_code, reason = "each test binary uses a part of this module")]

use ferrotape::{Entry, Error, Level, Reader};

/// The size of a block, and of a header.
pub(crate) const BLOCK: usize = 512;

/// The magic and version a header carries, which say which of its fields
/// past byte 257 a reader reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Magic {
    /// POSIX: `ustar\0` and the version `00`.
    Ustar,
    /// GNU: `ustar ` and ` \0`.
    Gnu,
    /// None: a pre-POSIX v7 header, everything past the link name zero.
    V7,
}

/// The fields of one header block, written as given.
#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) name: Vec<u8>,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) size: u64,
    pub(crate) mtime: u64,
    pub(crate) typeflag: u8,
    pub(crate) link: Vec<u8>,
    pub(crate) magic: Magic,
    pub(crate) uname: Vec<u8>,
    pub(crate) gname: Vec<u8>,
    pub(crate) prefix: Vec<u8>,
}

impl Header {
    /// A POSIX header for a member `name` of `typeflag` declaring `size`
    /// bytes: mode 0o644, owned by id 0 and naming no owner, time 0.
    pub(crate) fn new(name: impl AsRef<[u8]>, typeflag: u8, size: u64) -> Header {
        Header {
            name: name.as_ref().to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            mtime: 0,
            typeflag,
            link: Vec::new(),
            magic: Magic::Ustar,
            uname: Vec::new(),
            gname: Vec::new(),
            prefix: Vec::new(),
        }
    }

    /// The header's block, its checksum written.
    pub(crate) fn block(&self) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        put(&mut block[0..100], &self.name);
        octal(&mut block[100..108], u64::from(self.mode));
        octal(&mut block[108..116], u64::from(self.uid));
        octal(&mut block[116..124], u64::from(self.gid));
        octal(&mut block[124..136], self.size);
        octal(&mut block[136..148], self.mtime);
        block[156] = self.typeflag;
        put(&mut block[157..257], &self.link);
        match self.magic {
            Magic::Ustar => block[257..265].copy_from_slice(b"ustar\x0000"),
            Magic::Gnu => block[257..265].copy_from_slice(b"ustar  \0"),
            Magic::V7 => {}
        }
        if self.magic != Magic::V7 {
            put(&mut block[265..297], &self.uname);
            put(&mut block[297..329], &self.gname);
            octal(&mut block[329..337], 0);
            octal(&mut block[337..345], 0);
        }
        if self.magic == Magic::Ustar {
            put(&mut block[345..500], &self.prefix);
        }
        seal(&mut block);
        block
    }
}

/// Copies `value` into the start of `field`, which it must fit.
fn put(field: &mut [u8], value: &[u8]) {
    assert!(value.len() <= field.len(), "a test's value fits its field");
    field[..value.len()].copy_from_slice(value);
}

/// Writes `value` into `field` as zero-padded octal digits and a NUL.
pub(crate) fn octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    assert_eq!(digits.len(), field.len() - 1, "{value} fits the field");
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[digits.len()] = 0;
}

/// Writes `block`'s checksum: the unsigned sum of its bytes, the checksum
/// field read as spaces, as six octal digits, a NUL and a space.
pub(crate) fn seal(block: &mut [u8; BLOCK]) {
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// A pax record, `<length> <keyword>=<value>` and a newline, whose decimal
/// length counts the whole record, its own digits included: a fixed point,
/// reached by iteration.
pub(crate) fn pax_record(keyword: &[u8], value: &[u8]) -> Vec<u8> {
    let content = [b" ", keyword, b"=", value, b"\n"].concat();
    let mut length = content.len();
    while length.to_string().len() + content.len() != length {
        length = length.to_string().len() + content.len();
    }
    [length.to_string().as_bytes(), &content].concat()
}

/// The records `pairs` hold, each written by [`pax_record`].
pub(crate) fn pax_records(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    pairs
        .iter()
        .flat_map(|(keyword, value)| pax_record(keyword, value))
        .collect()
}

/// A tar stream under construction.
///
/// Members are appended through `&mut self`, so a stream is built on a
/// binding or in one chain on a temporary:
/// `Tar::new().file("a", b"x").file("b", b"y").finish()`.
#[derive(Debug, Default)]
pub(crate) struct Tar {
    data: Vec<u8>,
}

impl Tar {
    /// An empty stream.
    pub(crate) fn new() -> Tar {
        Tar::default()
    }

    /// Appends `header`'s block.
    pub(crate) fn header(&mut self, header: &Header) -> &mut Tar {
        self.data.extend_from_slice(&header.block());
        self
    }

    /// Appends `block` as it stands.
    pub(crate) fn block(&mut self, block: &[u8; BLOCK]) -> &mut Tar {
        self.data.extend_from_slice(block);
        self
    }

    /// Appends `data`, padded with zeros to the next block.
    pub(crate) fn body(&mut self, data: &[u8]) -> &mut Tar {
        self.data.extend_from_slice(data);
        self.data.resize(self.data.len().next_multiple_of(BLOCK), 0);
        self
    }

    /// Appends `bytes` as they stand, unpadded.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Tar {
        self.data.extend_from_slice(bytes);
        self
    }

    /// A member: `header`, declaring `data`'s length, then `data`.
    pub(crate) fn entry(&mut self, mut header: Header, data: &[u8]) -> &mut Tar {
        header.size = data.len() as u64;
        self.header(&header).body(data)
    }

    /// A regular file named `name` holding `data`.
    pub(crate) fn file(&mut self, name: impl AsRef<[u8]>, data: &[u8]) -> &mut Tar {
        self.entry(Header::new(name, b'0', 0), data)
    }

    /// A pax header of `typeflag` (`x`, `g`, or another) whose data is
    /// `records`.
    pub(crate) fn pax(&mut self, typeflag: u8, records: &[u8]) -> &mut Tar {
        self.entry(Header::new("PaxHeader", typeflag, 0), records)
    }

    /// A GNU long name (`L`) or long link (`K`) whose data is `value` exactly:
    /// GNU tar's terminating NUL is there only where `value` holds it.
    pub(crate) fn long(&mut self, typeflag: u8, value: &[u8]) -> &mut Tar {
        let mut header = Header::new("././@LongLink", typeflag, 0);
        header.magic = Magic::Gnu;
        self.entry(header, value)
    }

    /// The stream, with the two zero blocks that end an archive.
    pub(crate) fn finish(&self) -> Vec<u8> {
        let mut data = self.unterminated();
        data.resize(data.len() + 2 * BLOCK, 0);
        data
    }

    /// The members alone, without the end marker.
    pub(crate) fn unterminated(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// The first member of `archive`.
pub(crate) fn first(archive: &[u8]) -> Result<Entry, Error> {
    first_at(archive, Level::default())
}

/// The first member of `archive`, read at `level`.
pub(crate) fn first_at(archive: &[u8], level: Level) -> Result<Entry, Error> {
    Ok(Reader::new(archive)
        .with_level(level)
        .next_entry()?
        .expect("the archive holds a member"))
}

/// The path of every member of `archive`, or the first error.
pub(crate) fn paths(archive: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    paths_at(archive, Level::default())
}

/// The path of every member of `archive`, read at `level`, or the first
/// error.
pub(crate) fn paths_at(archive: &[u8], level: Level) -> Result<Vec<Vec<u8>>, Error> {
    let mut reader = Reader::new(archive).with_level(level);
    let mut paths = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        paths.push(entry.path().to_vec());
    }
    Ok(paths)
}

/// An archive whose pax extended header holds `records`, then a member whose
/// own header names it `header-name`.
pub(crate) fn records_archive(records: &[u8]) -> Vec<u8> {
    Tar::new()
        .pax(b'x', records)
        .file("header-name", b"")
        .finish()
}

/// The first member of [`records_archive`].
pub(crate) fn with_records(records: &[u8]) -> Result<Entry, Error> {
    first(&records_archive(records))
}

/// The first member of [`records_archive`], read at `level`.
pub(crate) fn with_records_at(records: &[u8], level: Level) -> Result<Entry, Error> {
    first_at(&records_archive(records), level)
}
