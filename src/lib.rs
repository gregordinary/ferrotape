//! A tape archive reader and header writer, in safe Rust.
//!
//! ferrotape is in early development, and its API is not yet stable.
//!
//! Its scope is the tar formats in use: POSIX ustar and pax, GNU, and
//! pre-POSIX v7. The reader takes archives from sources its caller does not
//! control. It reads an archive as GNU tar, bsdtar, Go's `archive/tar` and
//! Python's `tarfile` read it, and refuses one they read differently. The
//! writer encodes ustar headers, preceded by pax records for what ustar cannot
//! hold. ferrotape parses and serializes, and never touches a filesystem. It
//! contains no `unsafe` code and has no dependencies.
//!
//! # Reading
//!
//! A [`Reader`] reads an archive from any [`Read`](std::io::Read): a file, a
//! decompressor, another archive's member. [`Reader::next_entry`] yields each
//! member as an [`Entry`], the long names and pax records that describe it
//! already applied, and [`Reader::data`] reads its data:
//!
//! ```no_run
//! use std::io::Read;
//!
//! let file = std::fs::File::open("archive.tar")?;
//! let mut reader = ferrotape::Reader::new(file);
//! while let Some(entry) = reader.next_entry()? {
//!     let mut data = Vec::new();
//!     reader.data().read_to_end(&mut data)?;
//!     println!("{}: {} bytes", entry.path().escape_ascii(), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! A refused archive fails with an [`Error`], whose [`ErrorKind`] names the
//! rule the archive breaks and whose offset says where. Where the reader
//! refuses an archive that some other reader reads, the kind's documentation
//! says what the readers disagree about, and [`differences`] lists every kind
//! of archive on which ferrotape reads otherwise than one of the four. Every
//! allocation an archive can drive has a ceiling: the [`Limits`] set on the
//! reader, and the limit a caller passes to [`Reader::read_entry`] and
//! [`Reader::finish`].
//!
//! # A destination of the caller's
//!
//! What a member becomes is the caller's to decide: a file on disk, an object
//! in a store, an entry in an in-memory filesystem. Here the regular files go
//! into a map, and paths that would leave a directory are refused:
//!
//! ```
//! use std::collections::BTreeMap;
//! use std::error::Error;
//! use std::io::Read;
//!
//! use ferrotape::{EntryKind, Reader};
//!
//! /// The regular files of an archive, by path.
//! fn files(archive: impl Read) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn Error>> {
//!     let mut reader = Reader::new(archive);
//!     let mut files = BTreeMap::new();
//!     while let Some(entry) = reader.next_entry()? {
//!         let path = entry.path().to_vec();
//!         if !beneath(&path) {
//!             return Err(format!("{} leaves the destination", path.escape_ascii()).into());
//!         }
//!         match entry.kind() {
//!             // Each file is held whole, and one larger than 16 MiB is refused.
//!             EntryKind::File => {
//!                 let data = reader.read_entry(16 << 20)?;
//!                 files.insert(path, data);
//!             }
//!             // A hard link names an earlier file, whose data it shares.
//!             EntryKind::HardLink => {
//!                 let target = entry.link_target();
//!                 let Some(data) = files.get(target).cloned() else {
//!                     let (path, target) = (path.escape_ascii(), target.escape_ascii());
//!                     return Err(format!("{path} links to {target}, no earlier file").into());
//!                 };
//!                 files.insert(path, data);
//!             }
//!             // Directories, symbolic links, devices and FIFOs hold no data.
//!             _ => {}
//!         }
//!     }
//!     // The rest of the stream, so that a decoder beneath checks its trailer.
//!     reader.finish(1 << 20)?;
//!     Ok(files)
//! }
//!
//! /// Whether `path` stays beneath the directory it is read into: relative,
//! /// with no `..` component.
//! fn beneath(path: &[u8]) -> bool {
//!     !path.starts_with(b"/") && path.split(|&byte| byte == b'/').all(|part| part != b"..")
//! }
//! # use ferrotape::{Header, Writer};
//! # let mut writer = Writer::new(Vec::new());
//! # writer.append(&Header::directory("docs/"), std::io::empty())?;
//! # writer.append(&Header::file("docs/a.txt", 2), &b"hi"[..])?;
//! # writer.append(&Header::hard_link("docs/b.txt", "docs/a.txt"), std::io::empty())?;
//! # let held = files(&writer.finish()?[..])?;
//! # assert_eq!(held.len(), 2);
//! # assert_eq!(held.get(&b"docs/b.txt"[..]), Some(&b"hi".to_vec()));
//! # let mut writer = Writer::new(Vec::new());
//! # writer.append(&Header::file("docs/../../a.txt", 2), &b"hi"[..])?;
//! # assert!(files(&writer.finish()?[..]).is_err());
//! # let mut writer = Writer::new(Vec::new());
//! # writer.append(&Header::directory("docs/"), std::io::empty())?;
//! # writer.append(&Header::hard_link("docs/b.txt", "docs/"), std::io::empty())?;
//! # let refused = files(&writer.finish()?[..]).expect_err("a link to no earlier file");
//! # assert_eq!(refused.to_string(), "docs/b.txt links to docs/, no earlier file");
//! # let mut writer = Writer::new(Vec::new());
//! # writer.append(&Header::hard_link("b.txt", "a.txt"), std::io::empty())?;
//! # writer.append(&Header::file("a.txt", 2), &b"hi"[..])?;
//! # assert!(files(&writer.finish()?[..]).is_err());
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//!
//! A compressed archive is read through its decoder, from a crate of its own,
//! such as `flate2`'s `GzDecoder` for gzip. [`Reader::finish`] reads on to the
//! end of the stream, so the decoder compares the check that closes it.
//!
//! # Sparse files
//!
//! A sparse member stands for a file with holes, as GNU tar writes one with
//! `--sparse` and bsdtar by default. [`Reader::data`] delivers that file,
//! the holes as zeros, and [`Entry::size`] is its size, which can be far
//! more than the archive holds: up to 2<sup>60</sup> - 1 bytes. A caller that
//! copies data to a file checks the size first, or writes the holes as holes:
//! [`Entry::sparse`] gives the map, and [`Reader::stored_data`] the stored
//! regions alone, each to be placed at its offset.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::{self, Read, Seek, SeekFrom};
//!
//! /// Writes the current member's data to `file`, a new one, a sparse
//! /// member's holes left as holes.
//! fn extract<R: Read>(
//!     reader: &mut ferrotape::Reader<R>,
//!     entry: &ferrotape::Entry,
//!     file: &mut File,
//! ) -> io::Result<()> {
//!     let Some(map) = entry.sparse() else {
//!         io::copy(&mut reader.data(), file)?;
//!         return Ok(());
//!     };
//!     let mut stored = reader.stored_data();
//!     for region in map.regions() {
//!         file.seek(SeekFrom::Start(region.offset()))?;
//!         io::copy(&mut (&mut stored).take(region.length()), file)?;
//!     }
//!     // The file ends at its real size, past any hole after the last region.
//!     file.set_len(map.real_size())
//! }
//! ```
//!
//! A map is read only in the shapes the reference readers extract alike, and
//! at [`Level::Strict`] only in GNU's old form (typeflag `S`): see
//! [`SparseFlaw`].
//!
//! # Settings
//!
//! A [`Level`] says whose readings an archive must agree with to be read.
//! [`Level::Strict`], the default, counts every reader in wide use, the Rust
//! tar crates among them, and suits archives from sources the caller does
//! not control. [`Level::Compatible`] counts the four reference readers and
//! POSIX, and no others, and suits archives a trusted publisher vouches for.
//! It reads one kind of member the four extract differently, as GNU tar
//! extracts it, which its documentation states.
//!
//! [`GlobalHeaders`] says what is done with a global extended header, which
//! one family of readers applies to every later member and the other
//! ignores. The default refuses one holding any record but `comment`. The
//! others apply it as GNU tar and Python do, or apply nothing, as Go does. In
//! every mode its records reach the caller through [`Entry::global`].
//!
//! ```
//! # let archive: &[u8] = &[0; 1024];
//! use ferrotape::{GlobalHeaders, Level, Reader};
//!
//! let mut reader = Reader::new(archive)
//!     .with_level(Level::Compatible)
//!     .with_global_headers(GlobalHeaders::Defer);
//! # assert!(reader.next_entry()?.is_none());
//! # Ok::<(), ferrotape::Error>(())
//! ```
//!
//! A source that can seek, a file, can be read with [`Reader::seeking`],
//! which passes over the data the caller does not read rather than reading
//! it, and [`Entry::data_offset`] says where each member's data lies.
//!
//! # Writing
//!
//! A [`Header`] describes a member to write: one constructor for each kind of
//! member, and a method for each field. [`Header::encode`] writes it as a
//! POSIX ustar header block, preceded by a pax extended header for whatever
//! the block cannot hold exactly. It refuses, with a [`HeaderError`], a header
//! that would not read back as set at [`Level::Compatible`]. A [`Writer`]
//! appends each member's header and data to any [`Write`](std::io::Write), and
//! ends the archive:
//!
//! ```
//! use ferrotape::{Header, Timestamp, Writer};
//!
//! let mut header = Header::file("notes.txt", 5);
//! header
//!     .set_owner(1000, 1000)
//!     .set_mtime(Timestamp::new(1_700_000_000, 250_000_000).expect("a time"));
//! let mut writer = Writer::new(Vec::new());
//! writer.append(&header, &b"hello"[..])?;
//! let archive = writer.finish()?;
//! # assert_eq!(archive.len(), 6 * 512);
//! # Ok::<(), ferrotape::WriteError>(())
//! ```
//!
//! Every header the writer encodes is one the reader reads back as set, at
//! [`Level::Compatible`] and in every global-header mode. At
//! [`Level::Strict`], the reader refuses one kind: a member whose mode has
//! setuid, setgid or sticky beside an access control list
//! ([`ErrorKind::SpecialBitsWithAcl`]). The writer writes such a member as GNU
//! tar does.
//!
//! Paths, link targets and owner names are the archive's bytes. Whether a
//! path is acceptable, an absolute one or one with a `..` component, is the
//! caller's to decide, as is everything about writing members to a
//! filesystem.

// Archives come from sources the caller does not control, so a panic in library
// code is a decision made where the code is written rather than a finding a
// fuzzer reports later. Each lint below names a way to panic, or to compute a
// wrong length silently; a site that genuinely cannot fail and is clearer
// written directly carries `#[expect(..., reason = "...")]` on the smallest
// item that holds it, with the reason stating the invariant. Tests are exempt:
// there a panic is how a check fails.
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::string_slice,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used,
    )
)]
// What the standard library re-exports from `core` and `alloc` is named at its
// source, so the library's use of `std` is confined to I/O and visible where it
// occurs.
#![cfg_attr(
    not(test),
    deny(
        clippy::alloc_instead_of_core,
        clippy::std_instead_of_alloc,
        clippy::std_instead_of_core,
    )
)]

extern crate alloc;

pub mod differences;
mod encode;
mod entry;
mod error;
mod escaped;
mod header;
mod parser;
mod pax;
mod reader;
mod settings;
mod sparse;
mod writer;

pub use encode::{Header, HeaderError, TextField};
pub use entry::{Entry, EntryKind, Timestamp};
pub use error::{
    Error, ErrorKind, HeaderField, Keyword, Metadata, Numeric, PaxFraming, SparseFlaw, Truncation,
};
pub use pax::{AclRecords, PaxRecords, Records, Xattrs};
pub use reader::{Data, Reader};
pub use settings::{GlobalHeaders, Level, Limits};
pub use sparse::{Region, Sparse};
pub use writer::{WriteError, Writer};

// The README's examples are compiled as doctests, so they keep to the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
