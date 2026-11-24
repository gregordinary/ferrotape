//! The reader: framing members, the metadata that describes them, limits,
//! and how a read fails.

mod support;

use std::io::{self, Read};

use ferrotape::{
    EntryKind, Error, ErrorKind, Keyword, Level, Limits, Metadata, Reader, Truncation,
};
use support::{BLOCK, Header, Magic, Tar, first, first_at, paths, pax_record, read_whole};

const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

/// Everything left of the current member's data, at most `size` bytes,
/// read through `Data`.
fn rest_of_data<R: Read>(reader: &mut Reader<R>, size: u64) -> Vec<u8> {
    read_whole(reader.data(), size).unwrap()
}

#[test]
fn members_are_read_in_order_with_their_data() {
    let archive = Tar::new()
        .file("a", b"hello")
        .file("b", &[b'x'; 1000])
        .finish();
    let mut reader = Reader::new(&archive[..]);
    // Before the first member there is no data to read.
    assert_eq!(rest_of_data(&mut reader, 0), b"");

    let a = reader.next_entry().unwrap().unwrap();
    assert_eq!((a.path(), a.typeflag(), a.size()), (&b"a"[..], b'0', 5));
    assert_eq!(rest_of_data(&mut reader, a.size()), b"hello");
    // The data ends where the member's does.
    assert_eq!(rest_of_data(&mut reader, 0), b"");

    let b = reader.next_entry().unwrap().unwrap();
    assert_eq!(b.path(), b"b");
    // What is not read is skipped.
    let mut part = [0u8; 3];
    reader.data().read_exact(&mut part).unwrap();
    assert!(reader.next_entry().unwrap().is_none());
    assert!(
        reader.next_entry().unwrap().is_none(),
        "the end stays the end"
    );
}

#[test]
fn a_long_name_cut_after_a_separator_is_still_the_file_it_is() {
    // GNU tar fills the member's own name field with the first 100 bytes of
    // the long name, which can end in a separator. Read from that field, the
    // separator would make the file a directory, which carries no data, and
    // its data would be read as the next header.
    let long_name = format!("./{}/deep.hpp", "d".repeat(97));
    assert_eq!(long_name.as_bytes()[99], b'/');
    let body = b"the contents of a file that is not a directory\n";
    let archive = Tar::new()
        .long(b'L', &[long_name.as_bytes(), b"\0"].concat())
        .entry(Header::new(&long_name.as_bytes()[..100], b'0', 0), body)
        .file("after.txt", b"")
        .finish();

    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!(entry.path(), long_name.as_bytes());
    assert_eq!(entry.typeflag(), b'0', "a regular file, not a directory");
    assert_eq!(rest_of_data(&mut reader, entry.size()), body);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"after.txt");
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn a_second_metadata_member_of_one_kind_is_refused() {
    let cases = [
        (
            Tar::new()
                .pax(b'x', &pax_record(b"path", b"first"))
                .pax(b'x', &pax_record(b"mtime", b"100"))
                .unterminated(),
            Metadata::PaxHeader,
        ),
        (
            Tar::new()
                .long(b'L', b"first-long\0")
                .long(b'L', b"second-long\0")
                .unterminated(),
            Metadata::LongName,
        ),
        (
            Tar::new()
                .long(b'K', b"first-target\0")
                .long(b'K', b"second-target\0")
                .unterminated(),
            Metadata::LongLink,
        ),
    ];
    for (metadata, kind) in cases {
        let archive = Tar::new().raw(&metadata).file("plain", b"").finish();
        let err = paths(&archive).unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::RepeatedMetadata(kind));
        assert_eq!(err.offset(), 2 * BLOCK as u64, "the second's own header");
    }
    let err = paths(
        &Tar::new()
            .pax(b'x', &pax_record(b"comment", b"one"))
            .pax(b'x', &pax_record(b"comment", b"two"))
            .file("plain", b"")
            .finish(),
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "two pax extended headers describe one member at offset 1024",
    );
}

#[test]
fn a_pax_name_and_a_long_name_that_differ_are_refused() {
    // GNU tar and bsdtar take the pax record, and Python and Go the long name.
    let renamed = Tar::new()
        .long(b'L', b"gnu-long-name\0")
        .pax(b'x', &pax_record(b"path", b"pax-path"))
        .file("short", b"")
        .finish();
    let retargeted = Tar::new()
        .long(b'K', b"gnu-target\0")
        .pax(b'x', &pax_record(b"linkpath", b"pax-target"))
        .header(&Header::new("link", b'2', 0))
        .finish();
    for (archive, keyword) in [(renamed, Keyword::Path), (retargeted, Keyword::Linkpath)] {
        for level in [Level::Strict, Level::Compatible] {
            let err = first_at(&archive, level).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::LongNameConflict { keyword });
            assert_eq!(err.offset(), 4 * BLOCK as u64, "the member's own header");
        }
    }
    let archive = Tar::new()
        .long(b'L', b"gnu-long-name\0")
        .pax(b'x', &pax_record(b"path", b"pax-path"))
        .file("short", b"")
        .finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a pax `path` record and a GNU long name disagree at offset 2048",
    );

    // Where the two agree, every reader names the member alike: the ordinary
    // shape where a writer emits both.
    let archive = Tar::new()
        .long(b'L', b"same-name\0")
        .pax(b'x', &pax_record(b"path", b"same-name"))
        .file("short", b"")
        .finish();
    for level in [Level::Strict, Level::Compatible] {
        assert_eq!(first_at(&archive, level).unwrap().path(), b"same-name");
    }
}

#[test]
fn metadata_with_no_member_after_it_is_refused_with_or_without_an_end_marker() {
    // One archive ending in one place, spelled with the end marker and by the
    // stream running out, is refused one way.
    for metadata in [
        Tar::new()
            .pax(b'x', &pax_record(b"path", b"renamed"))
            .unterminated(),
        Tar::new().long(b'L', b"name").unterminated(),
        Tar::new().long(b'K', b"target").unterminated(),
    ] {
        for terminated in [false, true] {
            let mut archive = metadata.clone();
            if terminated {
                archive.extend_from_slice(&END);
            }
            let err = paths(&archive).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Member));
            assert_eq!(err.offset(), 2 * BLOCK as u64, "where the archive ends");
        }
    }
}

#[test]
fn a_member_naming_a_directory_and_declaring_data_is_refused() {
    // A name ending in a separator says directory and a size says data. A
    // reader that resolved the contradiction would pick one of two archives:
    // taking the name reads the data as the next header, and taking the size
    // writes a file at a directory's name.
    let archive = Tar::new()
        .entry(Header::new("dir/", b'0', 0), &[b'x'; BLOCK])
        .file("after.txt", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    let err = reader.next_entry().unwrap_err();
    // First in the stream, the refusal keeps its own kind: the stream is a
    // tar archive, if one the reader refuses.
    assert_eq!(err.kind(), &ErrorKind::DirectoryWithData);
    assert_eq!(err.offset(), 0);

    // Declaring nothing, it is the directory it names, as the oldest
    // archives, which predate a reliably set typeflag, mark one. GNU tar and
    // bsdtar extract a contiguous file's typeflag so too.
    for typeflag in *b"07" {
        let entry = first(
            &Tar::new()
                .header(&Header::new("dir/", typeflag, 0))
                .finish(),
        )
        .unwrap();
        assert_eq!(
            (entry.kind(), entry.typeflag()),
            (EntryKind::Directory, typeflag)
        );
        let archive = Tar::new()
            .entry(Header::new("dir/", typeflag, 0), b"x")
            .finish();
        assert_eq!(
            first(&archive).unwrap_err().kind(),
            &ErrorKind::DirectoryWithData
        );
    }
    let mut v7 = Header::new("olddir/", 0, 0);
    v7.magic = Magic::V7;
    let entry = first(&Tar::new().header(&v7).finish()).unwrap();
    assert_eq!((entry.kind(), entry.typeflag()), (EntryKind::Directory, 0));

    // Another type keeps its own kind: a symbolic link named so is a link.
    let entry = first(&Tar::new().header(&Header::new("link/", b'2', 0)).finish()).unwrap();
    assert_eq!(entry.kind(), EntryKind::Symlink);
}

#[test]
fn a_member_with_an_empty_name_is_refused() {
    // GNU tar substitutes `.`, bsdtar skips the member, and Go and Python
    // report the empty name. A header's own name and a long name can each be
    // empty; a pax `path` cannot.
    for archive in [
        Tar::new().file("", b"").file("after", b"").finish(),
        Tar::new()
            .long(b'L', b"\0")
            .file("short", b"")
            .file("after", b"")
            .finish(),
    ] {
        let err = paths(&archive).unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::EmptyName);
    }

    // The root's own member has a name, and is read.
    let archive = Tar::new().header(&Header::new("./", b'5', 0)).finish();
    assert_eq!(paths(&archive).unwrap(), [b"./"]);
}

#[test]
fn a_solaris_extended_header_is_refused() {
    // GNU tar, bsdtar and Python apply an `X` header's records to the member
    // after it and name it `renamed`; Go reads the header as a file and names
    // the member `victim`.
    let archive = Tar::new()
        .pax(b'X', &pax_record(b"path", b"renamed"))
        .file("victim", b"")
        .finish();
    let err = paths(&archive).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::SolarisExtendedHeader);
    assert_eq!(err.offset(), 0);
}

#[test]
fn a_stream_that_is_no_archive_is_told_from_a_damaged_one() {
    // A stream that ends before its first header holds no archive: it is a
    // file of some other format, or an empty one, never a complete archive of
    // nothing. Nor is one shorter than a block, or one whose first block is
    // no header.
    for stream in [
        &b""[..],
        b"not a tar archive at all",
        &[b'X'; BLOCK],
        &[b'X'; 3 * BLOCK],
    ] {
        let err = Reader::new(stream).next_entry().unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::NotATar, "{} bytes", stream.len());
        assert_eq!(err.offset(), 0);
    }

    // The end marker alone, which `tar cf empty.tar --files-from /dev/null`
    // writes, is an archive of nothing.
    let mut reader = Reader::new(&END[..]);
    assert!(reader.next_entry().unwrap().is_none());
    // The archive ends at the first zero block; the second follows it.
    reader.finish(BLOCK as u64).unwrap();
}

#[test]
fn an_archive_missing_only_its_end_marker_still_reads() {
    // GNU tar tolerates a missing end marker at a header boundary, once a
    // header has been read.
    let archive = Tar::new().file("file.txt", b"data").unterminated();
    let mut reader = Reader::new(&archive[..]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"file.txt");
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn a_stream_that_ends_inside_a_header_or_data_is_refused() {
    let one = Tar::new().file("one", b"").unterminated();
    let archive = [&one[..], &[b'x'; 100]].concat();
    let err = paths(&archive).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Header));
    assert_eq!(err.offset(), BLOCK as u64 + 100, "where the stream ends");

    // A member whose data the stream does not hold, skipped by the next read
    // of a header.
    let archive = Tar::new()
        .header(&Header::new("short", b'0', 3000))
        .raw(&[b'x'; 700])
        .unterminated();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    let err = reader.next_entry().unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Data));
    assert_eq!(err.offset(), BLOCK as u64 + 700);
    assert_eq!(
        err.to_string(),
        "the archive ends inside a member's data at offset 1212"
    );

    // So is its padding.
    let archive = Tar::new()
        .header(&Header::new("short", b'0', 100))
        .raw(&[b'x'; 200])
        .unterminated();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    assert_eq!(
        reader.next_entry().unwrap_err().kind(),
        &ErrorKind::Truncated(Truncation::Data),
    );
}

/// An archive of one regular file holding `size` bytes of `x`.
fn one_file(size: usize) -> Vec<u8> {
    Tar::new().file("entry", &vec![b'x'; size]).finish()
}

#[test]
fn a_member_is_read_whole_up_to_its_ceiling_and_refused_past_it() {
    let archive = one_file(3000);

    // At the ceiling exactly, the member is the whole of it, and the reader
    // goes on from where it ends.
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    assert_eq!(reader.read_entry(3000).unwrap(), vec![b'x'; 3000]);
    assert!(reader.next_entry().unwrap().is_none());

    // Past it, the member is refused on its declared size, rather than read
    // as far as the ceiling and returned cut short. Nothing has been read, so
    // the reader goes on to the next member.
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    let err = reader.read_entry(2999).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::EntryLimit {
            size: 3000,
            limit: 2999
        },
    );
    assert_eq!(
        err.to_string(),
        "a member of 3000 bytes is more than the 2999 accepted for it at offset 512",
    );
    assert_eq!(reader.read_entry(3000).unwrap().len(), 3000);
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn a_member_declaring_more_than_the_archive_holds_is_not_returned_short() {
    // The declared size is inside the ceiling, so it is believed until the
    // bytes run out, and then the read fails: what is returned is a whole
    // member or nothing.
    let archive = Tar::new()
        .header(&Header::new("entry", b'0', 1 << 20))
        .raw(&[b'x'; 700])
        .unterminated();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    let err = reader.read_entry(1 << 30).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Data));
}

#[test]
fn a_metadata_member_is_held_to_the_metadata_limit() {
    // Refused on the size it declares, before any of it is read.
    let archive = Tar::new()
        .header(&Header::new("././@LongLink", b'L', (1 << 20) + 1))
        .body(&[0; BLOCK])
        .finish();
    let err = paths(&archive).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::MetadataLimit {
            size: (1 << 20) + 1,
            limit: 1 << 20
        },
    );
    assert_eq!(err.offset(), 0);
    assert_eq!(Limits::default().metadata, 1 << 20);

    // The limit is the caller's to set, lower or higher.
    let name = vec![b'n'; 2 << 20];
    let archive = Tar::new().long(b'L', &name).file("short", b"").finish();
    let mut limits = Limits::default();
    assert!(matches!(
        paths(&archive).unwrap_err().kind(),
        ErrorKind::MetadataLimit { .. }
    ));
    limits.metadata = 4 << 20;
    let mut reader = Reader::new(&archive[..]).with_limits(limits);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), &name[..]);

    // A limit no allocation could follow is read as a sixteenth of the
    // largest allocation the target allows: 2^59 - 1 bytes on a 64-bit
    // target, 128 MiB on a 32-bit one.
    limits.metadata = u64::MAX;
    let mut huge = Header::new("PaxHeader", b'x', 0).block();
    huge[124..136].copy_from_slice(&{
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[4..].copy_from_slice(&(1u64 << 59).to_be_bytes());
        field
    });
    support::seal(&mut huge);
    let err = Reader::new(&huge[..])
        .with_limits(limits)
        .next_entry()
        .unwrap_err();
    let bound = u64::try_from(isize::MAX.unsigned_abs() / 16).unwrap();
    assert_eq!(
        err.kind(),
        &ErrorKind::MetadataLimit {
            size: 1 << 59,
            limit: bound,
        },
    );

    limits.metadata = 10;
    for (records, refused) in [
        (pax_record(b"comment", b"x"), true),
        (b"10 path=x\n".to_vec(), false),
    ] {
        let archive = Tar::new().pax(b'x', &records).file("plain", b"").finish();
        let result = Reader::new(&archive[..]).with_limits(limits).next_entry();
        assert_eq!(result.is_err(), refused, "{} bytes", records.len());
    }
}

/// A source that fails every read with the error `make` returns.
struct Failing(fn() -> io::Error);

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err((self.0)())
    }
}

#[test]
fn a_source_that_fails_is_reported_as_the_sources_failure() {
    // A decompressor beneath the reader refusing its stream: the reason is
    // the decompressor's, kept as the source, and not a guess that the stream
    // is some other format.
    let undecodable =
        || io::Error::new(io::ErrorKind::InvalidData, "the xz stream does not decode");
    let err = Reader::new(Failing(undecodable)).next_entry().unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Io);
    assert_eq!(err.offset(), 0);
    assert_eq!(
        err.to_string(),
        "reading the archive's source failed at offset 0"
    );
    let source = std::error::Error::source(&err).expect("the source's failure");
    assert_eq!(source.to_string(), "the xz stream does not decode");

    // A transport's failure, at the first block or inside a member, which a
    // caller can retry; returned through `io::Error` as it was.
    let reset = || io::Error::from(io::ErrorKind::ConnectionReset);
    let at_start = Reader::new(Failing(reset)).next_entry().unwrap_err();
    let archive = one_file(3000);
    let mut reader = Reader::new((&archive[..1024]).chain(Failing(reset)));
    reader.next_entry().unwrap().unwrap();
    let inside = reader.read_entry(1 << 20).unwrap_err();
    for (err, offset) in [(at_start, 0), (inside, 1024)] {
        assert_eq!((err.kind(), err.offset()), (&ErrorKind::Io, offset));
        assert_eq!(io::Error::from(err).kind(), io::ErrorKind::ConnectionReset);
    }
}

#[test]
fn a_source_s_failure_is_repeated_with_its_kind_and_message() {
    // Every later call repeats the first failure. An `io::Error` cannot be
    // copied, so the source's failure comes back as one of the same kind and
    // message, and through `io::Error` as that kind, not as invalid data.
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "the peer stopped sending");
    let mut reader = Reader::new(Failing(timed_out));
    let first_err = reader.next_entry().unwrap_err();
    for later in [
        reader.next_entry().map(|_| ()).unwrap_err(),
        reader.read_entry(1 << 20).map(|_| ()).unwrap_err(),
        reader.finish(1 << 20).unwrap_err(),
    ] {
        assert_eq!(
            (later.kind(), later.offset()),
            (first_err.kind(), first_err.offset())
        );
        let source = std::error::Error::source(&later).expect("the source's failure");
        assert_eq!(source.to_string(), "the peer stopped sending");
        let err = io::Error::from(later);
        assert_eq!(
            (err.kind(), err.to_string()),
            (
                io::ErrorKind::TimedOut,
                "the peer stopped sending".to_owned()
            )
        );
    }
    let through_data = reader.data().read(&mut [0; 16]).unwrap_err();
    assert_eq!(through_data.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn an_archive_read_from_another_archives_member_reports_where_the_outer_one_fails() {
    // The inner archive's source is the outer archive's member, and the
    // outer archive ends inside it. The inner reader returns the outer
    // reader's error as it was, its offset the outer stream's, rather than as
    // a source of its own that failed.
    let inner = Tar::new()
        .file("a", &[b'a'; 600])
        .file("b", &[b'b'; 600])
        .finish();
    let outer = Tar::new()
        .entry(Header::new("inner.tar", b'0', 0), &inner)
        .finish();
    let cut = BLOCK + BLOCK + 1024 + 100;
    let mut outer = Reader::new(&outer[..cut]);
    outer.next_entry().unwrap().unwrap();
    let mut inner = Reader::new(outer.data());
    assert_eq!(inner.next_entry().unwrap().unwrap().path(), b"a");
    let err = inner.next_entry().unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Data));
    assert_eq!(err.offset(), cut as u64);
    drop(inner);
    // The outer reader refused, and stays refused.
    let again = outer.next_entry().unwrap_err();
    assert_eq!((again.kind(), again.offset()), (err.kind(), err.offset()));
}

#[test]
fn a_read_through_data_fails_with_the_readers_error() {
    let archive = Tar::new()
        .header(&Header::new("short", b'0', 3000))
        .raw(&[b'x'; 700])
        .unterminated();
    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    let err = read_whole(reader.data(), entry.size()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    let err = err.downcast::<Error>().expect("the reader's error");
    assert_eq!(err.kind(), &ErrorKind::Truncated(Truncation::Data));

    // Any other refusal is invalid data.
    let refused = io::Error::from(paths(&Tar::new().file("", b"").finish()).unwrap_err());
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn after_a_refusal_every_later_call_is_refused() {
    // A reader that resumed past a refusal would read on from wherever the
    // stream had reached, and see members no other reader sees.
    let mut damaged = Header::new("second", b'0', 0).block();
    damaged[0] = b'X';
    let archive = Tar::new()
        .file("first", b"")
        .block(&damaged)
        .file("third", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    let err = reader.next_entry().unwrap_err();
    assert_eq!((err.kind(), err.offset()), (&ErrorKind::Checksum, 512));

    for later in [
        reader.next_entry().map(|_| ()).unwrap_err(),
        reader.read_entry(1 << 20).map(|_| ()).unwrap_err(),
        reader.finish(1 << 20).unwrap_err(),
        reader
            .data()
            .read(&mut [0; 16])
            .unwrap_err()
            .downcast::<Error>()
            .unwrap(),
    ] {
        assert_eq!((later.kind(), later.offset()), (&ErrorKind::Checksum, 512));
    }
}

#[test]
fn finish_reads_the_rest_of_the_archive_and_the_stream_after_it() {
    // What follows the end marker is read, up to the limit: the end
    // marker's second block, padding, a decompressor's trailer.
    let archive = Tar::new().file("a", b"x").file("b", b"y").finish();
    let padded = [&archive[..], &[0; 1000]].concat();
    let mut reader = Reader::new(&padded[..]);
    reader.next_entry().unwrap().unwrap();
    reader.finish(BLOCK as u64 + 1000).unwrap();

    let mut reader = Reader::new(&padded[..]);
    let err = reader.finish(BLOCK as u64 + 999).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::TrailingLimit { limit: 1511 });
    assert_eq!(
        err.to_string(),
        format!(
            "more than 1511 bytes follow the end of the archive at offset {}",
            padded.len()
        ),
    );

    // The members left are read as members, and refused as they would be.
    let archive = Tar::new()
        .file("a", b"x")
        .pax(b'X', &pax_record(b"path", b"renamed"))
        .file("b", b"y")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    assert_eq!(
        reader.finish(1 << 20).unwrap_err().kind(),
        &ErrorKind::SolarisExtendedHeader,
    );
}

/// A source that answers every other read with an interruption, and fills
/// at most 100 bytes of a read it answers, as a pipe or a socket can in a
/// process whose signal handlers do not restart the call.
struct Interrupting<R> {
    inner: R,
    interrupt: bool,
}

impl<R: Read> Read for Interrupting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let short = buf.len().min(100);
        self.inner.read(&mut buf[..short])
    }
}

#[test]
fn an_interrupted_read_is_retried_rather_than_reported() {
    // Headers, data read and data skipped: every read the reader makes meets
    // an interruption and a short read.
    let archive = Tar::new()
        .file("first", &[b'x'; 3000])
        .file("second", &[b'y'; 600])
        .finish();
    let trailer = [&archive[..], &[0; 700]].concat();
    let mut reader = Reader::new(Interrupting {
        inner: &trailer[..],
        interrupt: false,
    });
    let member = reader.next_entry().unwrap().unwrap();
    assert_eq!(rest_of_data(&mut reader, member.size()), vec![b'x'; 3000]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"second");
    assert!(reader.next_entry().unwrap().is_none());
    reader.finish(1 << 20).unwrap();
}

#[test]
fn a_member_debugs_as_text() {
    let entry = first(&Tar::new().file("dir/café", b"hello").finish()).unwrap();
    assert_eq!(
        format!("{entry:?}"),
        "Entry { path: \"dir/caf\\xc3\\xa9\", link_target: \"\", kind: File, \
         typeflag: '0', mode: 0o644, uid: 0, gid: 0, uname: \"\", gname: \"\", size: 5, \
         declared_size: 5, mtime: Timestamp { secs: 0, nanos: 0 }, atime: None, ctime: None, \
         device: None, header_offset: 0, data_offset: 512, sparse: None, pax_records: {}, \
         global: {}, .. }",
    );
}

#[test]
fn errors_cross_threads() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<Error>();
    shareable::<ferrotape::Entry>();
}

#[test]
fn a_long_name_or_long_link_read_past_its_size_is_refused() {
    // GNU tar and Python read a long name to its first NUL, past its size and
    // into the padding where its data holds none; bsdtar and Go read as far
    // as its size.
    let mut target = Header::new("short", b'2', 0);
    target.link = b"hdr".to_vec();
    for (typeflag, kind) in [(b'L', Metadata::LongName), (b'K', Metadata::LongLink)] {
        let mut long = Header::new("././@LongLink", typeflag, 1);
        long.magic = Magic::Gnu;
        // The size says `a`, and the block holds `abc` and a NUL.
        let cut_short = Tar::new()
            .header(&long)
            .body(b"abc\0")
            .header(&target)
            .finish();
        // Three bytes and no NUL, the padding beginning with `z`.
        long.size = 3;
        let no_nul = Tar::new()
            .header(&long)
            .raw(b"abcz")
            .raw(&[0; BLOCK - 4])
            .header(&target)
            .finish();
        for archive in [cut_short, no_nul] {
            for level in [Level::Strict, Level::Compatible] {
                let err = first_at(&archive, level).unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::LongNameOverrun(kind), 0)
                );
            }
        }

        // Read alike: a NUL ending the data, whatever the padding holds; no
        // NUL, but padding that begins with one; and no padding at all, the
        // data filling its blocks.
        long.size = 4;
        let ends_in_nul = Tar::new()
            .header(&long)
            .raw(b"abc\0zzz")
            .raw(&[0; BLOCK - 7])
            .header(&target)
            .finish();
        let padded = Tar::new().long(typeflag, b"abc").header(&target).finish();
        let whole = Tar::new()
            .long(typeflag, &[b'a'; BLOCK])
            .header(&target)
            .finish();
        for (archive, name) in [
            (ends_in_nul, &b"abc"[..]),
            (padded, b"abc"),
            (whole, &[b'a'; BLOCK][..]),
        ] {
            for level in [Level::Strict, Level::Compatible] {
                let entry = first_at(&archive, level).unwrap();
                let read = if typeflag == b'L' {
                    entry.path()
                } else {
                    entry.link_target()
                };
                assert_eq!(read, name);
            }
        }
    }
    // A stream that ends inside the padding is cut short, as before.
    let mut long = Header::new("././@LongLink", b'L', 3);
    long.magic = Magic::Gnu;
    let mut archive = Tar::new();
    archive.header(&long).raw(b"abc");
    let err = paths(&archive.unterminated()).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (&ErrorKind::Truncated(Truncation::Data), 515)
    );
    let archive = Tar::new()
        .header(&{
            let mut long = long.clone();
            long.size = 1;
            long
        })
        .body(b"abc\0")
        .file("short", b"")
        .finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a GNU long name holds no NUL, and readers read on into the padding after it \
         differently at offset 0",
    );
}

#[test]
fn an_empty_long_link_is_refused() {
    // GNU tar and Python take it as the link target, GNU tar linking a hard
    // link to `.`; bsdtar and Go take the target the member's header names.
    let mut symlink = Header::new("lnk", b'2', 0);
    symlink.link = b"hdrlink".to_vec();
    let mut hard = Header::new("h", b'1', 0);
    hard.link = b"f".to_vec();
    for value in [&b""[..], b"\0"] {
        for member in [&symlink, &hard, &Header::new("file", b'0', 0)] {
            let archive = Tar::new().long(b'K', value).header(member).finish();
            for level in [Level::Strict, Level::Compatible] {
                let err = first_at(&archive, level).unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::EmptyMetadata(Metadata::LongLink), 0)
                );
            }
        }
    }
    let archive = Tar::new().long(b'K', b"").header(&symlink).finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a GNU long link is empty at offset 0"
    );
    // An empty long name leaves the member no name.
    let archive = Tar::new().long(b'L', b"").file("hdr", b"").finish();
    let err = first(&archive).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (&ErrorKind::EmptyName, 512));
}
