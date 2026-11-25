//! A reader over a source that can seek: it passes over what it does not
//! deliver, and reads what a reader reading through reads.

mod support;

use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;

use ferrotape::{Error, ErrorKind, Reader, Truncation};
use support::{BLOCK, Tar, pax_record};

/// A source that counts the bytes read from it, where its owner can see.
struct Counting<R> {
    inner: R,
    read: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let got = self.inner.read(buf)?;
        self.read.set(self.read.get() + got as u64);
        Ok(got)
    }
}

impl<R: Seek> Seek for Counting<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

/// A member's path, and as much of its data as was read.
type Listed = (Vec<u8>, Vec<u8>);

/// Each member's path and the first `want` bytes of its data, or the first
/// error, read by `reader`.
fn listing<R: Read>(reader: &mut Reader<R>, want: usize) -> Result<Vec<Listed>, Error> {
    let mut members = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        let mut data = vec![0; want.min(entry.size() as usize)];
        reader
            .data()
            .read_exact(&mut data)
            .map_err(|err| err.downcast::<Error>().unwrap())?;
        members.push((entry.path().to_vec(), data));
    }
    Ok(members)
}

fn archive() -> Vec<u8> {
    Tar::new()
        .file("small", b"hello")
        .file("large", &[b'L'; 100_000])
        .pax(b'x', &pax_record(b"path", b"renamed"))
        .file("short", &[b'S'; 3000])
        .file("empty", b"")
        .finish()
}

#[test]
fn a_seeking_reader_reads_what_a_reading_reader_reads() {
    let archive = archive();
    for want in [0, 3, 1 << 20] {
        let read = listing(&mut Reader::new(&archive[..]), want).unwrap();
        let sought = listing(&mut Reader::seeking(Cursor::new(&archive)), want).unwrap();
        assert_eq!(read, sought, "reading {want} bytes of each member");
    }
}

#[test]
fn a_seeking_reader_passes_over_by_seeking() {
    let archive = archive();
    let records = pax_record(b"path", b"renamed").len() as u64;
    // Five headers, the extended header's records, the first byte of the
    // padding after them, and the end marker are read; seeking passes over
    // the members' data, which was not wanted, and the rest of the padding.
    let headers = 5 * BLOCK as u64 + records + 1 + 2 * BLOCK as u64;
    for (seeking, expected) in [(true, headers), (false, archive.len() as u64)] {
        let read = Rc::new(Cell::new(0));
        let source = Counting {
            inner: Cursor::new(&archive),
            read: Rc::clone(&read),
        };
        let mut reader = if seeking {
            Reader::seeking(source)
        } else {
            Reader::new(source)
        };
        assert_eq!(listing(&mut reader, 0).unwrap().len(), 4);
        assert_eq!(read.get(), expected, "seeking: {seeking}");
    }
}

#[test]
fn a_body_the_source_does_not_hold_is_refused_as_reading_refuses_it() {
    // Seeking past a source's end succeeds where reading does not, so each
    // seek is held to the source's length.
    let whole = Tar::new()
        .file("first", &[b'x'; 5000])
        .file("second", b"")
        .finish();
    for cut in [BLOCK + 100, BLOCK + 5000, BLOCK + 5100] {
        let archive = &whole[..cut];
        let read = listing(&mut Reader::new(archive), 0).unwrap_err();
        let sought = listing(&mut Reader::seeking(Cursor::new(archive)), 0).unwrap_err();
        assert_eq!(
            (sought.kind(), sought.offset()),
            (read.kind(), read.offset()),
            "cut at {cut}",
        );
        assert_eq!(sought.kind(), &ErrorKind::Truncated(Truncation::Data));
        assert_eq!(sought.offset(), cut as u64);
    }
}

#[test]
fn offsets_count_from_where_the_source_stands() {
    // An archive inside a larger file, from the offset it begins at.
    let archive = archive();
    let file = [&[b'#'; 700][..], &archive[..]].concat();
    let mut source = Cursor::new(&file);
    source.seek(SeekFrom::Start(700)).unwrap();
    let mut reader = Reader::seeking(source);
    let mut offsets = Vec::new();
    while let Some(entry) = reader.next_entry().unwrap() {
        offsets.push(entry.data_offset());
        let data = &archive[entry.data_offset() as usize..][..entry.size() as usize];
        assert_eq!(reader.read_entry(1 << 20).unwrap(), data);
    }
    assert_eq!(offsets.len(), 4);
}

/// A source that reads but cannot seek, as a pipe opened as a file cannot.
struct Unseekable<'a>(&'a [u8]);

impl Read for Unseekable<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for Unseekable<'_> {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::other("illegal seek"))
    }
}

#[test]
fn a_seek_that_fails_is_the_sources_failure() {
    let archive = archive();
    let mut reader = Reader::seeking(Unseekable(&archive));
    reader.next_entry().unwrap().unwrap();
    let err = reader.next_entry().unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Io);
    assert_eq!(
        std::error::Error::source(&err).unwrap().to_string(),
        "illegal seek"
    );
}
