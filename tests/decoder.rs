//! The decoder's contract with the driver that moves its bytes: what it asks
//! for, what a report does, and a driver of each kind the reader is not.
//!
//! `harness/tests/decoder.rs` reads every case of the catalog through a
//! decoder, its reads split several ways, against the reader.

#![forbid(unsafe_code)]

mod support;

use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use ferrotape::{Chunk, Decoder, Entry, Error, ErrorKind, Level, Reader, Step, Truncation};
use support::{BLOCK, Header, Tar, pax_records, read_whole};

/// What a step asks for, without the buffer: how much may be read into it,
/// or passed over.
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    Read(usize),
    Skip(u64),
    Entry(Vec<u8>),
    End,
}

fn asked(decoder: &mut Decoder) -> Asked {
    match decoder.step().unwrap() {
        Step::Read(buf) => Asked::Read(buf.len()),
        Step::Skip(count) => Asked::Skip(count),
        Step::Entry(entry) => Asked::Entry(entry.path().to_vec()),
        Step::End => Asked::End,
    }
}

/// Hands `bytes` to a decoder that has asked to read, all of them.
fn fill(decoder: &mut Decoder, bytes: &[u8]) {
    let Step::Read(buf) = decoder.step().unwrap() else {
        panic!("a read asked for");
    };
    buf[..bytes.len()].copy_from_slice(bytes);
    decoder.filled(bytes.len());
}

/// The regions of a sparse member: a hole, a region, a hole, a region.
const REGIONS: [(u64, u64); 2] = [(1000, 100), (2900, 100)];
const REAL: u64 = 3000;

/// An archive of a file, a format 1.0 sparse member of [`REGIONS`], and a
/// file after it; read at [`Level::Compatible`], where the pax forms are.
fn with_sparse() -> Vec<u8> {
    let mut map = format!("{}\n", REGIONS.len());
    for (offset, length) in REGIONS {
        map += &format!("{offset}\n{length}\n");
    }
    let mut body = map.into_bytes();
    body.resize(BLOCK, 0);
    for (index, (_, length)) in REGIONS.iter().enumerate() {
        body.extend(std::iter::repeat_n(b'a' + index as u8, *length as usize));
    }
    let real = REAL.to_string();
    Tar::new()
        .file("first", b"one")
        .pax(
            b'x',
            &pax_records(&[
                (b"GNU.sparse.major", b"1"),
                (b"GNU.sparse.minor", b"0"),
                (b"GNU.sparse.name", b"sparse"),
                (b"GNU.sparse.realsize", real.as_bytes()),
            ]),
        )
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
            &body,
        )
        .file("after", &[b'z'; 700])
        .finish()
}

/// Every member with its data, and how the reading ended: where, and with
/// what refusal, if it was refused.
type Listing = (Vec<(Entry, Vec<u8>)>, Result<(), (ErrorKind, u64)>);

/// Every member of `archive` with its data, as a reader reads them at
/// `level`, then how the reading ended.
fn read(archive: &[u8], level: Level) -> Listing {
    let mut reader = Reader::new(archive).with_level(level);
    let mut members = Vec::new();
    let end = loop {
        match reader.next_entry() {
            Ok(Some(entry)) => {
                let data = match read_whole(reader.data(), entry.size()) {
                    Ok(data) => data,
                    Err(err) => {
                        let err = err.downcast::<Error>().unwrap();
                        break Err((err.kind().clone(), err.offset()));
                    }
                };
                members.push((entry, data));
            }
            Ok(None) => {
                break reader
                    .finish(1 << 20)
                    .map_err(|e| (e.kind().clone(), e.offset()));
            }
            Err(err) => break Err((err.kind().clone(), err.offset())),
        }
    };
    (members, end)
}

#[test]
fn asking_again_before_reporting_asks_for_the_same() {
    let archive = Tar::new().file("a", b"hello").file("b", b"world").finish();
    let mut decoder = Decoder::new();
    assert_eq!(asked(&mut decoder), Asked::Read(BLOCK));
    assert_eq!(asked(&mut decoder), Asked::Read(BLOCK));

    // A part of a block, and the rest asked for, from where it stopped.
    fill(&mut decoder, &archive[..100]);
    assert_eq!(asked(&mut decoder), Asked::Read(BLOCK - 100));
    assert_eq!(asked(&mut decoder), Asked::Read(BLOCK - 100));
    fill(&mut decoder, &archive[100..BLOCK]);
    assert_eq!(asked(&mut decoder), Asked::Entry(b"a".to_vec()));
    assert_eq!(decoder.offset(), BLOCK as u64);

    // Its data unread, the member's data and padding are passed over.
    assert_eq!(asked(&mut decoder), Asked::Skip(BLOCK as u64));
    assert_eq!(asked(&mut decoder), Asked::Skip(BLOCK as u64));
    decoder.skipped(500);
    assert_eq!(asked(&mut decoder), Asked::Skip(12));
    decoder.skipped(12);
    assert_eq!(asked(&mut decoder), Asked::Read(BLOCK));

    // The data asked for again, before any of it is read, is the same.
    fill(&mut decoder, &archive[2 * BLOCK..3 * BLOCK]);
    assert_eq!(asked(&mut decoder), Asked::Entry(b"b".to_vec()));
    assert_eq!(decoder.data().unwrap(), Chunk::Read(5));
    assert_eq!(decoder.data().unwrap(), Chunk::Read(5));
    assert_eq!(decoder.data_remaining(), 5);
    decoder.data_read(2);
    assert_eq!(decoder.data().unwrap(), Chunk::Read(3));
    assert_eq!(decoder.data_remaining(), 3);
}

#[test]
fn a_report_beyond_what_was_asked_counts_as_what_was_asked() {
    let archive = Tar::new().file("a", b"hello").finish();
    let mut decoder = Decoder::new();
    let Step::Read(buf) = decoder.step().unwrap() else {
        panic!("a read asked for");
    };
    buf.copy_from_slice(&archive[..BLOCK]);
    decoder.filled(10_000);
    assert_eq!(decoder.offset(), BLOCK as u64);
    assert_eq!(asked(&mut decoder), Asked::Entry(b"a".to_vec()));

    assert_eq!(decoder.data().unwrap(), Chunk::Read(5));
    decoder.data_read(10_000);
    assert_eq!(decoder.offset(), BLOCK as u64 + 5);
    assert_eq!(decoder.data().unwrap(), Chunk::End);
    assert_eq!(asked(&mut decoder), Asked::Skip(BLOCK as u64 - 5));
    decoder.skipped(u64::MAX);
    assert_eq!(decoder.offset(), 2 * BLOCK as u64);
}

#[test]
fn a_report_with_nothing_to_answer_does_nothing() {
    let archive = Tar::new().file("a", b"hello").finish();
    let mut decoder = Decoder::new();
    // Before anything is asked: no member, no skip.
    decoder.data_read(7);
    decoder.skipped(7);
    assert_eq!(decoder.offset(), 0);
    assert_eq!(decoder.data().unwrap(), Chunk::End);
    assert_eq!(decoder.data_remaining(), 0);

    fill(&mut decoder, &archive[..BLOCK]);
    assert_eq!(asked(&mut decoder), Asked::Entry(b"a".to_vec()));
    // A fill with no read asked for, a skip with none, and data reported
    // without asking what it holds.
    decoder.filled(7);
    decoder.skipped(7);
    decoder.data_read(3);
    assert_eq!(decoder.offset(), BLOCK as u64);
    assert_eq!(decoder.data_remaining(), 5);

    // Once the decoder has moved on, the member's data is over.
    assert_eq!(asked(&mut decoder), Asked::Skip(BLOCK as u64));
    assert_eq!(decoder.data().unwrap(), Chunk::End);
    assert_eq!(decoder.data_remaining(), 0);
}

#[test]
fn a_refusal_is_repeated_by_every_later_call() {
    let mut archive = Tar::new().file("a", b"x").file("b", b"y").finish();
    archive[2 * BLOCK + 148] ^= 1;
    let mut decoder = Decoder::new();
    let mut rest = &archive[..];
    let err = loop {
        match decoder.step() {
            Ok(Step::Read(buf)) => {
                let count = buf.len().min(rest.len());
                buf[..count].copy_from_slice(&rest[..count]);
                rest = &rest[count..];
                decoder.filled(count);
            }
            Ok(Step::Skip(count)) => {
                rest = &rest[count as usize..];
                decoder.skipped(count);
            }
            Ok(Step::Entry(_)) => {}
            Ok(Step::End) => panic!("the archive is refused"),
            Err(err) => break err,
        }
    };
    assert_eq!((err.kind(), err.offset()), (&ErrorKind::Checksum, 1024));
    decoder.filled(BLOCK);
    decoder.finish(1 << 20);
    for later in [decoder.step().unwrap_err(), decoder.data().unwrap_err()] {
        assert_eq!((later.kind(), later.offset()), (&ErrorKind::Checksum, 1024));
    }
}

#[test]
fn the_room_for_metadata_grows_with_what_arrives() {
    // A pax header declaring nearly the default limit, 1 MiB, in a stream
    // that holds a few bytes of it: the room made is 64 KiB past what has
    // arrived, not the size declared.
    let mut header = Header::new("PaxHeader", b'x', 1_000_000);
    header.size = 1_000_000;
    let archive = Tar::new()
        .header(&header)
        .raw(b"12 path=abc\n")
        .unterminated();
    let mut decoder = Decoder::new();
    fill(&mut decoder, &archive[..BLOCK]);
    assert_eq!(asked(&mut decoder), Asked::Read(64 * 1024));
    fill(&mut decoder, &archive[BLOCK..]);
    assert_eq!(asked(&mut decoder), Asked::Read(64 * 1024));
    decoder.filled(0);
    let err = decoder.step().unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (&ErrorKind::Truncated(Truncation::Data), BLOCK as u64 + 12)
    );
}

#[test]
fn the_stream_ending_inside_data_is_refused_where_it_ends() {
    let archive = Tar::new().file("a", &[b'x'; 1000]).finish();
    let cut = &archive[..BLOCK + 600];
    let mut decoder = Decoder::new();
    fill(&mut decoder, &cut[..BLOCK]);
    assert_eq!(asked(&mut decoder), Asked::Entry(b"a".to_vec()));
    assert_eq!(decoder.data().unwrap(), Chunk::Read(1000));
    decoder.data_read(600);
    decoder.data_read(0);
    let err = decoder.data().unwrap_err();
    let want = (&ErrorKind::Truncated(Truncation::Data), cut.len() as u64);
    assert_eq!((err.kind(), err.offset()), want);
    let again = decoder.step().unwrap_err();
    assert_eq!((again.kind(), again.offset()), want);

    let mut reader = Reader::new(cut);
    let entry = reader.next_entry().unwrap().unwrap();
    let err = read_whole(reader.data(), entry.size()).unwrap_err();
    let err = err.downcast::<Error>().unwrap();
    assert_eq!((err.kind(), err.offset()), want);
}

#[test]
fn finish_refuses_at_the_same_offset_however_reads_are_split() {
    // The archive ends just past its first zero block, at 1536; 5000 zeros
    // follow, at Compatible padding, and a limit of 1000 is passed at 2537,
    // just past the first byte over it.
    let archive = Tar::new().file("a", b"x").finish();
    let padded = [&archive[..], &[0; 5000]].concat();
    for most in [1, 7, 511, 512, 513, 4096, usize::MAX] {
        let mut decoder = Decoder::new().with_level(Level::Compatible);
        decoder.finish(1000);
        let mut rest = &padded[..];
        let err = loop {
            match decoder.step() {
                Ok(Step::Read(buf)) => {
                    let count = buf.len().min(rest.len()).min(most);
                    buf[..count].copy_from_slice(&rest[..count]);
                    rest = &rest[count..];
                    decoder.filled(count);
                }
                Ok(Step::Skip(count)) => {
                    let count = (count as usize).min(rest.len()).min(most);
                    rest = &rest[count..];
                    decoder.skipped(count as u64);
                }
                Ok(Step::Entry(_)) => panic!("finishing delivers no member"),
                Ok(Step::End) => panic!("more than the limit follows"),
                Err(err) => break err,
            }
        };
        let want = (&ErrorKind::TrailingLimit { limit: 1000 }, 1536 + 1001);
        assert_eq!((err.kind(), err.offset()), want, "reads of at most {most}");
    }
    let err = Reader::new(&padded[..])
        .with_level(Level::Compatible)
        .finish(1000)
        .unwrap_err();
    assert_eq!(err.offset(), 1536 + 1001);
}

/// A source whose every other read is not ready, and which delivers at most
/// `most` bytes a read: a socket's shape.
struct Slow<'a> {
    rest: &'a [u8],
    most: usize,
    ready: bool,
    pending: usize,
}

impl<'s> Slow<'s> {
    fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> SlowRead<'b, 's> {
        SlowRead { source: self, buf }
    }
}

struct SlowRead<'a, 'b> {
    source: &'a mut Slow<'b>,
    buf: &'a mut [u8],
}

impl Future for SlowRead<'_, '_> {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<usize> {
        let this = &mut *self;
        if !this.source.ready {
            this.source.ready = true;
            this.source.pending += 1;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.source.ready = false;
        let count = this
            .buf
            .len()
            .min(this.source.most)
            .min(this.source.rest.len());
        this.buf[..count].copy_from_slice(&this.source.rest[..count]);
        this.source.rest = &this.source.rest[count..];
        Poll::Ready(count)
    }
}

/// Every member with its data, read through `decoder` from `source`, then
/// how the reading ended.
async fn read_async(decoder: &mut Decoder, source: &mut Slow<'_>) -> Listing {
    let mut members = Vec::new();
    let mut scratch = [0u8; 4096];
    let mut finishing = false;
    loop {
        let step = match decoder.step() {
            Ok(step) => step,
            Err(err) => return (members, Err((err.kind().clone(), err.offset()))),
        };
        match step {
            Step::Read(buf) => {
                let got = source.read(buf).await;
                decoder.filled(got);
            }
            Step::Skip(count) => {
                let want = (count as usize).min(scratch.len());
                let got = source.read(&mut scratch[..want]).await;
                decoder.skipped(got as u64);
            }
            Step::Entry(entry) => {
                let mut data = Vec::new();
                loop {
                    match decoder.data() {
                        Ok(Chunk::Read(count)) => {
                            let want = (count as usize).min(scratch.len());
                            let got = source.read(&mut scratch[..want]).await;
                            data.extend_from_slice(&scratch[..got]);
                            decoder.data_read(got as u64);
                        }
                        Ok(Chunk::Zeros(count)) => {
                            let count = count.min(entry.size().saturating_add(1));
                            data.resize(data.len() + count as usize, 0);
                            decoder.data_read(count);
                        }
                        Ok(Chunk::End) => break,
                        Err(err) => return (members, Err((err.kind().clone(), err.offset()))),
                    }
                    assert!(
                        data.len() as u64 <= entry.size(),
                        "the data runs past the member's size"
                    );
                }
                members.push((entry, data));
            }
            Step::End if finishing => return (members, Ok(())),
            Step::End => {
                decoder.finish(1 << 20);
                finishing = true;
            }
        }
    }
}

/// Runs `future` to completion on a waker that does nothing, polling again
/// whenever it is not ready.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut context) {
            return out;
        }
    }
}

#[test]
fn an_asynchronous_driver_reads_as_the_reader_does() {
    let archive = with_sparse();
    let cut = &archive[..archive.len() - 3 * BLOCK + 200];
    for archive in [&archive[..], cut] {
        let want = read(archive, Level::Compatible);
        for most in [1, 100, 512, 4096] {
            let mut decoder = Decoder::new().with_level(Level::Compatible);
            let mut source = Slow {
                rest: archive,
                most,
                ready: false,
                pending: 0,
            };
            let got = block_on(read_async(&mut decoder, &mut source));
            assert_eq!(got, want, "reads of at most {most}");
            assert!(source.pending > 0);
        }
    }
    // The sparse member's file, its holes included, was read.
    let (members, end) = read(&archive, Level::Compatible);
    assert_eq!(end, Ok(()));
    assert_eq!(members[1].1.len() as u64, REAL);
    assert!(members[1].1[..1000].iter().all(|byte| *byte == 0));
}

#[test]
fn a_decoder_moves_between_threads() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<Decoder>();
}
