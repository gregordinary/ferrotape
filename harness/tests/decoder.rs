//! The decoder over every case, however its reads are split.
//!
//! Each case's archive is read at each level in each global-header mode by a
//! [`Reader`], and by a [`Decoder`] whose driver hands it the stream in
//! pieces of several shapes: whole, a byte at a time, a block and either side
//! of one, and an irregular sequence. Every way lists the same members, with
//! the same data, and ends alike: the same records after the last member, or
//! the same refusal at the same offset. Data is read as the file, as the
//! stored regions, and not at all.

use std::fs;
use std::io::Read;

use ferrotape::{Chunk, Decoder, Entry, Error, ErrorKind, GlobalHeaders, Level, Reader, Step};
use ferrotape_harness::case::Case;
use ferrotape_harness::{case_files, catalog_dir};

/// The most `finish` reads after the archive: more than any case holds.
const TRAILING: u64 = 1 << 32;

/// The largest sparse file read whole; a larger one's stored data alone is
/// read.
const EXPAND: u64 = 1 << 20;

const LEVELS: [Level; 2] = [Level::Strict, Level::Compatible];
const MODES: [GlobalHeaders; 3] = [
    GlobalHeaders::Refuse,
    GlobalHeaders::Apply,
    GlobalHeaders::Defer,
];

/// The most each read delivers, in turn, cycling.
const SPLITS: [&[usize]; 7] = [
    &[usize::MAX],
    &[1],
    &[7],
    &[511],
    &[512],
    &[513],
    &[3, 1, 4096, 1, 5, 9, 2, 6, 5, 35],
];

/// How a member's data is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    /// As [`Reader::data`] delivers it, holes included.
    File,
    /// As [`Reader::stored_data`] delivers it.
    Stored,
    /// Not at all: passed over.
    Skipped,
}

const VIEWS: [View; 3] = [View::File, View::Stored, View::Skipped];

type Refusal = (ErrorKind, u64);

/// A member's data, or the refusal reading it met; `None` where it was not
/// read.
type Data = Option<Result<Vec<u8>, Refusal>>;

/// The records of a global header after the last member.
type Records = Vec<(Vec<u8>, Vec<u8>)>;

/// Every member read one way, with its data or the refusal reading it met,
/// and how the reading ended.
#[derive(Debug, PartialEq, Eq)]
struct Listing {
    members: Vec<(Entry, Data)>,
    end: Result<Records, Refusal>,
}

fn refusal(err: &Error) -> Refusal {
    (err.kind().clone(), err.offset())
}

/// Whether a member's data is read as `view` says, or, for a sparse file
/// past [`EXPAND`], as stored.
fn view_for(entry: &Entry, view: View) -> View {
    match entry.sparse() {
        Some(map) if view == View::File && map.real_size() > EXPAND => View::Stored,
        _ => view,
    }
}

/// How many bytes a member's data holds read as `view`: the file's size, or
/// a sparse file's stored regions.
fn expected_len(entry: &Entry, view: View) -> u64 {
    match (view, entry.sparse()) {
        (View::Stored, Some(map)) => map.stored_size(),
        _ => entry.size(),
    }
}

/// Reads `source` to its end, or one byte past `size`. No member's data
/// runs past its size, so a defect that makes the data endless fails here
/// at once rather than filling memory.
fn read_whole(source: impl Read, size: u64) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    source.take(size.saturating_add(1)).read_to_end(&mut data)?;
    assert!(
        data.len() as u64 <= size,
        "the data runs past the member's size"
    );
    Ok(data)
}

/// `archive` read by a [`Reader`].
fn by_reader(archive: &[u8], level: Level, mode: GlobalHeaders, view: View) -> Listing {
    let mut reader = Reader::new(archive)
        .with_level(level)
        .with_global_headers(mode);
    let mut members = Vec::new();
    let end = loop {
        let entry = match reader.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                break reader
                    .finish(TRAILING)
                    .map(|()| records(reader.trailing_global()))
                    .map_err(|err| refusal(&err));
            }
            Err(err) => break Err(refusal(&err)),
        };
        let view = view_for(&entry, view);
        let size = expected_len(&entry, view);
        let read = match view {
            View::File => read_whole(reader.data(), size),
            View::Stored => read_whole(reader.stored_data(), size),
            View::Skipped => {
                members.push((entry, None));
                continue;
            }
        };
        let read = read.map_err(|err| {
            let carried = err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<Error>())
                .expect("the reader's error, carried");
            refusal(carried)
        });
        let failed = read.is_err();
        members.push((entry, Some(read)));
        if failed {
            break reader
                .next_entry()
                .map(|_| Vec::new())
                .map_err(|err| refusal(&err));
        }
    };
    Listing { members, end }
}

/// A driver handing a decoder the stream in pieces of at most `split`'s
/// sizes, cycling.
struct Driver<'a> {
    rest: &'a [u8],
    split: &'static [usize],
    turn: usize,
}

impl Driver<'_> {
    /// How many bytes the next read delivers, of `want`.
    fn piece(&mut self, want: u64) -> usize {
        let most = self.split[self.turn % self.split.len()];
        self.turn += 1;
        usize::try_from(want)
            .unwrap_or(usize::MAX)
            .min(most)
            .min(self.rest.len())
    }

    fn take(&mut self, count: usize) -> &[u8] {
        let (taken, rest) = self.rest.split_at(count);
        self.rest = rest;
        taken
    }
}

/// `archive` read by a [`Decoder`] driven in pieces of `split`'s sizes.
fn by_decoder(
    archive: &[u8],
    level: Level,
    mode: GlobalHeaders,
    view: View,
    split: &'static [usize],
) -> Listing {
    let mut decoder = Decoder::new().with_level(level).with_global_headers(mode);
    let mut driver = Driver {
        rest: archive,
        split,
        turn: 0,
    };
    let mut members = Vec::new();
    let mut finishing = false;
    let end = loop {
        let step = match decoder.step() {
            Ok(step) => step,
            Err(err) => break Err(refusal(&err)),
        };
        match step {
            Step::Read(buf) => {
                let count = driver.piece(buf.len() as u64);
                buf[..count].copy_from_slice(driver.take(count));
                decoder.filled(count);
            }
            Step::Skip(count) => {
                let count = driver.piece(count);
                driver.take(count);
                decoder.skipped(count as u64);
            }
            Step::Entry(entry) => {
                assert!(!finishing, "a member delivered while finishing");
                let view = view_for(&entry, view);
                if view == View::Skipped {
                    members.push((entry, None));
                    continue;
                }
                let size = expected_len(&entry, view);
                let read = data(&mut decoder, &mut driver, view == View::Stored, size);
                let failed = read.is_err();
                members.push((entry, Some(read)));
                if failed {
                    break decoder
                        .step()
                        .map(|_| Vec::new())
                        .map_err(|err| refusal(&err));
                }
            }
            Step::End if finishing => break Ok(records(decoder.trailing_global())),
            Step::End => {
                decoder.finish(TRAILING);
                finishing = true;
            }
        }
    };
    Listing { members, end }
}

/// The current member's data, read through `decoder`, which must not run
/// past `size` bytes.
fn data(
    decoder: &mut Decoder,
    driver: &mut Driver<'_>,
    stored: bool,
    size: u64,
) -> Result<Vec<u8>, Refusal> {
    let mut out = Vec::new();
    loop {
        assert!(
            out.len() as u64 <= size,
            "the data runs past the member's size"
        );
        let chunk = if stored {
            decoder.stored_data()
        } else {
            decoder.data()
        };
        match chunk.map_err(|err| refusal(&err))? {
            Chunk::Read(count) => {
                let count = driver.piece(count);
                out.extend_from_slice(driver.take(count));
                decoder.data_read(count as u64);
            }
            Chunk::Zeros(count) => {
                let most = driver.split[driver.turn % driver.split.len()];
                driver.turn += 1;
                let count = count.min(size.saturating_add(1));
                let count = usize::try_from(count).unwrap_or(usize::MAX).min(most);
                out.resize(out.len() + count, 0);
                decoder.data_read(count as u64);
            }
            Chunk::End => return Ok(out),
        }
    }
}

fn records(records: &ferrotape::PaxRecords) -> Records {
    records
        .iter()
        .map(|(keyword, value)| (keyword.to_vec(), value.to_vec()))
        .collect()
}

#[test]
fn a_decoder_reads_every_case_as_the_reader_does_however_its_reads_are_split() {
    let mut compared = 0;
    for path in case_files(&catalog_dir()).unwrap() {
        let text = fs::read_to_string(&path).unwrap();
        let case = Case::parse(&text).unwrap();
        let archive = case.archive.build();
        let name = path.strip_prefix(catalog_dir()).unwrap_or(&path).display();
        for level in LEVELS {
            for mode in MODES {
                for view in VIEWS {
                    let want = by_reader(&archive, level, mode, view);
                    for split in SPLITS {
                        let got = by_decoder(&archive, level, mode, view, split);
                        assert_eq!(
                            got, want,
                            "{name} at {level:?}, {mode:?}, {view:?}, split {split:?}"
                        );
                        compared += 1;
                    }
                }
            }
        }
    }
    assert!(compared >= 242 * 6 * 3 * 7, "{compared} readings compared");
}
