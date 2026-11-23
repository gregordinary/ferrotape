//! The reader over arbitrary input: reading never panics, and what it
//! reports depends on neither how it is driven nor a setting that ought not
//! to change it.
//!
//! The input is read as an archive at each level in each global-header mode,
//! five ways: from a `Read`, and by seeking, each once reading every member's
//! data and once skipping it; and by a `Decoder` handed the input in pieces
//! whose sizes the input chooses. Checked:
//!
//! - the five ways list the same members, data aside, and end alike, a
//!   refusal with the same kind at the same offset; the decoder lists the
//!   same data as the reader;
//! - a refusal is final: the next call fails with the same kind and offset;
//! - each member's data is its size, from its data offset, within the input,
//!   and each member's header follows the last one's; a sparse member's
//!   stored data is its regions' lengths, within the input, and its file,
//!   read where it is at most [`EXPAND`] bytes, is zeros outside its regions;
//! - [`Level::Strict`] reads nothing [`Level::Compatible`] reads otherwise:
//!   the members Strict lists are the first Compatible lists, and where
//!   Strict reads the whole archive, Compatible reads the same. Likewise
//!   [`GlobalHeaders::Refuse`] against `Apply` and `Defer`.

#![no_main]
#![forbid(unsafe_code)]

use std::io::{Cursor, Read};

use ferrotape::{Chunk, Decoder, Entry, Error, ErrorKind, GlobalHeaders, Level, Reader, Step};
use libfuzzer_sys::fuzz_target;

/// The most `finish` reads after the archive: more than any input holds.
const TRAILING: u64 = 1 << 32;

/// A block's length.
const BLOCK: u64 = 512;

/// The largest sparse file read whole; a larger one's stored data alone is
/// read, since a map of a few blocks can describe 2^60 - 1 bytes.
const EXPAND: u64 = 1 << 20;

/// The bytes of a member's data the archive stores.
fn stored(entry: &Entry) -> u64 {
    entry.sparse().map_or(entry.size(), |map| map.stored_size())
}

/// A member as one way of reading lists it: its data where that way read it
/// whole.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    entry: Entry,
    data: Option<Vec<u8>>,
}

/// How one way of reading ended: the records of a global header after the
/// last member, or a refusal.
type End = Result<Vec<(Vec<u8>, Vec<u8>)>, (ErrorKind, u64)>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Listing {
    members: Vec<Member>,
    end: End,
}

impl Listing {
    fn without_data(&self) -> Listing {
        Listing {
            members: self
                .members
                .iter()
                .map(|member| Member {
                    entry: member.entry.clone(),
                    data: None,
                })
                .collect(),
            end: self.end.clone(),
        }
    }
}

fn refusal(err: &Error) -> (ErrorKind, u64) {
    (err.kind().clone(), err.offset())
}

/// Every member `reader` yields, reading each one's data where `read_data`
/// says to, then `finish`.
fn list<R: Read>(mut reader: Reader<R>, read_data: bool, input: u64) -> Listing {
    let mut members: Vec<Member> = Vec::new();
    let end = loop {
        let entry = match reader.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                break match reader.finish(TRAILING) {
                    Ok(()) => Ok(reader
                        .trailing_global()
                        .iter()
                        .map(|(keyword, value)| (keyword.to_vec(), value.to_vec()))
                        .collect()),
                    Err(err) => Err(refusal(&err)),
                };
            }
            Err(err) => break Err(refusal(&err)),
        };
        assert_eq!(entry.header_offset() % BLOCK, 0);
        assert_eq!(entry.data_offset() % BLOCK, 0);
        assert!(entry.data_offset() >= entry.header_offset() + BLOCK);
        if let Some(last) = members.last() {
            let past = last.entry.data_offset() + stored(&last.entry).next_multiple_of(BLOCK);
            assert!(entry.header_offset() >= past);
        }
        if !read_data {
            members.push(Member { entry, data: None });
            continue;
        }
        let mut data = Vec::new();
        let expand = entry.sparse().is_none_or(|map| map.real_size() <= EXPAND);
        let want = if expand { entry.size() } else { stored(&entry) };
        // One byte past what the data holds, so data that runs on fails the
        // length check below rather than filling memory.
        let read = if expand {
            reader.data().take(want + 1).read_to_end(&mut data)
        } else {
            reader.stored_data().take(want + 1).read_to_end(&mut data)
        };
        match read {
            Ok(_) => {
                assert_eq!(data.len() as u64, want);
                assert!(entry.data_offset() + stored(&entry) <= input);
                if let Some(map) = entry.sparse().filter(|_| expand) {
                    let mut at = 0;
                    for region in map.regions() {
                        assert!(region.offset() >= at);
                        let hole = &data[at as usize..region.offset() as usize];
                        assert!(hole.iter().all(|byte| *byte == 0));
                        at = region.end();
                    }
                    assert_eq!(at, map.real_size());
                }
                members.push(Member {
                    entry,
                    data: Some(data),
                });
            }
            Err(failure) => {
                members.push(Member { entry, data: None });
                let err = reader
                    .next_entry()
                    .expect_err("a failed read of a member's data is final");
                // The data's failure carries the reader's error.
                let carried = failure
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<Error>())
                    .expect("the reader's error, carried");
                assert_eq!(refusal(carried), refusal(&err));
                break Err(refusal(&err));
            }
        }
    };
    if let Err((kind, offset)) = &end {
        let again = reader.next_entry().expect_err("a refusal is final");
        assert_eq!((again.kind(), again.offset()), (kind, *offset));
    }
    Listing { members, end }
}

/// The sizes a decoder's driver hands it the input in, cycling: chosen by
/// the input, from a byte at a time to more than a block.
fn split(input: &[u8]) -> [usize; 4] {
    let seed = input.iter().fold(0x811c_9dc5_u32, |h, byte| {
        (h ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    });
    let at = |shift: u32, most: u32| ((seed >> shift) % most) as usize + 1;
    [at(0, 13), at(8, 1031), 512, at(16, 4099)]
}

/// Every member `decoder` yields over `input`, handed the input in pieces of
/// `sizes`, each member's data read as [`list`] reads it, then `finish`.
fn decode(input: &[u8], decoder: Decoder, sizes: [usize; 4]) -> Listing {
    let mut decoder = decoder;
    let mut rest = input;
    let mut turn = 0;
    let mut piece = |want: u64, rest: &[u8]| {
        turn += 1;
        usize::try_from(want)
            .unwrap_or(usize::MAX)
            .min(sizes[turn % sizes.len()])
            .min(rest.len())
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
                let count = piece(buf.len() as u64, rest);
                buf[..count].copy_from_slice(&rest[..count]);
                rest = &rest[count..];
                decoder.filled(count);
            }
            Step::Skip(count) => {
                let count = piece(count, rest);
                rest = &rest[count..];
                decoder.skipped(count as u64);
            }
            Step::Entry(entry) => {
                assert!(!finishing, "finishing delivers no member");
                let expand = entry.sparse().is_none_or(|map| map.real_size() <= EXPAND);
                let want = if expand { entry.size() } else { stored(&entry) };
                let mut data = Vec::new();
                let read = loop {
                    assert!(data.len() as u64 <= want, "the data runs past its size");
                    let chunk = if expand {
                        decoder.data()
                    } else {
                        decoder.stored_data()
                    };
                    match chunk {
                        Ok(Chunk::Read(count)) => {
                            let count = piece(count, rest);
                            data.extend_from_slice(&rest[..count]);
                            rest = &rest[count..];
                            decoder.data_read(count as u64);
                        }
                        Ok(Chunk::Zeros(count)) => {
                            let count = piece(count, &[0; 4096]).max(1);
                            data.resize(data.len() + count, 0);
                            decoder.data_read(count as u64);
                        }
                        Ok(Chunk::End) => break Ok(()),
                        Err(err) => break Err(err),
                    }
                };
                match read {
                    Ok(()) => members.push(Member {
                        entry,
                        data: Some(data),
                    }),
                    Err(err) => {
                        members.push(Member { entry, data: None });
                        let again = decoder.step().expect_err("a refusal is final");
                        assert_eq!(refusal(&again), refusal(&err));
                        break Err(refusal(&err));
                    }
                }
            }
            Step::End if finishing => {
                break Ok(decoder
                    .trailing_global()
                    .iter()
                    .map(|(keyword, value)| (keyword.to_vec(), value.to_vec()))
                    .collect());
            }
            Step::End => {
                decoder.finish(TRAILING);
                finishing = true;
            }
        }
    };
    if let Err((kind, offset)) = &end {
        let again = decoder.step().expect_err("a refusal is final");
        assert_eq!((again.kind(), again.offset()), (kind, *offset));
    }
    Listing { members, end }
}

/// `narrow`'s members are `wide`'s first, and where `narrow` reads the whole
/// archive, `wide` reads the same.
fn contained(narrow: &Listing, wide: &Listing, what: &str) {
    assert!(
        wide.members.starts_with(&narrow.members),
        "{what}: {narrow:#?} against {wide:#?}",
    );
    if narrow.end.is_ok() {
        assert_eq!(narrow, wide, "{what}");
    }
}

const LEVELS: [Level; 2] = [Level::Strict, Level::Compatible];
const MODES: [GlobalHeaders; 3] = [
    GlobalHeaders::Refuse,
    GlobalHeaders::Apply,
    GlobalHeaders::Defer,
];

fuzz_target!(|input: &[u8]| {
    let length = input.len() as u64;
    let mut listings = Vec::new();
    for level in LEVELS {
        for mode in MODES {
            let set = |reader: Reader<_>| reader.with_level(level).with_global_headers(mode);
            let reading = list(set(Reader::new(input)), true, length);
            let skipping = list(set(Reader::new(input)), false, length);
            let seeking = list(
                Reader::seeking(Cursor::new(input))
                    .with_level(level)
                    .with_global_headers(mode),
                true,
                length,
            );
            let seeking_skipping = list(
                Reader::seeking(Cursor::new(input))
                    .with_level(level)
                    .with_global_headers(mode),
                false,
                length,
            );
            let decoding = decode(
                input,
                Decoder::new().with_level(level).with_global_headers(mode),
                split(input),
            );
            assert_eq!(reading, seeking, "{level:?} {mode:?}");
            assert_eq!(reading, decoding, "{level:?} {mode:?}, {:?}", split(input));
            assert_eq!(reading.without_data(), skipping, "{level:?} {mode:?}");
            assert_eq!(skipping, seeking_skipping, "{level:?} {mode:?}");
            listings.push(((level, mode), reading));
        }
    }
    let at = |level, mode| {
        &listings
            .iter()
            .find(|(setting, _)| *setting == (level, mode))
            .expect("every setting is read")
            .1
    };
    for mode in MODES {
        contained(
            at(Level::Strict, mode),
            at(Level::Compatible, mode),
            &format!("Strict within Compatible, {mode:?}"),
        );
    }
    for level in LEVELS {
        for mode in [GlobalHeaders::Apply, GlobalHeaders::Defer] {
            contained(
                at(level, GlobalHeaders::Refuse),
                at(level, mode),
                &format!("Refuse within {mode:?}, {level:?}"),
            );
        }
    }
});
