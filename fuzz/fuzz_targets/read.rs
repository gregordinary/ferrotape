//! The reader over arbitrary input: reading never panics, and what it
//! reports depends on neither how it is driven nor a setting that ought not
//! to change it.
//!
//! The input is read as an archive at each level in each global-header mode,
//! four ways: from a `Read`, and by seeking, each once reading every member's
//! data and once skipping it. Checked:
//!
//! - the four ways list the same members, data aside, and end alike, a
//!   refusal with the same kind at the same offset;
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

use ferrotape::{Entry, Error, ErrorKind, GlobalHeaders, Level, Reader};
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
        let read = if expand {
            reader.data().read_to_end(&mut data)
        } else {
            reader.stored_data().read_to_end(&mut data)
        };
        match read {
            Ok(_) => {
                let want = if expand { entry.size() } else { stored(&entry) };
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
            assert_eq!(reading, seeking, "{level:?} {mode:?}");
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
