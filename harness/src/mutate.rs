//! Mutants of the catalog's archives, for reading with ferrotape and the
//! reference readers.
//!
//! A mutant is a case's archive with one to three of its items changed:
//! a header's numeric fields (its size above all), checksum, magic,
//! typeflag, names or raw bytes; a pax record's key, value or framing; or
//! the items themselves, deleted, repeated, swapped, cut short, or joined by
//! another case's member. Each mutant is derived from a seed and its index
//! alone, so a run's mutants are the same however many threads read them.

use crate::archive::{Archive, BLOCK, Checksum, Header, Item, Magic, Number, frame};

/// A small deterministic generator (SplitMix64), so a mutant reproduces from
/// its seed and index with no dependency.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// The generator for mutant `index` of a run seeded with `seed`.
    pub fn new(seed: u64, index: u64) -> Rng {
        let mut rng = Rng(seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        rng.next_u64();
        rng
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `n`, which is not zero.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// One of `choices`, which is not empty.
    pub fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        &choices[self.below(choices.len())]
    }

    /// True one time in `n`.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}

/// Typeflags a mutation sets: every one some reader gives a meaning, and
/// some none does.
const TYPEFLAGS: &[u8] = b"\x000123456789xgLKVMNSAEIDXZ ";

/// Pax keywords a mutation adds, renames to or changes: each one some reader
/// acts on.
const KEYS: &[&str] = &[
    "path",
    "linkpath",
    "size",
    "uid",
    "gid",
    "uname",
    "gname",
    "mtime",
    "atime",
    "ctime",
    "comment",
    "hdrcharset",
    "charset",
    "GNU.sparse.size",
    "GNU.sparse.name",
    "GNU.sparse.realsize",
    "GNU.sparse.major",
    "GNU.sparse.minor",
    "GNU.sparse.map",
    "GNU.sparse.offset",
    "GNU.sparse.numbytes",
    "SCHILY.xattr.user.k",
    "LIBARCHIVE.xattr.user.k",
    "SCHILY.acl.access",
    "SCHILY.dev",
    "SCHILY.ino",
    "SCHILY.nlink",
    "SCHILY.filetype",
    "SCHILY.fflags",
    "SCHILY.devmajor",
    "SCHILY.devminor",
    "RHT.security.selinux",
    "LIBARCHIVE.creationtime",
];

/// Values a mutation gives a pax record.
const VALUES: &[&[u8]] = &[
    b"",
    b"0",
    b"1",
    b"6",
    b"-1",
    b"007",
    b"+6",
    b" 6",
    b"1024",
    b"1.5",
    b"-1.5",
    b"18446744073709551616",
    b"x",
    b"a",
    b"a/",
    b"../a",
    b"/a",
    b"a\0b",
    b"tail",
    b"smuggled",
    b"0,1,2,3",
    b"user::rw-,group::r--,other::r--",
];

/// Names a mutation gives a header's name or link name.
const NAMES: &[&[u8]] = &[
    b"",
    b"a",
    b"a/",
    b"./a",
    b"../a",
    b"/a",
    b"a\0b",
    b"tail",
    b"smuggled",
    b"d/",
    b"././@LongLink",
    b"PaxHeader",
];

/// Raw bytes a mutation writes into a numeric field.
const RAW_NUMBERS: &[&[u8]] = &[
    b"",
    b" ",
    b"\0",
    b"x",
    b"  0644 ",
    b"0000644 \0",
    b"00000000006 ",
    b" 00000000006",
    b"0000000000+6",
    b"77777777777\0",
    b"\x80\0\0\0\0\0\0\0\0\0\x04\0",
    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
];

/// What a mutation did, for a mutant's statement.
pub type Steps = Vec<String>;

/// The indices of the items that are headers.
fn headers(archive: &Archive) -> Vec<usize> {
    (0..archive.items.len())
        .filter(|&i| matches!(archive.items[i], Item::Header(_)))
        .collect()
}

/// The length of the body that directly follows item `i`, as a header with
/// no size of its own takes it.
fn body_after(archive: &Archive, i: usize) -> u64 {
    match archive.items.get(i + 1) {
        Some(Item::Data(data)) => data.len() as u64,
        Some(Item::Records(records)) => frame(records).len() as u64,
        _ => 0,
    }
}

/// A size near the one a header declares, or one of a few that matter.
fn size(rng: &mut Rng, body: u64) -> Number {
    let blocks = BLOCK as u64;
    let near = [
        0,
        1,
        body.saturating_sub(1),
        body + 1,
        body + blocks,
        body.saturating_sub(blocks),
        2 * blocks,
        0o77_777_777_777,
        1 << 33,
    ];
    match rng.below(10) {
        0 => Number::Base256(*rng.pick(&[0, 6, 1024, -1, i64::MAX])),
        1 => Number::Raw(rng.pick(RAW_NUMBERS).to_vec()),
        _ => Number::Octal(*rng.pick(&near)),
    }
}

/// A numeric field's new value.
fn number(rng: &mut Rng) -> Number {
    match rng.below(4) {
        0 => Number::Raw(rng.pick(RAW_NUMBERS).to_vec()),
        1 => Number::Base256(*rng.pick(&[-1, -86_400, 0, 1 << 40, i64::MIN])),
        _ => Number::Octal(*rng.pick(&[
            0,
            1,
            0o777,
            0o4755,
            0o7777,
            1000,
            65_534,
            0o7_777_777,
            0o77_777_777_777,
        ])),
    }
}

/// Changes one header field.
fn mutate_header(rng: &mut Rng, header: &mut Header, body: u64, steps: &mut Steps) {
    match rng.below(12) {
        0..=2 => {
            let value = size(rng, body);
            steps.push(format!("size {value:?}"));
            header.size = Some(value);
        }
        3 => {
            header.checksum = rng.pick(&[Checksum::Signed, Checksum::Bad]).clone();
            steps.push(format!("checksum {:?}", header.checksum));
        }
        4 => {
            header.magic = *rng.pick(&[Magic::Ustar, Magic::Gnu, Magic::V7]);
            steps.push(format!("magic {:?}", header.magic));
        }
        5 | 6 => {
            header.typeflag = if rng.one_in(8) {
                rng.next_u64() as u8
            } else {
                *rng.pick(TYPEFLAGS)
            };
            steps.push(format!("typeflag {:?}", char::from(header.typeflag)));
        }
        7 => {
            let name = rng.pick(NAMES).to_vec();
            steps.push(format!("name {}", crate::value::render(&name)));
            header.name = name;
        }
        8 => {
            let name = rng.pick(NAMES).to_vec();
            steps.push(format!("linkname {}", crate::value::render(&name)));
            header.linkname = name;
        }
        9 => {
            let prefix = rng.pick(&[&b""[..], b"p", b"p/", b"/", b"a\0b"]).to_vec();
            steps.push(format!("prefix {}", crate::value::render(&prefix)));
            header.prefix = prefix;
        }
        10 => {
            let value = number(rng);
            let field = rng.below(6);
            let (name, slot) = match field {
                0 => ("mode", &mut header.mode),
                1 => ("uid", &mut header.uid),
                2 => ("gid", &mut header.gid),
                3 => ("mtime", &mut header.mtime),
                4 => ("devmajor", &mut header.devmajor),
                _ => ("devminor", &mut header.devminor),
            };
            steps.push(format!("{name} {value:?}"));
            *slot = value;
        }
        _ => {
            let offset = rng.below(BLOCK);
            let length = 1 + rng.below(4.min(BLOCK - offset));
            let bytes: Vec<u8> = (0..length).map(|_| rng.next_u64() as u8).collect();
            steps.push(format!("@{offset} {}", crate::value::quoted(&bytes)));
            header.raw.push((offset, bytes));
        }
    }
}

/// Changes one pax record body: a record removed, repeated, renamed, given
/// another value or added; or one record's length misstated, which turns
/// the body into raw bytes.
fn mutate_records(rng: &mut Rng, archive: &mut Archive, i: usize, steps: &mut Steps) {
    let Some(Item::Records(records)) = archive.items.get_mut(i) else {
        return;
    };
    let at = if records.is_empty() {
        0
    } else {
        rng.below(records.len())
    };
    match rng.below(6) {
        0 if !records.is_empty() => {
            let (key, _) = records.remove(at);
            steps.push(format!("record {} removed", crate::value::render(&key)));
        }
        1 if !records.is_empty() => {
            let mut record = records[at].clone();
            if rng.one_in(2) {
                record.1 = rng.pick(VALUES).to_vec();
            }
            steps.push(format!(
                "record {} repeated as {}",
                crate::value::render(&record.0),
                crate::value::render(&record.1)
            ));
            records.insert(at + 1, record);
        }
        2 if !records.is_empty() => {
            let key = rng.pick(KEYS).as_bytes().to_vec();
            steps.push(format!(
                "record {} renamed {}",
                crate::value::render(&records[at].0),
                crate::value::render(&key)
            ));
            records[at].0 = key;
        }
        3 if !records.is_empty() => {
            let text = rng.pick(VALUES).to_vec();
            steps.push(format!(
                "record {} set to {}",
                crate::value::render(&records[at].0),
                crate::value::render(&text)
            ));
            records[at].1 = text;
        }
        4 if !records.is_empty() => {
            // Each record framed alone, one length changed.
            let mut out = Vec::new();
            for (n, record) in records.iter().enumerate() {
                let mut framed = frame(std::slice::from_ref(record));
                if n == at {
                    let space = framed.iter().position(|&b| b == b' ').unwrap_or(0);
                    let length: i64 = std::str::from_utf8(&framed[..space])
                        .ok()
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0);
                    let wrong = (length + rng.pick(&[-1, 1, -3, 10, 1000])).max(0);
                    steps.push(format!(
                        "record {} framed with length {wrong}",
                        crate::value::render(&record.0)
                    ));
                    let mut again = wrong.to_string().into_bytes();
                    again.extend_from_slice(&framed[space..]);
                    framed = again;
                }
                out.extend_from_slice(&framed);
            }
            let length = out.len() as u64;
            out.resize(out.len().next_multiple_of(BLOCK), 0);
            archive.items[i] = Item::Bytes(out);
            if let Some(Item::Header(header)) =
                i.checked_sub(1).and_then(|h| archive.items.get_mut(h))
                && header.size.is_none()
            {
                header.size = Some(Number::Octal(length));
            }
        }
        _ => {
            let record = (
                rng.pick(KEYS).as_bytes().to_vec(),
                rng.pick(VALUES).to_vec(),
            );
            steps.push(format!(
                "record {}={} added",
                crate::value::render(&record.0),
                crate::value::render(&record.1)
            ));
            records.insert(at, record);
        }
    }
}

/// A member of another archive: a header and the body after it, if any.
fn member_of(rng: &mut Rng, donor: &Archive) -> Vec<Item> {
    let starts = headers(donor);
    if starts.is_empty() {
        return Vec::new();
    }
    let at = *rng.pick(&starts);
    let mut out = vec![donor.items[at].clone()];
    if let Some(next @ (Item::Data(_) | Item::Records(_))) = donor.items.get(at + 1) {
        out.push(next.clone());
    }
    out
}

/// Changes the items themselves.
fn mutate_items(rng: &mut Rng, archive: &mut Archive, donors: &[Archive], steps: &mut Steps) {
    let len = archive.items.len();
    if len == 0 {
        return;
    }
    let at = rng.below(len);
    match rng.below(7) {
        0 => {
            archive.items.remove(at);
            steps.push(format!("item {at} removed"));
        }
        1 => {
            let copy = archive.items[at].clone();
            archive.items.insert(at, copy);
            steps.push(format!("item {at} repeated"));
        }
        2 if at + 1 < len => {
            archive.items.swap(at, at + 1);
            steps.push(format!("items {at} and {} swapped", at + 1));
        }
        3 => {
            archive.items.insert(at, Item::Zeros(1));
            steps.push(format!("a zero block before item {at}"));
        }
        4 if !donors.is_empty() => {
            let donor = &donors[rng.below(donors.len())];
            let member = member_of(rng, donor);
            steps.push(format!("another case's member before item {at}"));
            for (n, item) in member.into_iter().enumerate() {
                archive.items.insert(at + n, item);
            }
        }
        5 => {
            archive.items.truncate(at.max(1));
            steps.push(format!("cut after item {}", at.max(1) - 1));
        }
        _ => {
            let bytes: Vec<u8> = (0..1 + rng.below(BLOCK))
                .map(|_| rng.next_u64() as u8)
                .collect();
            steps.push(format!("{} bytes appended", bytes.len()));
            archive.items.push(Item::Bytes(bytes));
        }
    }
}

/// Mutant `index` of a run seeded with `seed`: an archive of `cases`
/// changed, with the case it came from and what was done to it.
pub fn mutant(seed: u64, index: u64, cases: &[Archive]) -> (usize, Archive, Steps) {
    let mut rng = Rng::new(seed, index);
    let from = rng.below(cases.len());
    let mut archive = cases[from].clone();
    let mut steps = Vec::new();
    for _ in 0..1 + rng.below(3) {
        match rng.below(10) {
            0..=4 => {
                let starts = headers(&archive);
                if starts.is_empty() {
                    continue;
                }
                let at = *rng.pick(&starts);
                let body = body_after(&archive, at);
                if let Some(Item::Header(header)) = archive.items.get_mut(at) {
                    steps.push(format!("header {at}:"));
                    mutate_header(&mut rng, header, body, &mut steps);
                }
            }
            5..=6 => {
                let bodies: Vec<usize> = (0..archive.items.len())
                    .filter(|&i| matches!(archive.items[i], Item::Records(_)))
                    .collect();
                if bodies.is_empty() {
                    continue;
                }
                let at = *rng.pick(&bodies);
                steps.push(format!("records {at}:"));
                mutate_records(&mut rng, &mut archive, at, &mut steps);
            }
            _ => mutate_items(&mut rng, &mut archive, cases, &mut steps),
        }
    }
    (from, archive, steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mutant_is_its_seed_and_index() {
        let cases = vec![
            Archive::parse(&["pax path=p", "header name=a", "data \"x\"", "end"]).unwrap(),
            Archive::parse(&["header name=b typeflag=5", "end"]).unwrap(),
        ];
        for index in 0..200 {
            let one = mutant(7, index, &cases);
            let two = mutant(7, index, &cases);
            assert_eq!(one, two);
        }
        let changed = (0..200)
            .filter(|&i| {
                let (from, archive, _) = mutant(7, i, &cases);
                archive.build() != cases[from].build()
            })
            .count();
        assert!(
            changed > 150,
            "{changed} of 200 mutants changed their archive"
        );
    }
}
