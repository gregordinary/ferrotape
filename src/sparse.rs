//! Sparse members: the map of where a file's data lies, read from GNU's four
//! forms, and the rules a map keeps to be read.
//!
//! A sparse member stores only the parts of a file that hold data, its
//! regions, and a map that places them. The map gives each region's offset in
//! the file and its length, and the file's real size. A part the map does not
//! cover is a hole, read as zeros. GNU tar writes the map in four forms:
//!
//! - In an old GNU header (typeflag `S`) and the extension blocks after it
//! - Format 0.0, in pax records (`GNU.sparse.offset` and
//!   `GNU.sparse.numbytes` in pairs)
//! - Format 0.1, in a pax record (`GNU.sparse.map`)
//! - Format 1.0, at the start of the member's data, after pax records naming
//!   the version
//!
//! bsdtar writes 1.0.
//!
//! The reference readers extract a map alike only in the shapes GNU tar and
//! bsdtar write. They part ways over nearly every other: which region comes
//! first, whether two may touch, where the file ends, what a number may hold.
//! A map is therefore read only in those shapes, and every other is refused
//! ([`SparseFlaw`]). The catalog's `sparse/` cases hold the reference
//! readers' readings each rule rests on, and the tests hold the API to them.

use alloc::vec::Vec;

use crate::error::SparseFlaw;
use crate::header::{self, BLOCK, SIZE_LIMIT};
use crate::pax::PaxRecords;

/// The prefix of the keywords that describe a pax sparse member.
pub(crate) const PREFIX: &[u8] = b"GNU.sparse.";

/// The most decimal digits a number in a format 1.0 map may have. GNU tar
/// fails on one longer, leading zeros included, where the others read it.
const MAP_DIGITS: usize = 19;

/// Where an old GNU sparse header keeps its four slots, its extension flag
/// and the file's real size.
const HEADER_SLOTS: core::ops::Range<usize> = 386..482;
const HEADER_EXTENDED: usize = 482;
const HEADER_REAL_SIZE: core::ops::Range<usize> = 483..495;

/// Where an extension block keeps its 21 slots and its own extension flag.
const EXTENSION_SLOTS: core::ops::Range<usize> = 0..504;
const EXTENSION_EXTENDED: usize = 504;

/// A slot: an offset and a length, each a 12-byte numeric field.
const SLOT: usize = 24;
const FIELD: usize = 12;

/// The map of a sparse member: where its data lies in the file it stands
/// for.
///
/// The member's data, as [`Reader::data`](crate::Reader::data) delivers it,
/// is that file: [`real_size`](Self::real_size) bytes, each region's stored
/// bytes at its offset and zeros everywhere else. Its stored data, as
/// [`Reader::stored_data`](crate::Reader::stored_data) delivers it, is the
/// regions' bytes alone, in order: [`stored_size`](Self::stored_size) bytes.
///
/// A sparse member is the one member whose data can be longer than the
/// archive holding it. A map can describe a file of up to 2^60 - 1 bytes
/// stored in a few blocks. Its size is known before any of it is read
/// ([`Entry::size`](crate::Entry::size)).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Sparse {
    pub(crate) regions: Vec<Region>,
    pub(crate) real_size: u64,
    pub(crate) stored_size: u64,
}

impl Sparse {
    /// The regions, in the order of their offsets: each begins at or after
    /// the end of the one before it. A region can be empty, as the one GNU
    /// tar writes at the real size to end the map.
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// The size of the file the member stands for, in bytes: where the last
    /// region ends.
    #[must_use]
    pub fn real_size(&self) -> u64 {
        self.real_size
    }

    /// The sum of the regions' lengths, in bytes: what the archive stores of
    /// the file.
    #[must_use]
    pub fn stored_size(&self) -> u64 {
        self.stored_size
    }
}

/// A region of a sparse member's file that the archive stores.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Region {
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

impl Region {
    /// Where the region begins in the file, in bytes.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// How many bytes it holds.
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Where it ends in the file: its offset and length, which a map the
    /// reader accepts keeps within the real size.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// A map, its regions as read, held to the rules every reference reader
/// extracts alike.
///
/// `stored_size` is what the member stores of the file: its data, less a
/// format 1.0 map.
pub(crate) fn checked(
    regions: Vec<Region>,
    real_size: u64,
    stored_size: u64,
) -> Result<Sparse, SparseFlaw> {
    // bsdtar stops at 2^60; GNU tar cannot extract past 2^63.
    if real_size >= SIZE_LIMIT {
        return Err(SparseFlaw::RealSize);
    }
    let mut end: u64 = 0;
    let mut data_end: Option<u64> = None;
    let mut total: u64 = 0;
    for region in &regions {
        // Go and bsdtar refuse a region out of order, and GNU tar and Python
        // extract different files.
        if region.offset < end {
            return Err(SparseFlaw::Order);
        }
        // A region past the real size leaves the last ending past it.
        let region_end = region
            .offset
            .checked_add(region.length)
            .ok_or(SparseFlaw::End)?;
        if region.length > 0 {
            // bsdtar fails on a region that begins where the last region with
            // data ended, empty regions between them or not.
            if data_end == Some(region.offset) {
                return Err(SparseFlaw::Adjacent);
            }
            data_end = Some(region_end);
        }
        // Each length is at most the real size, below 2^60, and the regions
        // do not overlap, so the sum stays below it.
        total = total.saturating_add(region.length);
        end = region_end;
    }
    // GNU tar extracts the file only to the end of the last region.
    if end != real_size {
        return Err(SparseFlaw::End);
    }
    // bsdtar fails on a map that leaves no hole.
    if real_size > 0 && total == real_size {
        return Err(SparseFlaw::NoHole);
    }
    if total != stored_size {
        return Err(SparseFlaw::StoredSize);
    }
    Ok(Sparse {
        regions,
        real_size,
        stored_size,
    })
}

/// The map an old GNU sparse header (typeflag `S`) begins: its regions, its
/// real size, and whether an extension block follows.
pub(crate) fn old_header(block: &[u8; BLOCK]) -> Result<(Vec<Region>, u64, bool), SparseFlaw> {
    let real_size = block
        .get(HEADER_REAL_SIZE)
        .ok_or(SparseFlaw::Number)
        .and_then(field_number)?;
    let mut regions = Vec::new();
    let slots = block.get(HEADER_SLOTS).unwrap_or_default();
    let flag = block.get(HEADER_EXTENDED).copied().unwrap_or_default();
    let more = slots_into(slots, flag, &mut regions)?;
    Ok((regions, real_size, more))
}

/// The regions an old GNU extension block adds to `regions`, and whether
/// another follows it.
pub(crate) fn old_extension(
    block: &[u8; BLOCK],
    regions: &mut Vec<Region>,
) -> Result<bool, SparseFlaw> {
    let slots = block.get(EXTENSION_SLOTS).unwrap_or_default();
    let flag = block.get(EXTENSION_EXTENDED).copied().unwrap_or_default();
    let before = regions.len();
    let more = slots_into(slots, flag, regions)?;
    // GNU tar writes an extension block only for slots it fills.
    if regions.len() == before {
        return Err(SparseFlaw::Extension);
    }
    Ok(more)
}

/// Reads the slots of a header or an extension block into `regions`, and
/// says whether the block's extension flag, `flag`, announces another.
///
/// The slots are used from the first: GNU tar stops at the first unused one,
/// where bsdtar, Go and Python read on. An extension follows only where every
/// slot is used.
fn slots_into(slots: &[u8], flag: u8, regions: &mut Vec<Region>) -> Result<bool, SparseFlaw> {
    let more = match flag {
        0 => false,
        1 => true,
        _ => return Err(SparseFlaw::Extension),
    };
    let mut unused = false;
    let (slots, _) = slots.as_chunks::<SLOT>();
    for slot in slots {
        if slot.iter().all(|byte| *byte == 0) {
            unused = true;
            continue;
        }
        if unused {
            return Err(SparseFlaw::Extension);
        }
        let (offset, length) = slot.split_at(FIELD);
        regions.push(Region {
            offset: field_number(offset)?,
            length: field_number(length)?,
        });
    }
    if more && unused {
        return Err(SparseFlaw::Extension);
    }
    Ok(more)
}

/// A numeric field of an old GNU sparse header, as a header's fields are
/// read: octal, or base-256, and not negative.
fn field_number(field: &[u8]) -> Result<u64, SparseFlaw> {
    header::number(field)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SparseFlaw::Number)
}

/// Which pax form a member's sparse records take.
#[derive(Debug)]
pub(crate) enum PaxForm {
    /// Format 0.0 or 0.1: the regions are in the records.
    Records(Vec<Region>),
    /// Format 1.0: the map is at the start of the member's data.
    Data,
}

/// A member's pax sparse records, read.
#[derive(Debug)]
pub(crate) struct PaxSparse {
    pub(crate) form: PaxForm,
    /// `GNU.sparse.name`, the member's path, where given.
    pub(crate) name: Option<Vec<u8>>,
    pub(crate) real_size: u64,
}

/// The sparse records among `records`, read as one of GNU's three pax
/// forms, or `None` where there are none.
///
/// Each form's records, and those alone:
///
/// - 0.0: `size`, `numblocks`, and `offset` and `numbytes` in pairs
/// - 0.1: `size`, `numblocks` and `map`
/// - 1.0: `major` `1`, `minor` `0` and `realsize`
/// - Any form: `name`
///
/// A record of another form, a version other than 1.0, or a required record
/// missing is refused. The readers that read such a member read different
/// files. `name` and `realsize` may be repeated, the last taken, as every
/// reader takes it. Any other record is given once.
pub(crate) fn pax(records: &PaxRecords) -> Result<Option<PaxSparse>, SparseFlaw> {
    let mut seen = Seen::default();
    let mut pairs: Vec<u64> = Vec::new();
    // Whether the next 0.0 record is an offset rather than a length.
    let mut offset_next = true;
    let mut any = false;
    for (keyword, value) in records.iter() {
        let Some(key) = keyword.strip_prefix(PREFIX) else {
            continue;
        };
        any = true;
        match key {
            b"major" => once(&mut seen.major, value)?,
            b"minor" => once(&mut seen.minor, value)?,
            b"size" => once(&mut seen.size, value)?,
            b"numblocks" => once(&mut seen.numblocks, value)?,
            b"map" => once(&mut seen.map, value)?,
            b"name" => seen.name = Some(value),
            b"realsize" => seen.realsize = Some(value),
            b"offset" | b"numbytes" => {
                if (key == b"offset") != offset_next {
                    return Err(SparseFlaw::Count);
                }
                offset_next = !offset_next;
                pairs.push(decimal(value)?);
            }
            _ => return Err(SparseFlaw::Records),
        }
    }
    if !any {
        return Ok(None);
    }
    let name = seen.name.map(<[u8]>::to_vec);
    let form = if seen.major.is_some() || seen.minor.is_some() {
        if seen.major != Some(b"1".as_slice())
            || seen.minor != Some(b"0".as_slice())
            || seen.size.is_some()
            || seen.numblocks.is_some()
            || seen.map.is_some()
            || !pairs.is_empty()
            || !offset_next
        {
            return Err(SparseFlaw::Records);
        }
        let real_size = decimal(seen.realsize.ok_or(SparseFlaw::Records)?)?;
        return Ok(Some(PaxSparse {
            form: PaxForm::Data,
            name,
            real_size,
        }));
    } else if let Some(map) = seen.map {
        if !pairs.is_empty() || !offset_next {
            return Err(SparseFlaw::Records);
        }
        map.split(|byte| *byte == b',')
            .map(decimal)
            .collect::<Result<Vec<u64>, SparseFlaw>>()?
    } else {
        if !offset_next {
            return Err(SparseFlaw::Count);
        }
        pairs
    };
    if seen.realsize.is_some() {
        return Err(SparseFlaw::Records);
    }
    let real_size = decimal(seen.size.ok_or(SparseFlaw::Records)?)?;
    let numblocks = decimal(seen.numblocks.ok_or(SparseFlaw::Records)?)?;
    let regions = regions_of(&form)?;
    if u64::try_from(regions.len()).ok() != Some(numblocks) {
        return Err(SparseFlaw::Count);
    }
    Ok(Some(PaxSparse {
        form: PaxForm::Records(regions),
        name,
        real_size,
    }))
}

/// The sparse records seen, each once.
#[derive(Default)]
struct Seen<'a> {
    major: Option<&'a [u8]>,
    minor: Option<&'a [u8]>,
    size: Option<&'a [u8]>,
    numblocks: Option<&'a [u8]>,
    map: Option<&'a [u8]>,
    name: Option<&'a [u8]>,
    realsize: Option<&'a [u8]>,
}

/// Records `value` in `slot`, refused where it is there already.
fn once<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), SparseFlaw> {
    if slot.replace(value).is_some() {
        return Err(SparseFlaw::Records);
    }
    Ok(())
}

/// Numbers in pairs, offset then length, as regions. Refused where one is
/// left over.
fn regions_of(numbers: &[u64]) -> Result<Vec<Region>, SparseFlaw> {
    let (pairs, rest) = numbers.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(SparseFlaw::Count);
    }
    Ok(pairs
        .iter()
        .map(|&[offset, length]| Region { offset, length })
        .collect())
}

/// A number in a record or a 0.1 map: decimal digits alone, at least one,
/// small enough for a `u64`.
fn decimal(text: &[u8]) -> Result<u64, SparseFlaw> {
    if text.is_empty() {
        return Err(SparseFlaw::Number);
    }
    text.iter().try_fold(0u64, |value, byte| {
        let digit = char::from(*byte).to_digit(10).ok_or(SparseFlaw::Number)?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
            .ok_or(SparseFlaw::Number)
    })
}

/// A format 1.0 map, read a block at a time from the start of the member's
/// data. It is a count, then that many offsets and lengths, each a run of
/// decimal digits ended by a newline. Bytes after the last number in its
/// block are not read, as no reader reads them.
#[derive(Debug, Default)]
pub(crate) struct MapReader {
    count: Option<u64>,
    /// The offset read whose length has not been.
    offset: Option<u64>,
    /// The number being read, and its digits so far.
    number: u64,
    digits: usize,
    regions: Vec<Region>,
    /// The bytes of map read, whole blocks.
    read: u64,
}

impl MapReader {
    /// Reads the next block of the map. `Some` with the regions where the
    /// map ends in it, and the map's length in bytes, whole blocks.
    pub(crate) fn block(&mut self, block: &[u8]) -> Result<Option<(Vec<Region>, u64)>, SparseFlaw> {
        self.read = self.read.saturating_add(BLOCK as u64);
        for byte in block {
            if self.done() {
                break;
            }
            if let Some(digit) = char::from(*byte).to_digit(10) {
                self.digits = self.digits.saturating_add(1);
                if self.digits > MAP_DIGITS {
                    return Err(SparseFlaw::Number);
                }
                // Nineteen digits fit in a `u64`.
                self.number = self
                    .number
                    .saturating_mul(10)
                    .saturating_add(u64::from(digit));
                continue;
            }
            if *byte != b'\n' || self.digits == 0 {
                return Err(SparseFlaw::Number);
            }
            let number = core::mem::take(&mut self.number);
            self.digits = 0;
            match (self.count, self.offset.take()) {
                (None, _) => self.count = Some(number),
                (Some(_), None) => self.offset = Some(number),
                (Some(_), Some(offset)) => self.regions.push(Region {
                    offset,
                    length: number,
                }),
            }
        }
        if self.done() {
            return Ok(Some((core::mem::take(&mut self.regions), self.read)));
        }
        Ok(None)
    }

    /// Whether the count and every pair it promises have been read.
    fn done(&self) -> bool {
        self.count
            .is_some_and(|count| u64::try_from(self.regions.len()).ok() == Some(count))
    }

    /// The bytes of map read so far, whole blocks.
    pub(crate) fn read(&self) -> u64 {
        self.read
    }
}
