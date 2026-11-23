//! The 512-byte header block: its layout, its checksum, and its numeric
//! fields, read and written. One module holds both directions, so that the
//! layout is stated once.
//!
//! v7 is read as a subset of ustar rather than as a separate format. The first
//! 257 bytes of a header are laid out identically. v7 lacks everything after
//! them: the magic, the version, the owner names, the device numbers and the
//! prefix. A v7 header is read as a ustar one whose fields past byte 257
//! are absent.

use alloc::vec::Vec;
use core::ops::Range;

use crate::error::{HeaderField, Numeric};

/// The size of a block, and of a header.
pub(crate) const BLOCK: usize = 512;

/// The least declared size refused, 2^60 bytes: bsdtar stops at a member
/// declaring this much or more, where GNU tar, Go and Python read on. No
/// member's data comes near it.
pub(crate) const SIZE_LIMIT: u64 = 1 << 60;

// The fields of a header block, as POSIX lays out ustar. Indexing the block
// with these cannot fail: each lies inside 512 bytes.
const NAME: Range<usize> = 0..100;
const MODE: Range<usize> = 100..108;
const UID: Range<usize> = 108..116;
const GID: Range<usize> = 116..124;
const SIZE: Range<usize> = 124..136;
const MTIME: Range<usize> = 136..148;
const CHECKSUM: Range<usize> = 148..156;
const TYPEFLAG: usize = 156;
const LINKNAME: Range<usize> = 157..257;
const MAGIC: Range<usize> = 257..263;
const VERSION: Range<usize> = 263..265;
/// The magic and the version together.
const MAGIC_VERSION: Range<usize> = 257..265;
const UNAME: Range<usize> = 265..297;
const GNAME: Range<usize> = 297..329;
const DEVMAJOR: Range<usize> = 329..337;
const DEVMINOR: Range<usize> = 337..345;
const PREFIX: Range<usize> = 345..500;

/// The header layout a block holds, by its six bytes of magic alone. The
/// version is weighed where it matters (`Fields::exact_magic`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Magic {
    /// `ustar\0`, which POSIX follows with the version `00`: POSIX ustar,
    /// and pax.
    Posix,
    /// `ustar `, which GNU follows with ` \0`: GNU.
    Gnu,
    /// Neither: pre-POSIX v7, whose header ends at byte 257.
    V7,
}

/// What one header block states, before any metadata member before it is
/// applied.
#[derive(Debug)]
pub(crate) struct Fields {
    /// The name, the POSIX prefix joined onto it.
    pub(crate) path: Vec<u8>,
    pub(crate) link_target: Vec<u8>,
    /// The typeflag as the block holds it: a v7 regular file's is NUL.
    pub(crate) typeflag: u8,
    /// The permission bits, setuid, setgid and sticky included.
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// Empty in a v7 header, which has no field for it.
    pub(crate) uname: Vec<u8>,
    /// Empty in a v7 header, which has no field for it.
    pub(crate) gname: Vec<u8>,
    pub(crate) size: u64,
    pub(crate) mtime: i64,
    /// The device numbers, major and minor, where the header has fields for
    /// them: whatever the member's type, as every header with magic does.
    pub(crate) device: Option<(u32, u32)>,
    /// Whether a header without the POSIX magic has bytes where POSIX keeps a
    /// name prefix. Python joins them to its name, and no other reader does.
    pub(crate) stray_prefix: bool,
    /// Whether a POSIX header's prefix ends in `/`, which bsdtar joins to the
    /// name without adding one.
    pub(crate) prefix_slash: bool,
    /// Whether a header holds an owner name, or a device's number other than
    /// 0, where its magic and version are neither POSIX's nor GNU's exactly. The readers read those fields from some such headers and not
    /// from others.
    pub(crate) unknown_magic: bool,
    /// Whether the magic and version are exactly POSIX's, `ustar\0` and
    /// `00`, or GNU's, `ustar ` and ` \0`.
    pub(crate) exact_magic: bool,
}

/// Why a block is not read as a header.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Flaw {
    /// Neither magic nor a checksum that matches: not a header at all.
    NotAHeader,
    /// The magic, and a checksum that does not match: a damaged header.
    Checksum,
    /// A numeric field that does not read as a value it may hold.
    Field(HeaderField, Numeric),
}

/// Reads a header block.
pub(crate) fn parse(block: &[u8; BLOCK]) -> Result<Fields, Flaw> {
    // POSIX writes `ustar\0` and the version `00`; GNU writes `ustar ` and
    // ` \0`. A v7 header has neither, those bytes being part of its unused
    // tail, so the magic decides only whether the fields past byte 257 are
    // there to read.
    let magic = match &block[MAGIC] {
        b"ustar\0" => Magic::Posix,
        b"ustar " => Magic::Gnu,
        _ => Magic::V7,
    };

    // With v7 read, the checksum is the only thing separating a header from
    // arbitrary bytes, which makes the two failures worth telling apart: the
    // magic and a wrong checksum is a damaged header, and neither is very
    // likely no tar archive at all.
    if !checksum_matches(block) {
        return Err(match magic {
            Magic::Posix | Magic::Gnu => Flaw::Checksum,
            Magic::V7 => Flaw::NotAHeader,
        });
    }

    let mut path = text(&block[NAME]).to_vec();
    // The POSIX prefix extends the name. GNU uses those bytes for other
    // fields (an incremental dump's access and change times, a multi-volume
    // member's offset), and v7 has no such field. Python joins them to the
    // name all the same, where the first is not NUL.
    let prefix = text(&block[PREFIX]);
    let stray_prefix = magic != Magic::Posix && !prefix.is_empty();
    let prefix_slash = magic == Magic::Posix && prefix.ends_with(b"/");
    if magic == Magic::Posix && !prefix.is_empty() {
        path = [prefix, b"/", &path].concat();
    }

    // A mode and an id are unsigned. The base-256 form is two's complement
    // and can hold a negative value, which a cast would wrap into a
    // plausible permission set, setuid and setgid included, or an unrelated
    // id, so a negative one is refused. Nothing is lost by refusing: an
    // archive that means mode 0o7777 or uid 4294967295 spells it directly.
    let field = |field: HeaderField| move |problem| Flaw::Field(field, problem);
    let mode = unsigned(&block[MODE]).map_err(field(HeaderField::Mode))?;
    let uid = unsigned(&block[UID]).map_err(field(HeaderField::Uid))?;
    let gid = unsigned(&block[GID]).map_err(field(HeaderField::Gid))?;
    let size = number(&block[SIZE])
        .and_then(|size| u64::try_from(size).map_err(|_| Numeric::OutOfRange))
        .and_then(|size| {
            if size < SIZE_LIMIT {
                Ok(size)
            } else {
                Err(Numeric::OutOfRange)
            }
        })
        .map_err(field(HeaderField::Size))?;
    let mtime = number(&block[MTIME]).map_err(field(HeaderField::Mtime))?;
    let link_target = text(&block[LINKNAME]).to_vec();
    // The device fields are read in every header, whatever its type and its
    // magic: bsdtar, Go and Python refuse a header with magic whose device
    // field does not read, a regular file's included, and Python reads them
    // under any magic, ending the archive at one it cannot read.
    let major = unsigned(&block[DEVMAJOR]).map_err(field(HeaderField::DevMajor))?;
    let minor = unsigned(&block[DEVMINOR]).map_err(field(HeaderField::DevMinor))?;
    // Past byte 257, so a v7 header names its owner by id alone and has no
    // device numbers to report. A header with magic has both.
    let (uname, gname, device) = match magic {
        Magic::Posix | Magic::Gnu => (
            text(&block[UNAME]).to_vec(),
            text(&block[GNAME]).to_vec(),
            Some((major, minor)),
        ),
        Magic::V7 => (Vec::new(), Vec::new(), None),
    };

    // The readers agree on which headers hold owner names and device numbers
    // only for POSIX's magic, with any version, and GNU's magic and version
    // exactly. With any other pair, each reader decides for itself: GNU tar
    // and Go read GNU's magic with another version as v7, where bsdtar and
    // Python read the names and devices, and Python reads them under any
    // magic at all. So such a header is read only where those fields say
    // nothing.
    let gnu = &block[MAGIC_VERSION] == b"ustar  \0";
    let unknown_magic = magic != Magic::Posix && !gnu && {
        let names = !text(&block[UNAME]).is_empty() || !text(&block[GNAME]).is_empty();
        let device = matches!(block[TYPEFLAG], b'3' | b'4') && (major != 0 || minor != 0);
        names || device
    };
    // The `tar` and `tar-core` crates apply metadata only under POSIX's
    // magic with the version `00` and GNU's pair, and read it as a member
    // under any other.
    let exact_magic = gnu || &block[MAGIC_VERSION] == b"ustar\x0000";

    Ok(Fields {
        path,
        link_target,
        typeflag: block[TYPEFLAG],
        mode: mode & 0o7777,
        uid,
        gid,
        uname,
        gname,
        size,
        mtime,
        device,
        stray_prefix,
        prefix_slash,
        unknown_magic,
        exact_magic,
    })
}

/// Whether the header's checksum matches it: the sum of every byte of the
/// block, the checksum field read as spaces.
///
/// The unsigned sum is the format's. The signed sum is accepted as well, as
/// GNU tar documents for archives from historical writers. Every reader
/// ferrotape is measured against accepts it.
fn checksum_matches(block: &[u8; BLOCK]) -> bool {
    let Ok(stored) = number(&block[CHECKSUM]) else {
        return false;
    };
    let bytes = || {
        block
            .iter()
            .enumerate()
            .map(|(at, byte)| if CHECKSUM.contains(&at) { b' ' } else { *byte })
    };
    // At most 512 * 255 either way, so neither sum can overflow.
    let unsigned: i64 = bytes().map(i64::from).sum();
    let signed: i64 = bytes().map(|byte| i64::from(byte.cast_signed())).sum();
    stored == unsigned || stored == signed
}

/// A text field: the bytes up to the first NUL.
///
/// A header's own text fields are NUL-padded, and a GNU long name or long
/// link is a C string. In either, a NUL ends the text. The reference readers
/// all read a long name holding one this way.
pub(crate) fn text(field: &[u8]) -> &[u8] {
    field.split(|byte| *byte == 0).next().unwrap_or(field)
}

/// A numeric field: octal digits, or GNU's base-256 form where the first
/// byte has its high bit set.
pub(crate) fn number(field: &[u8]) -> Result<i64, Numeric> {
    match field.split_first() {
        Some((first, rest)) if first & 0x80 != 0 => base256(*first, rest),
        _ => octal(field),
    }
}

/// A numeric field that cannot be negative: a mode or an id.
fn unsigned(field: &[u8]) -> Result<u32, Numeric> {
    u32::try_from(number(field)?).map_err(|_| Numeric::OutOfRange)
}

/// An octal field: leading spaces, digits, then a space or a NUL ending
/// them. A field of blanks or NULs alone is zero, as GNU tar reads one.
///
/// After a space that ends the digits, the field holds spaces alone up to its
/// first NUL. GNU tar and bsdtar read digits followed by a space and more as
/// the first digits. Go cannot read the field, and Python, which cannot
/// either, ends the archive at its header.
fn octal(field: &[u8]) -> Result<i64, Numeric> {
    let mut value: i64 = 0;
    let mut seen_digit = false;
    let mut bytes = field.iter();
    for byte in bytes.by_ref() {
        if let Some(digit) = char::from(*byte).to_digit(8) {
            value = value
                .checked_mul(8)
                .and_then(|value| value.checked_add(i64::from(digit)))
                .ok_or(Numeric::OutOfRange)?;
            seen_digit = true;
            continue;
        }
        match byte {
            b' ' if !seen_digit => {}
            0 => return Ok(value),
            b' ' => break,
            _ => return Err(Numeric::Unreadable),
        }
    }
    for byte in bytes {
        match byte {
            b' ' => {}
            0 => break,
            _ => return Err(Numeric::Unreadable),
        }
    }
    Ok(value)
}

/// GNU's base-256 form: big-endian two's complement, the high bit of the
/// first byte marking the form and the next bit the value's sign.
fn base256(first: u8, rest: &[u8]) -> Result<i64, Numeric> {
    // The first byte's seven low bits begin the value, sign-extended from the
    // seventh. With the marker bit set, reading the byte as signed is that
    // extension where the sign bit is set.
    let mut value = if first & 0x40 != 0 {
        i64::from(first.cast_signed())
    } else {
        i64::from(first & 0x3f)
    };
    for byte in rest {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(i64::from(*byte)))
            .ok_or(Numeric::OutOfRange)?;
    }
    Ok(value)
}

/// A text field of a header being written.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Text {
    Name,
    Linkname,
    Uname,
    Gname,
    Prefix,
}

impl Text {
    fn range(self) -> Range<usize> {
        match self {
            Text::Name => NAME,
            Text::Linkname => LINKNAME,
            Text::Uname => UNAME,
            Text::Gname => GNAME,
            Text::Prefix => PREFIX,
        }
    }

    /// The most bytes the field holds. POSIX ends `uname` and `gname` with a
    /// NUL. The name, link name and prefix may fill their fields.
    pub(crate) fn capacity(self) -> usize {
        let range = self.range();
        let length = range.end.saturating_sub(range.start);
        match self {
            Text::Uname | Text::Gname => length.saturating_sub(1),
            Text::Name | Text::Linkname | Text::Prefix => length,
        }
    }
}

/// A numeric field of a header being written.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Number {
    Mode,
    Uid,
    Gid,
    Size,
    Mtime,
    DevMajor,
    DevMinor,
}

impl Number {
    fn range(self) -> Range<usize> {
        match self {
            Number::Mode => MODE,
            Number::Uid => UID,
            Number::Gid => GID,
            Number::Size => SIZE,
            Number::Mtime => MTIME,
            Number::DevMajor => DEVMAJOR,
            Number::DevMinor => DEVMINOR,
        }
    }

    /// The largest value the field holds in octal: as many digits as fit
    /// with the NUL that ends them.
    pub(crate) fn octal_max(self) -> u64 {
        largest_in(self.width().saturating_sub(1))
    }

    /// The largest value the field holds in octal digits that fill it, with
    /// no NUL. bsdtar writes a device number in that form where seven digits
    /// do not hold it, and every reader reads it.
    pub(crate) fn filling_max(self) -> u64 {
        largest_in(self.width())
    }

    fn width(self) -> usize {
        let range = self.range();
        range.end.saturating_sub(range.start)
    }
}

/// The largest value `digits` octal digits hold.
fn largest_in(digits: usize) -> u64 {
    u32::try_from(digits)
        .ok()
        .and_then(|digits| digits.checked_mul(3))
        .and_then(|bits| 1u64.checked_shl(bits))
        .map_or(u64::MAX, |bound| bound.saturating_sub(1))
}

/// A POSIX ustar header block being written: each field set in turn, then
/// sealed with its checksum.
pub(crate) struct Draft {
    block: [u8; BLOCK],
}

impl Draft {
    /// A block of `typeflag` with the POSIX magic and version, every numeric
    /// field zero and every text field empty.
    pub(crate) fn new(typeflag: u8) -> Draft {
        let mut block = [0u8; BLOCK];
        block[MAGIC].copy_from_slice(b"ustar\0");
        block[VERSION].copy_from_slice(b"00");
        block[TYPEFLAG] = typeflag;
        let mut draft = Draft { block };
        for field in [
            Number::Mode,
            Number::Uid,
            Number::Gid,
            Number::Size,
            Number::Mtime,
            Number::DevMajor,
            Number::DevMinor,
        ] {
            draft.octal(field, 0);
        }
        draft
    }

    /// Sets `field` to `text`, NUL-padded. The caller checks that `text` fits
    /// ([`Text::capacity`]). Where it does not, the field is left as it was
    /// and `false` returned.
    pub(crate) fn text(&mut self, field: Text, text: &[u8]) -> bool {
        if text.len() > field.capacity() {
            return false;
        }
        let Some(slot) = self.block.get_mut(field.range()) else {
            return false;
        };
        slot.fill(0);
        match slot.get_mut(..text.len()) {
            Some(start) => {
                start.copy_from_slice(text);
                true
            }
            None => false,
        }
    }

    /// Sets `field` to `value` as zero-padded octal digits and a NUL, the
    /// form every writer uses. Where `value` exceeds [`Number::octal_max`],
    /// the field is left as it was and `false` returned.
    pub(crate) fn octal(&mut self, field: Number, value: u64) -> bool {
        if value > field.octal_max() {
            return false;
        }
        let Some((end, digits)) = self
            .block
            .get_mut(field.range())
            .and_then(|slot| slot.split_last_mut())
        else {
            return false;
        };
        *end = 0;
        put_digits(digits, value);
        true
    }

    /// Sets `field` to `value` as octal digits filling it, with no NUL.
    /// Where `value` exceeds [`Number::filling_max`], the field is left as it
    /// was and `false` returned.
    pub(crate) fn octal_filling(&mut self, field: Number, value: u64) -> bool {
        if value > field.filling_max() {
            return false;
        }
        let Some(digits) = self.block.get_mut(field.range()) else {
            return false;
        };
        put_digits(digits, value);
        true
    }

    /// Sets `field` to `value` in GNU's base-256 form: big-endian two's
    /// complement, the first byte's high bit marking the form and the next
    /// holding the sign. Where the field's bits cannot hold `value`, the
    /// field is left as it was and `false` returned.
    pub(crate) fn base256(&mut self, field: Number, value: i128) -> bool {
        let Some(slot) = self.block.get_mut(field.range()) else {
            return false;
        };
        let bytes = value.to_be_bytes();
        let sign = if value < 0 { 0xff } else { 0x00 };
        let Some((high, low)) = bytes
            .len()
            .checked_sub(slot.len())
            .and_then(|cut| bytes.split_at_checked(cut))
        else {
            return false;
        };
        // What the field cannot hold must be the sign extended, and the bit
        // under the marker must still hold the sign.
        let fits = high.iter().all(|byte| *byte == sign)
            && low.first().is_some_and(|first| first & 0xc0 == sign & 0xc0);
        if !fits {
            return false;
        }
        slot.copy_from_slice(low);
        if let Some(first) = slot.first_mut() {
            *first |= 0x80;
        }
        true
    }

    /// The block, its checksum computed. The checksum is the unsigned sum of
    /// every byte, the checksum field read as spaces. It is written as six
    /// octal digits, a NUL and a space.
    pub(crate) fn seal(mut self) -> [u8; BLOCK] {
        self.block[CHECKSUM].fill(b' ');
        // At most 512 * 255, which six octal digits hold.
        let sum: u64 = self.block.iter().copied().map(u64::from).sum();
        let mut field = *b"000000\0 ";
        if let Some(digits) = field.get_mut(..6) {
            put_digits(digits, sum);
        }
        self.block[CHECKSUM].copy_from_slice(&field);
        self.block
    }
}

/// Writes the low octal digits of `value` into `digits`, zero-padded, the
/// last digit last.
fn put_digits(digits: &mut [u8], value: u64) {
    const OCTAL_DIGITS: &[u8; 8] = b"01234567";
    let mut rest = value;
    for slot in digits.iter_mut().rev() {
        *slot = OCTAL_DIGITS
            .get(usize::from(u8::try_from(rest & 7).unwrap_or(0)))
            .copied()
            .unwrap_or(b'0');
        rest >>= 3;
    }
}
