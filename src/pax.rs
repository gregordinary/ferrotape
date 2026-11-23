//! Pax extended headers: records framed by their length, the records a member
//! has, and the keywords the reader applies to it.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::iter::FusedIterator;

use crate::entry::Timestamp;
use crate::error::{ErrorKind, Keyword, Numeric, PaxFraming, SparseFlaw};
use crate::escaped::Escaped;
use crate::header::SIZE_LIMIT;
use crate::settings::{GlobalHeaders, Level};

/// The keyword prefix of a record holding an extended attribute, the
/// attribute's name following it.
const XATTR: &[u8] = b"SCHILY.xattr.";

/// The keyword prefix of bsdtar's second record of an extended attribute: the
/// name follows it URL-encoded, and the value is base64.
const LIBARCHIVE_XATTR: &[u8] = b"LIBARCHIVE.xattr.";

/// The standard base64 alphabet (RFC 4648, section 4).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The prefix of the keywords that describe a pax sparse member.
const SPARSE: &[u8] = crate::sparse::PREFIX;

/// The records of a pax extended header, in the order the archive holds them.
/// The header is the one (typeflag `x`) that preceded a member, or a global one
/// (typeflag `g`).
///
/// The reader has already applied the records of a member's own header that
/// it reads as the member's fields (`path`, `linkpath`, `size`, `uid`, `gid`,
/// `uname`, `gname`, `mtime`, `atime` and `ctime`). Each is here as well, as
/// the archive spells it. Every other record, a vendor's included, is here
/// and nowhere else.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PaxRecords {
    /// The header's data, every record of which frames.
    data: Vec<u8>,
}

impl PaxRecords {
    /// Each record's keyword and value, in the archive's order.
    pub fn iter(&self) -> Records<'_> {
        Records { rest: &self.data }
    }

    /// Whether the member has no records: no extended header preceded it.
    /// The reader refuses an extended header with no records
    /// ([`ErrorKind::EmptyMetadata`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The value of the record with `keyword`, or of the last one where
    /// several have it, as POSIX gives the last precedence.
    #[must_use]
    pub fn get(&self, keyword: &[u8]) -> Option<&[u8]> {
        self.iter()
            .filter(|(spelled, _)| *spelled == keyword)
            .last()
            .map(|(_, value)| value)
    }

    /// Whether the `SCHILY.devmajor` and `SCHILY.devminor` records agree with
    /// a device's header numbers, `major` and `minor`. Where either record is
    /// present, bsdtar takes the device's numbers from the two, a missing one
    /// as 0. GNU tar, Go and Python take them from the header. A record that is
    /// not decimal digits agrees with nothing.
    pub(crate) fn device_records_agree(&self, (major, minor): (u32, u32)) -> bool {
        let (major_record, minor_record) =
            (self.get(b"SCHILY.devmajor"), self.get(b"SCHILY.devminor"));
        if major_record.is_none() && minor_record.is_none() {
            return true;
        }
        let stated = |record: Option<&[u8]>| record.map_or(Ok(0), decimal);
        stated(major_record) == Ok(u64::from(major)) && stated(minor_record) == Ok(u64::from(minor))
    }

    /// The extended attributes the records hold, each name with its value, in
    /// the archive's order.
    ///
    /// An attribute is a `SCHILY.xattr.` record, the attribute's name
    /// following the prefix as the archive spells it. GNU tar, bsdtar and Go
    /// read these records, and bsdtar also writes and applies a
    /// `LIBARCHIVE.xattr.` record for each attribute. The reader refuses a
    /// member whose records different readers would extract as different
    /// attributes ([`ErrorKind::XattrName`], [`ErrorKind::XattrConflict`]).
    /// Every `LIBARCHIVE.xattr.` record of a member read therefore repeats an
    /// attribute listed here.
    ///
    /// A global header's records are not held to that rule, and their
    /// attributes are listed as spelled.
    pub fn xattrs(&self) -> Xattrs<'_> {
        Xattrs {
            records: self.iter(),
        }
    }

    /// The value of the extended attribute named `name`, or of the last
    /// record naming it where several do.
    #[must_use]
    pub fn xattr(&self, name: &[u8]) -> Option<&[u8]> {
        self.xattrs()
            .filter(|(spelled, _)| *spelled == name)
            .last()
            .map(|(_, value)| value)
    }

    /// The member's access control list, in each form the records hold it.
    ///
    /// An archive records a POSIX access control list in two forms. One is
    /// the kernel's binary value, as the extended attribute
    /// `system.posix_acl_access`. The other is `getfacl`'s text, as a
    /// `SCHILY.acl.access` record. Readers apply different ones, so an archive
    /// whose two forms state different lists is extracted with different
    /// permissions by each. Both are delivered together, as the archive holds
    /// them. The caller parses them, and decides what a disagreement means.
    ///
    /// The list also states the permissions the header's mode does, and the
    /// two can differ. Where the list has a mask, GNU tar writes the mask in
    /// the mode's group bits, and bsdtar writes the owning group's entry. GNU
    /// tar extracts the header's mode beside the list. bsdtar takes the whole
    /// mode from the list's text, the group bits from the owning group's
    /// entry. It drops setuid, setgid and sticky, which
    /// [`Level::Strict`](crate::Level::Strict) refuses beside a list
    /// ([`ErrorKind::SpecialBitsWithAcl`]). [`Entry::mode`](crate::Entry::mode)
    /// is the header's, as the archive holds it, and the caller checks it
    /// against the list by the list's own rules.
    #[must_use]
    pub fn access_acl(&self) -> AclRecords<'_> {
        AclRecords {
            binary: self.xattr(b"system.posix_acl_access"),
            text: self.get(b"SCHILY.acl.access"),
        }
    }

    /// A directory's default access control list, in each form the records
    /// hold it: the extended attribute `system.posix_acl_default` and the
    /// `SCHILY.acl.default` record. As [`access_acl`](Self::access_acl).
    ///
    /// The record is refused on a member that is not a directory
    /// ([`ErrorKind::DefaultAclWithoutDirectory`]).
    #[must_use]
    pub fn default_acl(&self) -> AclRecords<'_> {
        AclRecords {
            binary: self.xattr(b"system.posix_acl_default"),
            text: self.get(b"SCHILY.acl.default"),
        }
    }
}

/// One access control list, in the forms an archive's records hold it.
///
/// Either form can be present without the other, and an empty text form is a
/// form. GNU tar writes an empty `SCHILY.acl.default` for a directory with no
/// default list.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AclRecords<'a> {
    binary: Option<&'a [u8]>,
    text: Option<&'a [u8]>,
}

impl<'a> AclRecords<'a> {
    /// The kernel's binary form, the extended attribute's value.
    #[must_use]
    pub fn binary(&self) -> Option<&'a [u8]> {
        self.binary
    }

    /// `getfacl`'s text form, the `SCHILY.acl.` record's value.
    #[must_use]
    pub fn text(&self) -> Option<&'a [u8]> {
        self.text
    }

    /// Whether the records hold the list in neither form.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.binary.is_none() && self.text.is_none()
    }
}

impl fmt::Debug for AclRecords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclRecords")
            .field("binary", &self.binary.map(Escaped))
            .field("text", &self.text.map(Escaped))
            .finish()
    }
}

impl<'a> IntoIterator for &'a PaxRecords {
    type Item = (&'a [u8], &'a [u8]);
    type IntoIter = Records<'a>;

    fn into_iter(self) -> Records<'a> {
        self.iter()
    }
}

impl fmt::Debug for PaxRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.iter()
                    .map(|(keyword, value)| (Escaped(keyword), Escaped(value))),
            )
            .finish()
    }
}

/// The records of a [`PaxRecords`], each a keyword and its value.
#[derive(Clone, Debug)]
pub struct Records<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Records<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        // The data was checked when the records were read, so every record
        // frames; were one not to, iteration would end there.
        match split_record(self.rest) {
            Ok((record, rest)) => {
                self.rest = rest;
                Some(record)
            }
            Err(_) => {
                self.rest = &[];
                None
            }
        }
    }
}

impl FusedIterator for Records<'_> {}

/// The extended attributes of a [`PaxRecords`], each a name and its value.
#[derive(Clone, Debug)]
pub struct Xattrs<'a> {
    records: Records<'a>,
}

impl<'a> Iterator for Xattrs<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.records
            .find_map(|(keyword, value)| keyword.strip_prefix(XATTR).map(|name| (name, value)))
    }
}

impl FusedIterator for Xattrs<'_> {}

/// What pax records say about the fields the reader reads.
#[derive(Clone, Debug, Default)]
pub(crate) struct Applied {
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) link_target: Option<Vec<u8>>,
    pub(crate) size: Option<u64>,
    pub(crate) mtime: Option<Timestamp>,
    pub(crate) atime: Option<Timestamp>,
    pub(crate) ctime: Option<Timestamp>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) uname: Option<Vec<u8>>,
    pub(crate) gname: Option<Vec<u8>>,
}

impl Applied {
    /// These records over `beneath`'s: each field these leave unstated takes
    /// `beneath`'s.
    pub(crate) fn over(self, beneath: &Applied) -> Applied {
        Applied {
            path: self.path.or_else(|| beneath.path.clone()),
            link_target: self.link_target.or_else(|| beneath.link_target.clone()),
            size: self.size.or(beneath.size),
            mtime: self.mtime.or(beneath.mtime),
            atime: self.atime.or(beneath.atime),
            ctime: self.ctime.or(beneath.ctime),
            uid: self.uid.or(beneath.uid),
            gid: self.gid.or(beneath.gid),
            uname: self.uname.or_else(|| beneath.uname.clone()),
            gname: self.gname.or_else(|| beneath.gname.clone()),
        }
    }

    /// Whether the records state any field of a member.
    pub(crate) fn sets_a_field(&self) -> bool {
        self.path.is_some()
            || self.link_target.is_some()
            || self.size.is_some()
            || self.mtime.is_some()
            || self.atime.is_some()
            || self.ctime.is_some()
            || self.uid.is_some()
            || self.gid.is_some()
            || self.uname.is_some()
            || self.gname.is_some()
    }
}

/// Reads a member's extended header: every record framed, and the ones the
/// reader applies read.
pub(crate) fn parse(data: Vec<u8>, level: Level) -> Result<(PaxRecords, Applied), ErrorKind> {
    let mut applied = Applied::default();
    for record in framed(&data) {
        let (keyword, value) = record?;
        apply(&mut applied, keyword, value)?;
    }
    if level == Level::Strict {
        check_repeats(&data)?;
    }
    check_xattrs(&data)?;
    check_selinux(&data)?;
    check_charset(&data)?;
    Ok((PaxRecords { data }, applied))
}

/// Reads a global extended header as `mode` reads one: every record framed,
/// and what the header states for the members after it.
pub(crate) fn parse_global(
    data: Vec<u8>,
    mode: GlobalHeaders,
    level: Level,
) -> Result<(PaxRecords, Applied), ErrorKind> {
    let mut applied = Applied::default();
    for record in framed(&data) {
        let (keyword, value) = record?;
        // bsdtar fails on a sparse record in a global header, and Go reads the
        // next member as a file of its stored data.
        if keyword.starts_with(SPARSE) {
            return Err(ErrorKind::Sparse(SparseFlaw::Global));
        }
        // GNU tar and Python agree on a global header's records only for
        // these, with values the reader would read in a member's own header.
        let applies = matches!(
            Keyword::of(keyword),
            Some(
                Keyword::Path
                    | Keyword::Linkpath
                    | Keyword::Uid
                    | Keyword::Gid
                    | Keyword::Uname
                    | Keyword::Gname
                    | Keyword::Mtime
            )
        );
        match mode {
            GlobalHeaders::Defer => {}
            GlobalHeaders::Apply if applies => apply(&mut applied, keyword, value)?,
            GlobalHeaders::Refuse | GlobalHeaders::Apply if keyword == b"comment" => {}
            GlobalHeaders::Refuse | GlobalHeaders::Apply => {
                return Err(ErrorKind::GlobalRecord {
                    keyword: keyword.to_vec(),
                });
            }
        }
    }
    // GNU tar applies the first of a keyword a global header repeats, and
    // Python the last, so applying one is refused at both levels.
    if level == Level::Strict || mode == GlobalHeaders::Apply {
        check_repeats(&data)?;
    }
    Ok((PaxRecords { data }, applied))
}

/// The records of `data`, each framed, ending at the first that does not
/// frame.
fn framed(data: &[u8]) -> impl Iterator<Item = Result<Record<'_>, ErrorKind>> {
    let mut rest = data;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        Some(match split_record(rest) {
            Ok((record, after)) => {
                rest = after;
                Ok(record)
            }
            Err(framing) => {
                rest = &[];
                Err(ErrorKind::PaxFraming(framing))
            }
        })
    })
}

/// Refuses a keyword `data`, records already framed, holds twice with
/// different values.
///
/// POSIX gives the last record precedence and the reader takes it, but one
/// reader in wide use takes the first ([`ErrorKind::RepeatedKeyword`]). Any
/// keyword counts, a vendor's included: the records reach the caller, who can
/// read either. The records are sorted rather than compared pairwise, so the
/// time taken grows with the header's length and not its square.
fn check_repeats(data: &[u8]) -> Result<(), ErrorKind> {
    let mut records: Vec<Record<'_>> = (Records { rest: data }).collect();
    if records.len() < 2 {
        return Ok(());
    }
    records.sort_unstable();
    for pair in records.windows(2) {
        if let [(keyword, value), (next_keyword, next_value)] = pair
            && keyword == next_keyword
            && value != next_value
        {
            return Err(ErrorKind::RepeatedKeyword {
                keyword: keyword.to_vec(),
            });
        }
    }
    Ok(())
}

/// Refuses extended attribute records, `data`'s records already framed, that
/// the readers extract as different attributes.
///
/// GNU tar reads a `SCHILY.xattr.` name with `%3D` and `%25` undone, where
/// bsdtar and Go read it as spelled. No reader extracts an attribute with an
/// empty name, which Go reports ([`ErrorKind::XattrName`]). Go reads an empty
/// value as the record's deletion, where GNU tar and bsdtar set an empty
/// attribute ([`ErrorKind::EmptyXattr`]). bsdtar also applies
/// `LIBARCHIVE.xattr.` records, which GNU tar and Go do not. Each must repeat
/// a `SCHILY.xattr.` record: the same name, holding no `%` for bsdtar to
/// decode, and the last such record's value in base64
/// ([`ErrorKind::XattrConflict`]).
///
/// GNU tar keeps the last value, and bsdtar applies every record of the name
/// in turn, so the two readers agree whatever the order. The `SCHILY.xattr.`
/// records are sorted rather than searched once for each, so the time taken
/// grows with the header's length and not its square.
fn check_xattrs(data: &[u8]) -> Result<(), ErrorKind> {
    let mut libarchive = false;
    for (keyword, value) in (Records { rest: data }) {
        if let Some(spelled) = keyword.strip_prefix(XATTR) {
            let escapes = spelled
                .windows(3)
                .any(|escape| escape == b"%3D" || escape == b"%25");
            if escapes || spelled.is_empty() {
                return Err(ErrorKind::XattrName {
                    keyword: keyword.to_vec(),
                });
            }
            if value.is_empty() {
                return Err(ErrorKind::EmptyXattr {
                    keyword: keyword.to_vec(),
                });
            }
        } else if keyword.starts_with(LIBARCHIVE_XATTR) {
            libarchive = true;
        }
    }
    if !libarchive {
        return Ok(());
    }
    // A stable sort keeps the archive's order among records of one name, so
    // the last of each run is the record that holds.
    let mut attributes: Vec<Record<'_>> = (Records { rest: data })
        .filter_map(|(keyword, value)| Some((keyword.strip_prefix(XATTR)?, value)))
        .collect();
    attributes.sort_by_key(|(name, _)| *name);
    for (keyword, encoded) in (Records { rest: data }) {
        let Some(name) = keyword.strip_prefix(LIBARCHIVE_XATTR) else {
            continue;
        };
        let run_end = attributes.partition_point(|(spelled, _)| *spelled <= name);
        let holding = run_end
            .checked_sub(1)
            .and_then(|last| attributes.get(last))
            .filter(|(spelled, _)| *spelled == name);
        let repeats =
            !name.contains(&b'%') && holding.is_some_and(|(_, value)| is_base64_of(encoded, value));
        if !repeats {
            return Err(ErrorKind::XattrConflict {
                keyword: keyword.to_vec(),
            });
        }
    }
    Ok(())
}

/// Refuses an `RHT.security.selinux` record, `data`'s records already
/// framed, that the readers apply differently ([`ErrorKind::SelinuxConflict`]).
///
/// The record is a second spelling of the attribute `security.selinux`. GNU
/// tar applies it only with `--selinux`, after any `SCHILY.xattr.` record of
/// the attribute, with a NUL appended. bsdtar applies every record of the
/// attribute in the archive's order, as it holds it. Go reports only the
/// `SCHILY.xattr.` record. They agree on GNU tar's own form, which every
/// `RHT.security.selinux` record beside another record of the attribute must
/// take. In that form a later `SCHILY.xattr.` record of the attribute, the
/// last, holds the same context followed by one NUL.
///
/// A record alone, as GNU tar's `--selinux` writes one on every member of a
/// labeled system, is read. GNU tar with `--selinux` and bsdtar apply its
/// context, and no reader applies another label. Where SELinux is enforcing,
/// the kernel stores the context with one NUL, whichever spelling it is
/// given. The record must be given once, hold a context, and hold no NUL.
fn check_selinux(data: &[u8]) -> Result<(), ErrorKind> {
    const RHT: &[u8] = b"RHT.security.selinux";
    const SCHILY: &[u8] = b"SCHILY.xattr.security.selinux";
    const LIBARCHIVE: &[u8] = b"LIBARCHIVE.xattr.security.selinux";
    let mut alone = (Records { rest: data }).filter(|(keyword, _)| *keyword == RHT);
    let beside =
        (Records { rest: data }).any(|(keyword, _)| keyword == SCHILY || keyword == LIBARCHIVE);
    if !beside {
        return match (alone.next(), alone.next()) {
            (None, _) => Ok(()),
            (Some((_, value)), None) if !value.is_empty() && !value.contains(&0) => Ok(()),
            _ => Err(ErrorKind::SelinuxConflict),
        };
    }
    let last = (Records { rest: data })
        .enumerate()
        .filter(|(_, (keyword, _))| *keyword == SCHILY)
        .last()
        .map(|(at, (_, value))| (at, value));
    for (at, (keyword, value)) in (Records { rest: data }).enumerate() {
        if keyword != RHT {
            continue;
        }
        let repeated = last.is_some_and(|(schily_at, schily)| {
            schily_at > at && schily.strip_suffix(b"\0") == Some(value)
        });
        if !repeated {
            return Err(ErrorKind::SelinuxConflict);
        }
    }
    Ok(())
}

/// Refuses a `hdrcharset` record, `data`'s records already framed, naming
/// neither of POSIX's two character sets ([`ErrorKind::UnknownCharset`]).
///
/// bsdtar reports another value as an error. It then reads a `path` ending in
/// `/` over a regular file as a regular file. GNU tar, which ignores the
/// record, reads a directory.
fn check_charset(data: &[u8]) -> Result<(), ErrorKind> {
    for (keyword, value) in (Records { rest: data }) {
        if keyword == b"hdrcharset" && value != b"BINARY" && value != b"ISO-IR 10646 2000 UTF-8" {
            return Err(ErrorKind::UnknownCharset {
                value: value.to_vec(),
            });
        }
    }
    Ok(())
}

/// Whether `encoded` is `bytes` in standard base64, with its padding or
/// without it.
fn is_base64_of(encoded: &[u8], bytes: &[u8]) -> bool {
    let mut rest = encoded;
    let mut padding: &[u8] = b"";
    for chunk in bytes.chunks(3) {
        let (a, b, c, symbols, pad): (u8, u8, u8, usize, &[u8]) = match *chunk {
            [a, b, c] => (a, b, c, 4, b""),
            [a, b] => (a, b, 0, 3, b"="),
            [a] => (a, 0, 0, 2, b"=="),
            _ => return false,
        };
        let sextets = [
            a >> 2,
            (a & 0x03) << 4 | b >> 4,
            (b & 0x0f) << 2 | c >> 6,
            c & 0x3f,
        ];
        for sextet in sextets.iter().take(symbols) {
            match (rest.split_first(), BASE64.get(usize::from(*sextet))) {
                (Some((found, after)), Some(expected)) if found == expected => rest = after,
                _ => return false,
            }
        }
        padding = pad;
    }
    rest.is_empty() || rest == padding
}

/// Reads one record into `applied`, where its keyword is one the reader
/// applies. A later record of a keyword replaces an earlier one, as POSIX
/// gives the last precedence.
fn apply(applied: &mut Applied, keyword: &[u8], value: &[u8]) -> Result<(), ErrorKind> {
    let Some(known) = Keyword::of(keyword) else {
        return Ok(());
    };
    let number = |problem| ErrorKind::PaxValue {
        keyword: known,
        problem,
    };
    match known {
        Keyword::Path => applied.path = Some(name(known, value)?),
        Keyword::Linkpath => applied.link_target = Some(name(known, value)?),
        Keyword::Uname => applied.uname = Some(text(known, value)?),
        Keyword::Gname => applied.gname = Some(text(known, value)?),
        Keyword::Size => {
            let size = decimal(value).map_err(number)?;
            // bsdtar stops at a member declaring 2^60 or more.
            if size >= SIZE_LIMIT {
                return Err(number(Numeric::OutOfRange));
            }
            applied.size = Some(size);
        }
        // GNU tar writes these where an id does not fit the header's octal
        // field, so an archive of a tree with high ids holds its ownership
        // here and nowhere else.
        Keyword::Uid | Keyword::Gid => {
            let id = decimal(value)
                .and_then(|id| u32::try_from(id).map_err(|_| Numeric::OutOfRange))
                .map_err(number)?;
            if known == Keyword::Uid {
                applied.uid = Some(id);
            } else {
                applied.gid = Some(id);
            }
        }
        Keyword::Mtime | Keyword::Atime | Keyword::Ctime => {
            let read = time(value).map_err(number)?;
            if before_epoch_with_fraction(value) {
                return Err(ErrorKind::FractionBeforeEpoch { keyword: known });
            }
            match known {
                Keyword::Atime => applied.atime = Some(read),
                Keyword::Ctime => applied.ctime = Some(read),
                _ => applied.mtime = Some(read),
            }
        }
    }
    Ok(())
}

/// The value of a text record the reader applies, which may not be empty.
///
/// An empty value is POSIX's deletion of the record, and the readers part ways
/// over it ([`ErrorKind::EmptyPaxValue`]). A record the reader does not apply
/// keeps an empty value: GNU tar writes an empty `SCHILY.acl.default` for a
/// directory with no default list.
fn text(keyword: Keyword, value: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    if value.is_empty() {
        return Err(ErrorKind::EmptyPaxValue { keyword });
    }
    Ok(value.to_vec())
}

/// The value of a `path` or `linkpath` record: a [`text`] value holding no
/// NUL.
///
/// The record's length frames the value, so a NUL in it is part of the name
/// rather than its end ([`ErrorKind::PaxNul`]).
fn name(keyword: Keyword, value: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let name = text(keyword, value)?;
    if name.contains(&0) {
        return Err(ErrorKind::PaxNul { keyword });
    }
    Ok(name)
}

/// A pax time: seconds since the epoch, optionally negative, with an optional
/// fraction, rounded down to the nanosecond.
///
/// The second is rounded down, as GNU tar rounds it. `-1.5` is an instant
/// between `-2` and `-1`, so the second holding it is `-2`, and the instant
/// is half a second past it.
fn time(value: &[u8]) -> Result<Timestamp, Numeric> {
    const NANOS_PER_SEC: u32 = 1_000_000_000;
    let (whole, fraction) = split_once(value, b'.').unwrap_or((value, &[]));
    let (negative, magnitude) = match whole.strip_prefix(b"-") {
        Some(magnitude) => (true, magnitude),
        None => (false, whole),
    };
    if !fraction.iter().all(u8::is_ascii_digit) {
        return Err(Numeric::Unreadable);
    }
    let magnitude = decimal(magnitude)?;
    // The fraction's first nine digits, as nanoseconds, missing ones zero,
    // and whether any digit past them is not.
    let (nanos, finer) = fraction.split_at_checked(9).unwrap_or((fraction, &[]));
    let mut fraction_nanos: u32 = 0;
    for place in 0..9 {
        let digit = nanos
            .get(place)
            .and_then(|digit| char::from(*digit).to_digit(10))
            .unwrap_or(0);
        fraction_nanos = fraction_nanos
            .checked_mul(10)
            .and_then(|nanos| nanos.checked_add(digit))
            .ok_or(Numeric::OutOfRange)?;
    }
    let finer = finer.iter().any(|digit| *digit != b'0');

    if !negative {
        // Dropping the digits past the nanosecond floors a positive time.
        let secs = i64::try_from(magnitude).map_err(|_| Numeric::OutOfRange)?;
        return Timestamp::new(secs, fraction_nanos).ok_or(Numeric::OutOfRange);
    }
    // A negative time is `-(magnitude + fraction)`, so its floor takes the
    // fraction's ceiling, then counts the nanoseconds forward from the second
    // below.
    let secs = 0i64
        .checked_sub_unsigned(magnitude)
        .ok_or(Numeric::OutOfRange)?;
    let ceiling = fraction_nanos
        .checked_add(u32::from(finer))
        .ok_or(Numeric::OutOfRange)?;
    if ceiling == 0 {
        return Ok(Timestamp::from_secs(secs));
    }
    // A ceiling of a whole second leaves no nanoseconds past the second below.
    let secs = secs.checked_sub(1).ok_or(Numeric::OutOfRange)?;
    let nanos = NANOS_PER_SEC
        .checked_sub(ceiling)
        .ok_or(Numeric::OutOfRange)?;
    Timestamp::new(secs, nanos).ok_or(Numeric::OutOfRange)
}

/// Whether a pax time, already read, is negative with a fraction that is not
/// zero.
///
/// bsdtar reads the fraction otherwise than the other readers
/// ([`ErrorKind::FractionBeforeEpoch`]).
fn before_epoch_with_fraction(value: &[u8]) -> bool {
    value.starts_with(b"-")
        && split_once(value, b'.')
            .is_some_and(|(_, fraction)| fraction.iter().any(|digit| *digit != b'0'))
}

/// `text` as a decimal number: a non-empty run of ASCII digits and nothing
/// else.
///
/// An integer parser also takes a leading `+`, which no pax writer emits. A
/// record's length decides where the next one begins, and a `size` decides
/// where the next header does. A reader more lenient than the format
/// therefore reads an archive differently from the tools that wrote it.
fn decimal(text: &[u8]) -> Result<u64, Numeric> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Err(Numeric::Unreadable);
    }
    text.iter().try_fold(0u64, |value, byte| {
        let digit = char::from(*byte).to_digit(10).ok_or(Numeric::Unreadable)?;
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
            .ok_or(Numeric::OutOfRange)
    })
}

/// A record's keyword and value.
type Record<'a> = (&'a [u8], &'a [u8]);

/// Appends the record `keyword=value` to `out`, framed as
/// [`split_record`] reads it: `<length> <keyword>=<value>` and a newline, the
/// length counting the whole record, its own digits included. `None` where
/// the record's length overflows.
pub(crate) fn push_record(out: &mut Vec<u8>, keyword: &[u8], value: &[u8]) -> Option<()> {
    // Everything but the length's digits: a space, the keyword, `=`, the
    // value and a newline.
    let rest = keyword.len().checked_add(value.len())?.checked_add(3)?;
    // Each pass counts the digits of the last guess; the count only grows, and
    // settles within two passes.
    let mut length = rest.checked_add(1)?;
    loop {
        let digits = usize::try_from(length.checked_ilog10()?.checked_add(1)?).ok()?;
        let total = rest.checked_add(digits)?;
        if total == length {
            break;
        }
        length = total;
    }
    out.extend_from_slice(length.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(keyword);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    Some(())
}

/// The first record of `rest`, which is not empty, and the bytes after it.
fn split_record(rest: &[u8]) -> Result<(Record<'_>, &[u8]), PaxFraming> {
    let (length, _) = split_once(rest, b' ').ok_or(PaxFraming::NoDelimiter)?;
    let length = match decimal(length) {
        Ok(length) => usize::try_from(length).map_err(|_| PaxFraming::LengthOutOfBounds)?,
        Err(Numeric::Unreadable) => return Err(PaxFraming::BadLength),
        Err(Numeric::OutOfRange) => return Err(PaxFraming::LengthOutOfBounds),
    };
    // The length counts the whole record, its own digits and the space after
    // them included, so a length that ends before the keyword begins does not
    // frame.
    let (record, after) = rest
        .split_at_checked(length)
        .ok_or(PaxFraming::LengthOutOfBounds)?;
    let line = match split_once(record, b' ') {
        Some((_, line)) if !line.is_empty() => line,
        _ => return Err(PaxFraming::LengthOutOfBounds),
    };
    let line = line.strip_suffix(b"\n").ok_or(PaxFraming::NoNewline)?;
    let field = split_once(line, b'=').ok_or(PaxFraming::NoEquals)?;
    // GNU tar and bsdtar read a keyword as a C string, ending at a NUL, and
    // Go refuses the archive, so a NUL frames the record differently for each.
    if field.0.contains(&0) {
        return Err(PaxFraming::KeywordNul);
    }
    Ok((field, after))
}

/// `bytes` split at the first `delimiter`, which neither part holds.
fn split_once(bytes: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let mut parts = bytes.splitn(2, |byte| *byte == delimiter);
    Some((parts.next()?, parts.next()?))
}
