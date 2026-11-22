//! What a reference reader read from an archive: its members, in order, and
//! how it ended.
//!
//! A reading is written one line to a member, then the line that ends it.
//! Each member line is `member` and the fields the reader reports, as
//! `key=value`, in a fixed order:
//!
//! - `type`, the typeflag byte, for the readers that report it (Go and
//!   Python); `listed`, the first character of the mode column, for the
//!   readers read through their listings (GNU tar and bsdtar);
//! - `path`, and `link` where the member has a link target;
//! - `size`, the size the reader reports;
//! - `device`, a character or block device's major and minor numbers;
//! - `mode`, the permission bits, in octal: as Go and Python report the
//!   mode field, and as GNU tar's and bsdtar's listings show them;
//! - `mtime`, in whole seconds, floored; `uid`, `gid`, `uname`, `gname`;
//! - `data`, the member's data: quoted, or where its quoted form would be
//!   long, its length and its 64-bit FNV-1a digest in hexadecimal
//!   (`600:9b2d...`);
//! - `note`, what a listing appends to a member's name, which is not part
//!   of it (GNU tar's `--Volume Header--`, for one).
//!
//! A field a reader does not report is absent. The last line is `ok`;
//! `error` and the reader's message, for a reader that refuses; or `exit`
//! and the status of a command, after its standard error's lines as
//! `warning` lines.

use std::fmt::{self, Write as _};

use crate::value;

/// One member as a reader reports it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Member {
    /// The typeflag byte.
    pub typeflag: Option<u8>,
    /// The first character of a listing's mode column.
    pub listed: Option<u8>,
    /// The member's path.
    pub path: Vec<u8>,
    /// Its link target.
    pub link: Option<Vec<u8>>,
    /// Its size. Each number a reader reports is held as an `i128`: Go and
    /// Python read a base-256 field as signed, and Python's integers have no
    /// bound.
    pub size: Option<i128>,
    /// A device's major and minor numbers.
    pub device: Option<(i128, i128)>,
    /// Its mode, written with a sign where it is negative (`mode=-0o1`).
    pub mode: Option<i128>,
    /// Its modification time, in whole seconds.
    pub mtime: Option<i128>,
    /// Its owner's id.
    pub uid: Option<i128>,
    /// Its group's id.
    pub gid: Option<i128>,
    /// Its owner's name.
    pub uname: Option<Vec<u8>>,
    /// Its group's name.
    pub gname: Option<Vec<u8>>,
    /// Its data.
    pub data: Option<Data>,
    /// What a listing appends to the name.
    pub note: Option<Vec<u8>>,
}

/// A member's data, as a reading records it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Data {
    /// The bytes.
    Bytes(Vec<u8>),
    /// The length and digest of bytes too long to write out.
    Digest(u64, u64),
}

impl Data {
    /// The form a reading records `bytes` in.
    pub fn of(bytes: &[u8]) -> Data {
        if value::quoted(bytes).len() <= LONGEST {
            Data::Bytes(bytes.to_vec())
        } else {
            Data::Digest(bytes.len() as u64, fnv(bytes))
        }
    }

    /// Whether `bytes` is this data.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        match self {
            Data::Bytes(b) => b == bytes,
            Data::Digest(len, digest) => *len == bytes.len() as u64 && *digest == fnv(bytes),
        }
    }
}

/// The longest quoted form a reading writes data in.
const LONGEST: usize = 72;

/// The 64-bit FNV-1a digest of `bytes`.
pub fn fnv(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// How a reading ended.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum End {
    /// The reader read to the end.
    Ok,
    /// The reader refused, with its message.
    Error(Vec<u8>),
    /// A command exited with this status.
    Exit(i32),
}

/// A reference reader's reading of one archive.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reading {
    /// The members, in the order read.
    pub members: Vec<Member>,
    /// A command's standard error, line by line.
    pub warnings: Vec<Vec<u8>>,
    /// How the reading ended.
    pub end: End,
}

impl Reading {
    /// Whether the reader refused the archive: a library that failed, or a
    /// command that exited with an error having read no member. A command
    /// that exits with an error after reading members read those members,
    /// but for bsdtar stopping at a global header it does not support, as
    /// libarchive does from 3.8.10 at one carrying any record but `comment`:
    /// that refuses the archive from the header on, wherever it falls, and
    /// is counted as the refusal it is before the first member.
    pub fn refused(&self) -> bool {
        /// What bsdtar reports as it stops at such a header.
        const GLOBAL_UNSUPPORTED: &[u8] = b"Unsupported pax global extended header attribute";
        match self.end {
            End::Ok => false,
            End::Error(_) => true,
            End::Exit(status) => {
                status != 0
                    && (self.members.is_empty()
                        || self.warnings.iter().any(|warning| {
                            warning
                                .windows(GLOBAL_UNSUPPORTED.len())
                                .any(|window| window == GLOBAL_UNSUPPORTED)
                        }))
            }
        }
    }

    /// The prefixes GNU tar reports removing from what it extracts, `what`
    /// being `member names` or `hard link targets`: its warning
    /// "Removing leading `P' from member names", one for each prefix.
    pub fn removed_prefixes(&self, what: &str) -> Vec<Vec<u8>> {
        removed_prefixes(&self.warnings, what)
    }

    /// Reads a reading's lines.
    pub fn parse(lines: &[&str]) -> Result<Reading, String> {
        let mut members = Vec::new();
        let mut warnings = Vec::new();
        let mut end = None;
        for &line in lines {
            if end.is_some() {
                return Err(format!("`{line}` after the reading's end"));
            }
            let words = value::words(line)?;
            match words.as_slice() {
                ["member", fields @ ..] => members.push(member(fields)?),
                ["warning", text] => warnings.push(value::parse(text)?),
                ["ok"] => end = Some(End::Ok),
                ["error", text] => end = Some(End::Error(value::parse(text)?)),
                ["exit", status] => {
                    end = Some(End::Exit(
                        status
                            .parse()
                            .map_err(|_| format!("`{line}`: a bad status"))?,
                    ));
                }
                _ => return Err(format!("`{line}` is not a reading's line")),
            }
        }
        let end = end.ok_or("a reading that does not end")?;
        Ok(Reading {
            members,
            warnings,
            end,
        })
    }
}

/// The prefixes `warnings`, GNU tar's, report removing from `what`.
///
/// GNU tar extracts an absolute name, or one climbing out with `..`, under
/// the directory it extracts into, and says so once for each prefix it
/// removes: from member names as it extracts them, and from hard link
/// targets in its listing too. Which names it extracts is the caller's
/// policy, not a reading of the archive, so the comparison takes the name
/// as stored.
pub fn removed_prefixes(warnings: &[Vec<u8>], what: &str) -> Vec<Vec<u8>> {
    let tail = format!("' from {what}");
    warnings
        .iter()
        .filter_map(|warning| {
            let rest = warning
                .windows(b"Removing leading `".len())
                .position(|w| w == b"Removing leading `")
                .map(|at| &warning[at + b"Removing leading `".len()..])?;
            let end = rest
                .windows(tail.len())
                .position(|w| w == tail.as_bytes())?;
            Some(rest[..end].to_vec())
        })
        .collect()
}

/// A member line's fields.
fn member(fields: &[&str]) -> Result<Member, String> {
    let mut member = Member::default();
    let mut order = ORDER.iter();
    for word in fields {
        let (key, text) =
            value::split_pair(word).ok_or_else(|| format!("`{word}` is not key=value"))?;
        if !order.any(|&k| k == key) {
            return Err(format!("`{key}` is unknown or out of order"));
        }
        let number = |text: &str| text.parse().map_err(|_| format!("`{word}`: a bad number"));
        match key {
            "type" | "listed" => {
                let bytes = value::parse(text)?;
                let [byte] = bytes[..] else {
                    return Err(format!("`{word}`: one byte"));
                };
                if key == "type" {
                    member.typeflag = Some(byte);
                } else {
                    member.listed = Some(byte);
                }
            }
            "path" => member.path = value::parse(text)?,
            "link" => member.link = Some(value::parse(text)?),
            "size" => member.size = Some(number(text)?),
            "device" => {
                let (major, minor) = text
                    .split_once(',')
                    .ok_or_else(|| format!("`{word}`: not major,minor"))?;
                member.device = Some((number(major)?, number(minor)?));
            }
            "mode" => {
                let (negative, text) = match text.strip_prefix('-') {
                    Some(rest) => (true, rest),
                    None => (false, text),
                };
                let octal = text
                    .strip_prefix("0o")
                    .ok_or_else(|| format!("`{word}`: not 0o and octal"))?;
                let mode =
                    i128::from_str_radix(octal, 8).map_err(|_| format!("`{word}`: a bad mode"))?;
                member.mode = Some(if negative { -mode } else { mode });
            }
            "mtime" => {
                member.mtime = Some(text.parse().map_err(|_| format!("`{word}`: a bad time"))?);
            }
            "uid" => member.uid = Some(number(text)?),
            "gid" => member.gid = Some(number(text)?),
            "uname" => member.uname = Some(value::parse(text)?),
            "gname" => member.gname = Some(value::parse(text)?),
            "data" => {
                member.data = Some(if text.starts_with('"') {
                    Data::Bytes(value::parse(text)?)
                } else {
                    let (len, digest) = text
                        .split_once(':')
                        .ok_or_else(|| format!("`{word}`: neither quoted nor a digest"))?;
                    Data::Digest(
                        len.parse().map_err(|_| format!("`{word}`: a bad length"))?,
                        u64::from_str_radix(digest, 16)
                            .map_err(|_| format!("`{word}`: a bad digest"))?,
                    )
                });
            }
            "note" => member.note = Some(value::parse(text)?),
            _ => unreachable!("every key in ORDER is handled"),
        }
    }
    Ok(member)
}

/// The fields of a member line, in the order they are written.
const ORDER: &[&str] = &[
    "type", "listed", "path", "link", "size", "device", "mode", "mtime", "uid", "gid", "uname",
    "gname", "data", "note",
];

impl fmt::Display for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut line = String::from("member");
        if let Some(t) = self.typeflag {
            let _ = write!(line, " type={}", value::render(&[t]));
        }
        if let Some(l) = self.listed {
            let _ = write!(line, " listed={}", value::render(&[l]));
        }
        let _ = write!(line, " path={}", value::render(&self.path));
        if let Some(link) = &self.link {
            let _ = write!(line, " link={}", value::render(link));
        }
        if let Some(size) = self.size {
            let _ = write!(line, " size={size}");
        }
        if let Some((major, minor)) = self.device {
            let _ = write!(line, " device={major},{minor}");
        }
        if let Some(mode) = self.mode {
            let sign = if mode < 0 { "-" } else { "" };
            let _ = write!(line, " mode={sign}0o{:o}", mode.unsigned_abs());
        }
        if let Some(mtime) = self.mtime {
            let _ = write!(line, " mtime={mtime}");
        }
        if let Some(uid) = self.uid {
            let _ = write!(line, " uid={uid}");
        }
        if let Some(gid) = self.gid {
            let _ = write!(line, " gid={gid}");
        }
        if let Some(uname) = &self.uname {
            let _ = write!(line, " uname={}", value::render(uname));
        }
        if let Some(gname) = &self.gname {
            let _ = write!(line, " gname={}", value::render(gname));
        }
        match &self.data {
            Some(Data::Bytes(bytes)) => {
                let _ = write!(line, " data={}", value::quoted(bytes));
            }
            Some(Data::Digest(len, digest)) => {
                let _ = write!(line, " data={len}:{digest:016x}");
            }
            None => {}
        }
        if let Some(note) = &self.note {
            let _ = write!(line, " note={}", value::quoted(note));
        }
        f.write_str(&line)
    }
}

impl fmt::Display for Reading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for member in &self.members {
            writeln!(f, "{member}")?;
        }
        for warning in &self.warnings {
            writeln!(f, "warning {}", value::quoted(warning))?;
        }
        match &self.end {
            End::Ok => writeln!(f, "ok"),
            End::Error(message) => writeln!(f, "error {}", value::quoted(message)),
            End::Exit(status) => writeln!(f, "exit {status}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnu_tar_s_removed_prefixes_are_read_from_its_warnings() {
        let warnings = [
            b"tar: Removing leading `/' from member names".to_vec(),
            b"tar: Removing leading `b/../../' from hard link targets".to_vec(),
            b"tar: Removing leading `//' from hard link targets".to_vec(),
            b"tar: a/b: Not found in archive".to_vec(),
        ];
        assert_eq!(removed_prefixes(&warnings, "member names"), [b"/".to_vec()]);
        assert_eq!(
            removed_prefixes(&warnings, "hard link targets"),
            [b"b/../../".to_vec(), b"//".to_vec()]
        );
    }

    fn reading(lines: &[&str]) -> Reading {
        Reading::parse(lines).unwrap()
    }

    #[test]
    fn a_reader_that_fails_after_members_read_them_but_where_it_stops_at_a_global_header() {
        assert!(reading(&["error \"bad\""]).refused());
        assert!(reading(&["exit 1"]).refused());
        assert!(!reading(&["member path=a", "exit 0"]).refused());
        // A delayed error exit after reading on: the members it read count.
        assert!(
            !reading(&[
                "member path=a",
                "member path=b",
                "warning \"bsdtar: Malformed pax attributes\"",
                "exit 1",
            ])
            .refused()
        );
        // bsdtar refusing a global header from that header on.
        assert!(
            reading(&[
                "member path=a",
                "warning \"bsdtar: Unsupported pax global extended header attribute 'path'\"",
                "warning \"bsdtar: Error exit delayed from previous errors\"",
                "exit 1",
            ])
            .refused()
        );
    }
}
