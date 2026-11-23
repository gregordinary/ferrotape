//! ferrotape's reading of a case, and how it is held to the reference
//! readers' readings.

use std::fmt;
use std::io::Read as _;

use ferrotape::{EntryKind, GlobalHeaders, Reader as TarReader};

use crate::case::{Case, Level, Mode, Reader, Verdict};
use crate::reading::{Data, Member, Reading};

/// How far past the end marker `finish` reads.
const TRAILING_LIMIT: u64 = 1 << 20;

/// One member as ferrotape reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Read {
    /// The member's kind.
    pub kind: EntryKind,
    /// Its typeflag byte.
    pub typeflag: u8,
    /// Its path.
    pub path: Vec<u8>,
    /// Its link target.
    pub link: Vec<u8>,
    /// Its size.
    pub size: u64,
    /// A device's major and minor numbers.
    pub device: Option<(u32, u32)>,
    /// Its mode.
    pub mode: u32,
    /// Its modification time, in whole seconds, floored.
    pub mtime: i64,
    /// Its owner's id.
    pub uid: u32,
    /// Its group's id.
    pub gid: u32,
    /// Its owner's name.
    pub uname: Vec<u8>,
    /// Its group's name.
    pub gname: Vec<u8>,
    /// Its data.
    pub data: Vec<u8>,
    /// Whether its pax records hold a list's text, POSIX.1e's access or
    /// default list or an NFSv4 list (`SCHILY.acl.access`,
    /// `SCHILY.acl.default`, `SCHILY.acl.ace`), from which bsdtar takes its
    /// mode.
    pub lists: bool,
}

/// The `ErrorKind` variant's name, which a verdict states; for a sparse
/// member, with its `SparseFlaw` in parentheses.
pub fn kind_name(error: &ferrotape::Error) -> String {
    // A sparse member's refusal names the rule it breaks.
    if let ferrotape::ErrorKind::Sparse(flaw) = error.kind() {
        return format!("Sparse({flaw:?})");
    }
    let debug = format!("{:?}", error.kind());
    debug
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Reads `archive` in one setting, as a program would: each member and its
/// data, then `finish`. The members are those read before a refusal.
pub fn read(archive: &[u8], level: Level, mode: Mode) -> (Vec<Read>, Verdict) {
    let level = match level {
        Level::Strict => ferrotape::Level::Strict,
        Level::Compatible => ferrotape::Level::Compatible,
    };
    let mode = match mode {
        Mode::Refuse => GlobalHeaders::Refuse,
        Mode::Apply => GlobalHeaders::Apply,
        Mode::Defer => GlobalHeaders::Defer,
    };
    let refused = |error: &ferrotape::Error| Verdict::Refused {
        kind: kind_name(error),
        offset: error.offset(),
    };
    let mut reader = TarReader::new(archive)
        .with_level(level)
        .with_global_headers(mode);
    let mut members = Vec::new();
    loop {
        match reader.next_entry() {
            Ok(None) => break,
            Ok(Some(entry)) => {
                // One byte past the size, which no member's data reaches, so
                // data that runs on shows as a difference rather than
                // filling memory.
                let mut data = Vec::new();
                let failed = reader
                    .data()
                    .take(entry.size().saturating_add(1))
                    .read_to_end(&mut data)
                    .err();
                members.push(Read {
                    kind: entry.kind(),
                    typeflag: entry.typeflag(),
                    path: entry.path().to_vec(),
                    link: entry.link_target().to_vec(),
                    size: entry.size(),
                    device: entry.device(),
                    mode: entry.mode(),
                    mtime: entry.mtime().secs(),
                    uid: entry.uid(),
                    gid: entry.gid(),
                    uname: entry.uname().to_vec(),
                    gname: entry.gname().to_vec(),
                    data,
                    lists: [
                        &b"SCHILY.acl.access"[..],
                        b"SCHILY.acl.default",
                        b"SCHILY.acl.ace",
                    ]
                    .iter()
                    .any(|keyword| entry.pax_records().get(keyword).is_some()),
                });
                if let Some(error) = failed {
                    let verdict = match error.downcast::<ferrotape::Error>() {
                        Ok(error) => refused(&error),
                        Err(error) => Verdict::Refused {
                            kind: format!("Io({error})"),
                            offset: 0,
                        },
                    };
                    return (members, verdict);
                }
            }
            Err(error) => return (members, refused(&error)),
        }
    }
    match reader.finish(TRAILING_LIMIT) {
        Ok(()) => (members, Verdict::Read),
        Err(error) => (members, refused(&error)),
    }
}

/// Whether two paths name one member. Python drops a directory's trailing
/// slash from its name, and extracts the same directory, so a trailing slash
/// is not compared.
fn same_path(ours: &[u8], theirs: &[u8]) -> bool {
    let trim = |p: &[u8]| -> Vec<u8> {
        let mut p = p.to_vec();
        while p.last() == Some(&b'/') {
            p.pop();
        }
        p
    };
    trim(ours) == trim(theirs)
}

/// The kind a listing's mode column shows, as the reader extracts it. GNU tar
/// lists a contiguous file as `C` and extracts it as a regular file, or as a
/// directory where its name ends in `/`; it lists an unknown typeflag as `?`
/// and extracts a regular file.
fn listed_kind(reader: Reader, listed: u8, path: &[u8]) -> Option<EntryKind> {
    let gnu = reader == Reader::GnuTar;
    Some(match listed {
        b'-' => EntryKind::File,
        b'd' => EntryKind::Directory,
        b'l' => EntryKind::Symlink,
        b'h' => EntryKind::HardLink,
        b'c' => EntryKind::CharDevice,
        b'b' => EntryKind::BlockDevice,
        b'p' => EntryKind::Fifo,
        b'C' if gnu && path.ends_with(b"/") => EntryKind::Directory,
        b'C' | b'?' if gnu => EntryKind::File,
        _ => return None,
    })
}

/// The members of a reading that are members: Go yields a global header as
/// one, typeflag `g`.
fn members(reading: &Reading) -> Vec<&Member> {
    reading
        .members
        .iter()
        .filter(|m| m.typeflag != Some(b'g'))
        .collect()
}

/// One way ferrotape's members differ from what a reader read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Difference {
    /// The reader.
    pub reader: Reader,
    /// What differs: `members` where the member lists do not name the same
    /// members in the same order, and otherwise the field (`link target`,
    /// `data`, `kind`, `device`, `mode`, `uid`, `gid`, `uname`, `gname`,
    /// `mtime`).
    pub what: &'static str,
    /// The member, and each side's value, as a message.
    pub detail: String,
    /// Whether the documentation states the difference, so that a check
    /// passes over it: bsdtar's mode for a member carrying a list's text,
    /// which bsdtar takes from the lists and ferrotape from the header. A
    /// case that shows one is still read otherwise
    /// ([`undisputed`] counts it).
    pub stated: bool,
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.what == "members" {
            write!(f, "{}: members {}", self.reader.name(), self.detail)
        } else {
            write!(
                f,
                "{}: {} of {}",
                self.reader.name(),
                self.what,
                self.detail
            )
        }
    }
}

/// Every way ferrotape's members differ from what `reader` read. Empty where
/// they agree, or where the reader refused the archive, since a refusal reads
/// nothing.
pub fn differences(ours: &[Read], reader: Reader, reading: &Reading) -> Vec<Difference> {
    if reading.refused() {
        return Vec::new();
    }
    let theirs = members(reading);
    let mut out = Vec::new();
    let paths = |m: &[&Member]| -> Vec<String> {
        m.iter().map(|m| crate::value::render(&m.path)).collect()
    };
    if ours.len() != theirs.len()
        || ours
            .iter()
            .zip(&theirs)
            .any(|(a, b)| !same_path(&a.path, &b.path))
    {
        let mine: Vec<String> = ours.iter().map(|m| crate::value::render(&m.path)).collect();
        out.push(Difference {
            reader,
            what: "members",
            detail: format!("{mine:?}, theirs {:?}", paths(&theirs)),
            stated: false,
        });
        return out;
    }
    for (a, b) in ours.iter().zip(&theirs) {
        let name = crate::value::render(&a.path);
        let mut differ = |what: &'static str, mine: String, them: String, stated: bool| {
            out.push(Difference {
                reader,
                what,
                detail: format!("{name}: {mine}, theirs {them}"),
                stated,
            });
        };
        // A listing shows a link target for a link alone. GNU tar lists a
        // hard link's target as it extracts it, without a prefix it reports
        // removing.
        let is_link = matches!(a.kind, EntryKind::HardLink | EntryKind::Symlink);
        let theirs = b.link.as_deref().unwrap_or_default();
        let stripped = reader == Reader::GnuTar
            && a.kind == EntryKind::HardLink
            && reading
                .removed_prefixes("hard link targets")
                .iter()
                .any(|prefix| a.link.strip_prefix(prefix.as_slice()) == Some(theirs));
        if is_link && theirs != a.link.as_slice() && !stripped {
            differ(
                "link target",
                crate::value::render(&a.link),
                crate::value::render(b.link.as_deref().unwrap_or_default()),
                false,
            );
        }
        if let Some(data) = &b.data
            && !data.matches(&a.data)
        {
            differ(
                "data",
                format!("{:?}", Data::of(&a.data)),
                format!("{data:?}"),
                false,
            );
        }
        if let Some(listed) = b.listed {
            let kind = listed_kind(reader, listed, &b.path);
            if kind != Some(a.kind) {
                differ(
                    "kind",
                    format!("{:?}", a.kind),
                    format!("listed {}", char::from(listed)),
                    false,
                );
            }
        }
        if let Some((major, minor)) = b.device {
            let ours = a.device.map(|(x, y)| (i128::from(x), i128::from(y)));
            if ours != Some((major, minor)) {
                differ(
                    "device",
                    format!("{ours:?}"),
                    format!("{major},{minor}"),
                    false,
                );
            }
        }
        // A mode field's bits above the twelve permission bits are applied
        // by no reader, though Go and Python report them. bsdtar takes the
        // mode of a member carrying a list's text from the lists.
        if let Some(mode) = b.mode
            && mode & 0o7777 != i128::from(a.mode)
        {
            let stated = reader == Reader::Bsdtar && a.lists;
            differ(
                "mode",
                format!("0o{:o}", a.mode),
                format!("{mode:#o}"),
                stated,
            );
        }
        if let Some(uid) = b.uid
            && uid != i128::from(a.uid)
        {
            differ("uid", a.uid.to_string(), uid.to_string(), false);
        }
        if let Some(gid) = b.gid
            && gid != i128::from(a.gid)
        {
            differ("gid", a.gid.to_string(), gid.to_string(), false);
        }
        if let Some(uname) = &b.uname
            && *uname != a.uname
        {
            differ(
                "uname",
                crate::value::render(&a.uname),
                crate::value::render(uname),
                false,
            );
        }
        if let Some(gname) = &b.gname
            && *gname != a.gname
        {
            differ(
                "gname",
                crate::value::render(&a.gname),
                crate::value::render(gname),
                false,
            );
        }
        if let Some(mtime) = b.mtime
            && mtime != i128::from(a.mtime)
        {
            differ("mtime", a.mtime.to_string(), mtime.to_string(), false);
        }
    }
    out
}

/// What checking a case found.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Checked {
    /// Every way the case fails: a verdict ferrotape does not give, and
    /// wherever it reads the archive, a difference from a reference reader
    /// the setting's mode stands in for.
    pub failures: Vec<String>,
    /// How many readings ferrotape's members were compared with: one for
    /// each setting it reads the case in and each reader of that setting's
    /// mode that did not refuse it.
    pub compared: usize,
}

/// Checks a case in every setting.
pub fn check(case: &Case) -> Checked {
    let archive = case.archive.build();
    let mut out = Vec::new();
    let mut compared = 0;
    for (level, mode) in crate::case::SETTINGS {
        let setting = format!("{} {}", level.name(), mode.name());
        let (ours, verdict) = read(&archive, level, mode);
        let want = case.verdict(level, mode);
        if verdict != *want {
            out.push(format!(
                "{setting}: {verdict}, where the case states {want}"
            ));
            continue;
        }
        if verdict != Verdict::Read {
            continue;
        }
        for &reader in mode.readers() {
            let Some(reading) = case.reading(reader) else {
                out.push(format!("{setting}: no reading from {}", reader.name()));
                continue;
            };
            if !reading.refused() {
                compared += 1;
            }
            for difference in differences(&ours, reader, reading) {
                if !difference.stated {
                    out.push(format!("{setting}: {difference}"));
                }
            }
        }
    }
    Checked {
        failures: out,
        compared,
    }
}

/// The kind a typeflag is to a reader that reports typeflags and extracts
/// any it does not know as a regular file, as Go and Python do.
fn typeflag_kind(typeflag: u8) -> EntryKind {
    match typeflag {
        b'1' => EntryKind::HardLink,
        b'2' => EntryKind::Symlink,
        b'3' => EntryKind::CharDevice,
        b'4' => EntryKind::BlockDevice,
        b'5' => EntryKind::Directory,
        b'6' => EntryKind::Fifo,
        _ => EntryKind::File,
    }
}

/// Whether ferrotape and the reference readers read a case all alike:
/// either every reader reads it to the end, ferrotape reads it in every
/// setting, and every reader's members are ferrotape's, their kinds
/// included, as far as each reader reports them; or every reader refuses it,
/// and so does ferrotape in every setting. Every other case is a difference
/// the documentation states.
pub fn undisputed(case: &Case) -> bool {
    let readings: Option<Vec<&Reading>> = Reader::ALL.iter().map(|&r| case.reading(r)).collect();
    let Some(readings) = readings else {
        return false;
    };
    if case.verdicts.iter().all(|v| *v != Verdict::Read) {
        return readings.iter().all(|r| r.refused());
    }
    if case.verdicts.iter().any(|v| *v != Verdict::Read) {
        return false;
    }
    let (ours, _) = read(&case.archive.build(), Level::Strict, Mode::Refuse);
    Reader::ALL.iter().zip(readings).all(|(&reader, reading)| {
        let finished = matches!(
            reading.end,
            crate::reading::End::Ok | crate::reading::End::Exit(0)
        );
        let kinds = members(reading)
            .iter()
            .zip(&ours)
            .all(|(m, a)| m.typeflag.is_none_or(|t| typeflag_kind(t) == a.kind));
        finished && kinds && differences(&ours, reader, reading).is_empty()
    })
}
