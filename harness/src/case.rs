//! A case of the catalog: the rule it shows, its archive, ferrotape's verdict
//! in each setting, and what each reference reader read.
//!
//! A case file is text in sections, each opened by a line holding its name
//! in brackets:
//!
//! ```text
//! [statement]
//! A member whose pax `size` record is zero carries no data, whatever its
//! header declares, and the headers inside the declared body are members.
//!
//! [archive]
//! pax size=0
//! header name=outer size=1024
//! header name=smuggled1
//! header name=smuggled2
//! end
//!
//! [verdict]
//! all: read
//!
//! [gnu-tar 1.35]
//! member listed=- path=outer size=0 data=""
//! ...
//! ```
//!
//! `[statement]` states the rule in prose. `[archive]` holds the archive as
//! items (see [`crate::archive`]); a line beginning `#` there is a comment.
//! `[verdict]` gives ferrotape's verdict in each of the six settings, a level
//! and a global-header mode: lines of a selector, `:` and a verdict, where a
//! selector is `all`, a level (`strict`, `compatible`), a mode (`refuse`,
//! `apply`, `defer`) or a level and a mode, and the lines together name each
//! setting once. A verdict is `read`, or `refused`, the error's kind and
//! `at` its offset. Then one section for each reference reader, named with
//! its version, holding its reading (see [`crate::reading`]).
//!
//! The statement and the archive are kept as written. The verdict and the
//! readings have one written form each, which a case file holds, so a
//! recording rewrites nothing else.

use std::fmt::{self, Write as _};

use crate::archive::Archive;
use crate::reading::Reading;

/// A reference reader.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Reader {
    /// GNU tar, read through its listing, and its extraction to a command for
    /// each regular file's data.
    GnuTar,
    /// bsdtar (libarchive), read through its listing.
    Bsdtar,
    /// Python's `tarfile`.
    Python,
    /// Go's `archive/tar`.
    Go,
}

impl Reader {
    /// Every reference reader, in the order a case lists them.
    pub const ALL: [Reader; 4] = [Reader::GnuTar, Reader::Bsdtar, Reader::Python, Reader::Go];

    /// The reader's name in a section header.
    pub fn name(self) -> &'static str {
        match self {
            Reader::GnuTar => "gnu-tar",
            Reader::Bsdtar => "bsdtar",
            Reader::Python => "python",
            Reader::Go => "go",
        }
    }

    /// The version every reading in the catalog is recorded from. The
    /// catalog's README names the build of each, which a version alone does
    /// not settle.
    pub fn pinned(self) -> &'static str {
        match self {
            Reader::GnuTar => "1.35",
            Reader::Bsdtar => "3.8.11",
            Reader::Python => "3.12.3",
            Reader::Go => "1.27.0",
        }
    }

    fn from_name(name: &str) -> Option<Reader> {
        Reader::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// A level, as a verdict names it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// `ferrotape::Level::Strict`.
    Strict,
    /// `ferrotape::Level::Compatible`.
    Compatible,
}

/// A global-header mode, as a verdict names it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `ferrotape::GlobalHeaders::Refuse`.
    Refuse,
    /// `ferrotape::GlobalHeaders::Apply`.
    Apply,
    /// `ferrotape::GlobalHeaders::Defer`.
    Defer,
}

/// The six settings, in the order a verdict holds them.
pub const SETTINGS: [(Level, Mode); 6] = [
    (Level::Strict, Mode::Refuse),
    (Level::Strict, Mode::Apply),
    (Level::Strict, Mode::Defer),
    (Level::Compatible, Mode::Refuse),
    (Level::Compatible, Mode::Apply),
    (Level::Compatible, Mode::Defer),
];

impl Level {
    /// The level's name in a selector.
    pub fn name(self) -> &'static str {
        match self {
            Level::Strict => "strict",
            Level::Compatible => "compatible",
        }
    }
}

impl Mode {
    /// The mode's name in a selector.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Refuse => "refuse",
            Mode::Apply => "apply",
            Mode::Defer => "defer",
        }
    }

    /// The reference readers whose reading of global headers this mode
    /// follows: all four where it refuses a global header that would change
    /// a member, GNU tar and Python where it applies one, bsdtar and Go where
    /// it applies none.
    pub fn readers(self) -> &'static [Reader] {
        match self {
            Mode::Refuse => &Reader::ALL,
            Mode::Apply => &[Reader::GnuTar, Reader::Python],
            Mode::Defer => &[Reader::Bsdtar, Reader::Go],
        }
    }
}

/// ferrotape's verdict on an archive in one setting.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The archive is read.
    Read,
    /// The archive is refused with this kind of error, at this offset.
    Refused {
        /// The `ErrorKind` variant's name.
        kind: String,
        /// The error's offset.
        offset: u64,
    },
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Read => f.write_str("read"),
            Verdict::Refused { kind, offset } => write!(f, "refused {kind} at {offset}"),
        }
    }
}

impl Verdict {
    fn parse(text: &str) -> Result<Verdict, String> {
        match text.split(' ').collect::<Vec<_>>().as_slice() {
            ["read"] => Ok(Verdict::Read),
            ["refused", kind, "at", offset] => Ok(Verdict::Refused {
                kind: (*kind).to_owned(),
                offset: offset
                    .parse()
                    .map_err(|_| format!("`{text}`: a bad offset"))?,
            }),
            _ => Err(format!("`{text}` is not a verdict")),
        }
    }
}

/// A case.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Case {
    /// The rule, in prose.
    pub statement: String,
    /// The archive section's lines, as written.
    pub archive_text: Vec<String>,
    /// The archive.
    pub archive: Archive,
    /// The verdict in each setting, in [`SETTINGS`]'s order.
    pub verdicts: [Verdict; 6],
    /// Each reference reader's reading, with the version that read it, in
    /// [`Reader::ALL`]'s order.
    pub readings: Vec<(Reader, String, Reading)>,
}

impl Case {
    /// The verdict in a setting.
    pub fn verdict(&self, level: Level, mode: Mode) -> &Verdict {
        let index = SETTINGS
            .iter()
            .position(|&s| s == (level, mode))
            .unwrap_or_default();
        &self.verdicts[index]
    }

    /// The reading `reader` recorded, if the case holds one.
    pub fn reading(&self, reader: Reader) -> Option<&Reading> {
        self.readings
            .iter()
            .find(|(r, _, _)| *r == reader)
            .map(|(_, _, reading)| reading)
    }

    /// Reads a case file.
    pub fn parse(text: &str) -> Result<Case, String> {
        let mut sections: Vec<(&str, Vec<&str>)> = Vec::new();
        for line in text.lines() {
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                sections.push((name, Vec::new()));
            } else if let Some((_, lines)) = sections.last_mut() {
                lines.push(line);
            } else if !line.trim().is_empty() {
                return Err(format!("`{line}` before the first section"));
            }
        }
        let trim = |lines: &[&str]| -> Vec<String> {
            let start = lines.iter().position(|l| !l.trim().is_empty());
            let end = lines.iter().rposition(|l| !l.trim().is_empty());
            match (start, end) {
                (Some(s), Some(e)) => lines[s..=e].iter().map(|l| (*l).to_owned()).collect(),
                _ => Vec::new(),
            }
        };
        let mut sections = sections.into_iter();
        let mut next = |want: &str| -> Result<Vec<String>, String> {
            match sections.next() {
                Some((name, lines)) if name == want => Ok(trim(&lines)),
                Some((name, _)) => Err(format!("[{name}] where [{want}] belongs")),
                None => Err(format!("no [{want}] section")),
            }
        };
        let statement = next("statement")?.join("\n");
        let archive_text = next("archive")?;
        let items: Vec<&str> = archive_text
            .iter()
            .map(String::as_str)
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .collect();
        let archive = Archive::parse(&items).map_err(|e| e.to_string())?;
        let verdicts = parse_verdicts(&next("verdict")?)?;
        let mut readings = Vec::new();
        for (name, lines) in sections {
            let (reader, version) = name
                .split_once(' ')
                .and_then(|(r, v)| Some((Reader::from_name(r)?, v.to_owned())))
                .ok_or_else(|| format!("[{name}] is no reference reader"))?;
            if readings.last().is_some_and(|(last, _, _)| *last >= reader) {
                return Err(format!("[{name}] out of order, or twice"));
            }
            let lines = trim(&lines);
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            let reading = Reading::parse(&lines).map_err(|e| format!("[{name}]: {e}"))?;
            readings.push((reader, version, reading));
        }
        Ok(Case {
            statement,
            archive_text,
            archive,
            verdicts,
            readings,
        })
    }

    /// The verdict section's lines, in their one written form: `all` where
    /// every setting agrees; a line for each level where each level's three
    /// modes agree; otherwise a line for each mode whose levels agree and one
    /// for each setting of the rest.
    fn verdict_lines(&self) -> Vec<String> {
        let v = &self.verdicts;
        if v.iter().all(|x| *x == v[0]) {
            return vec![format!("all: {}", v[0])];
        }
        if v[..3].iter().all(|x| *x == v[0]) && v[3..].iter().all(|x| *x == v[3]) {
            return vec![format!("strict: {}", v[0]), format!("compatible: {}", v[3])];
        }
        let mut lines = Vec::new();
        for (i, mode) in [Mode::Refuse, Mode::Apply, Mode::Defer]
            .into_iter()
            .enumerate()
        {
            let (strict, compatible) = (&v[i], &v[i + 3]);
            if strict == compatible {
                lines.push(format!("{}: {strict}", mode.name()));
            } else {
                lines.push(format!("strict {}: {strict}", mode.name()));
                lines.push(format!("compatible {}: {compatible}", mode.name()));
            }
        }
        lines
    }
}

/// A verdict section's lines, each setting named once.
fn parse_verdicts(lines: &[String]) -> Result<[Verdict; 6], String> {
    let mut verdicts: [Option<Verdict>; 6] = Default::default();
    for line in lines {
        let (selector, verdict) = line
            .split_once(": ")
            .ok_or_else(|| format!("`{line}` is not `selector: verdict`"))?;
        let verdict = Verdict::parse(verdict)?;
        let words: Vec<&str> = selector.split(' ').collect();
        let matches = |level: Level, mode: Mode| match words.as_slice() {
            ["all"] => true,
            [one] => *one == level.name() || *one == mode.name(),
            [l, m] => *l == level.name() && *m == mode.name(),
            _ => false,
        };
        let mut named = false;
        for (i, &(level, mode)) in SETTINGS.iter().enumerate() {
            if matches(level, mode) {
                if verdicts[i].is_some() {
                    return Err(format!(
                        "`{line}` names {} {} a second time",
                        level.name(),
                        mode.name()
                    ));
                }
                verdicts[i] = Some(verdict.clone());
                named = true;
            }
        }
        if !named {
            return Err(format!("`{selector}` selects no setting"));
        }
    }
    let mut out = Vec::new();
    for (i, verdict) in verdicts.into_iter().enumerate() {
        let (level, mode) = SETTINGS[i];
        out.push(
            verdict.ok_or_else(|| format!("no verdict for {} {}", level.name(), mode.name()))?,
        );
    }
    out.try_into().map_err(|_| "six verdicts".to_owned())
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        let _ = writeln!(out, "[statement]\n{}\n", self.statement);
        let _ = writeln!(out, "[archive]");
        for line in &self.archive_text {
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(out, "\n[verdict]");
        for line in self.verdict_lines() {
            let _ = writeln!(out, "{line}");
        }
        for (reader, version, reading) in &self.readings {
            let _ = write!(out, "\n[{} {version}]\n{reading}", reader.name());
        }
        f.write_str(&out)
    }
}
