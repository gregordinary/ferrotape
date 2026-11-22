//! Running the reference readers over an archive, and turning what each
//! reports into a reading.
//!
//! GNU tar and bsdtar are run as commands and read through their verbose
//! listings; GNU tar's regular files' data through an extraction to a
//! command, this program's `gnu-data`. Python's `tarfile` and Go's
//! `archive/tar` are run through the small drivers in `drivers/`, which print
//! each member's fields in hexadecimal. Each command is found on `PATH`, or
//! where an environment variable names it: `FERROTAPE_GNU_TAR`,
//! `FERROTAPE_BSDTAR`, `FERROTAPE_PYTHON`, `FERROTAPE_GO`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::case::Reader;
use crate::reading::{Data, End, Member, Reading};

/// The directory the drivers are in.
fn drivers() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("drivers")
}

/// The environment variable that names `reader`'s command, and the command
/// found on `PATH` where it is not set.
fn names(reader: Reader) -> (&'static str, &'static str) {
    match reader {
        Reader::GnuTar => ("FERROTAPE_GNU_TAR", "tar"),
        Reader::Bsdtar => ("FERROTAPE_BSDTAR", "bsdtar"),
        Reader::Python => ("FERROTAPE_PYTHON", "python3"),
        Reader::Go => ("FERROTAPE_GO", "go"),
    }
}

/// A command with the environment every reader runs in: the C locale, so
/// messages do not vary, and UTC, so listed times do not.
fn command(program: impl Into<OsString>) -> Command {
    let mut command = Command::new(program.into());
    command.env("LC_ALL", "C").env("TZ", "UTC");
    command
}

/// A command that runs `reader`. GNU tar begins each message with the name
/// it was run by, so GNU tar and bsdtar named by a path run under their
/// plain names, and their messages read alike wherever they are installed.
/// An interpreter is run by the name it was given, since Python finds its
/// own library from it.
fn reader_command(reader: Reader) -> Command {
    let (variable, default) = names(reader);
    let mut command = command(std::env::var_os(variable).unwrap_or_else(|| default.into()));
    if matches!(reader, Reader::GnuTar | Reader::Bsdtar) {
        plain_name(&mut command, default);
    }
    command
}

#[cfg(unix)]
fn plain_name(command: &mut Command, name: &str) {
    use std::os::unix::process::CommandExt as _;
    command.arg0(name);
}

#[cfg(not(unix))]
fn plain_name(_: &mut Command, _: &str) {}

fn run(mut command: Command) -> Result<Output, String> {
    command
        .output()
        .map_err(|e| format!("running {command:?}: {e}"))
}

/// The reference readers, ready to read: their versions found, and Go's
/// driver built.
pub struct Readers {
    scratch: PathBuf,
    versions: Vec<(Reader, String)>,
    go_driver: PathBuf,
}

impl Readers {
    /// Finds each reader's version and builds Go's driver, in `scratch`, a
    /// directory the readers may write in.
    pub fn new(scratch: &Path) -> Result<Readers, String> {
        fs::create_dir_all(scratch).map_err(|e| e.to_string())?;
        let mut versions = Vec::new();
        for reader in Reader::ALL {
            versions.push((reader, version(reader)?));
        }
        let go_driver = scratch.join("archive-tar");
        let mut build = reader_command(Reader::Go);
        build
            .arg("build")
            .arg("-o")
            .arg(&go_driver)
            .arg(drivers().join("archive_tar.go"));
        let output = run(build)?;
        if !output.status.success() {
            return Err(format!(
                "building the Go driver: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(Readers {
            scratch: scratch.to_owned(),
            versions,
            go_driver,
        })
    }

    /// The version of `reader` that reads.
    pub fn version(&self, reader: Reader) -> &str {
        self.versions
            .iter()
            .find(|(r, _)| *r == reader)
            .map_or("", |(_, v)| v.as_str())
    }

    /// Every reader's reading of `archive`.
    pub fn read(&self, archive: &[u8]) -> Result<Vec<(Reader, String, Reading)>, String> {
        self.read_in(&self.scratch.join("case"), archive)
    }

    /// Every reader's reading of `archive`, in `dir`, a directory of the
    /// caller's that the readers may write in and that is emptied first, so
    /// that several threads can read at once, each in its own.
    pub fn read_in(
        &self,
        dir: &Path,
        archive: &[u8],
    ) -> Result<Vec<(Reader, String, Reading)>, String> {
        if dir.exists() {
            fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
        }
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        fs::write(dir.join("case.tar"), archive).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for reader in Reader::ALL {
            let reading = match reader {
                Reader::GnuTar => gnu_tar(dir)?,
                Reader::Bsdtar => bsdtar(dir)?,
                Reader::Python => {
                    let mut c = reader_command(Reader::Python);
                    c.arg("-I")
                        .arg(drivers().join("tarfile_reader.py"))
                        .arg("case.tar")
                        .env("LC_ALL", "C.UTF-8")
                        .current_dir(dir);
                    driver(c)?
                }
                Reader::Go => {
                    let mut c = command(&self.go_driver);
                    c.arg("case.tar").current_dir(dir);
                    driver(c)?
                }
            };
            out.push((reader, self.version(reader).to_owned(), reading));
        }
        Ok(out)
    }
}

/// The version a reader reports.
fn version(reader: Reader) -> Result<String, String> {
    let mut c = reader_command(reader);
    match reader {
        Reader::GnuTar | Reader::Bsdtar => c.arg("--version"),
        Reader::Python => c
            .arg("-I")
            .arg("-c")
            .arg("import platform; print(platform.python_version())"),
        Reader::Go => c.arg("version"),
    };
    let output = run(c)?;
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next().unwrap_or_default();
    let words: Vec<&str> = first.split_whitespace().collect();
    let version = match reader {
        // `tar (GNU tar) 1.35`
        Reader::GnuTar => words.last().copied(),
        // `bsdtar 3.8.11 - libarchive 3.8.11 ...`
        Reader::Bsdtar => words.get(1).copied(),
        Reader::Python => words.first().copied(),
        // `go version go1.27.0 linux/amd64`
        Reader::Go => words.get(2).and_then(|w| w.strip_prefix("go")),
    };
    version
        .map(str::to_owned)
        .ok_or_else(|| format!("{} reports no version: {first}", reader.name()))
}

/// Decodes hexadecimal.
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("`{text}`: odd hexadecimal"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Encodes hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A driver's reading: lines of tab-separated fields, `member` with
/// typeflag, path, link target, size, device major and minor, mode, mtime,
/// uid, gid, uname, gname and data (`-` for none), the text ones in
/// hexadecimal; then `ok`, or `error` and a message.
fn driver(command: Command) -> Result<Reading, String> {
    let output = run(command)?;
    if !output.stderr.is_empty() {
        return Err(format!(
            "a driver wrote to standard error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    let mut members = Vec::new();
    let mut end = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            [
                "member",
                t,
                path,
                link,
                size,
                major,
                minor,
                mode,
                mtime,
                uid,
                gid,
                uname,
                gname,
                data,
            ] => {
                let number = |s: &str| s.parse::<i128>().map_err(|e| format!("`{line}`: {e}"));
                let typeflag = *unhex(t)?.first().unwrap_or(&0);
                let link = unhex(link)?;
                let device = matches!(typeflag, b'3' | b'4');
                members.push(Member {
                    typeflag: Some(typeflag),
                    path: unhex(path)?,
                    link: (!link.is_empty()).then_some(link),
                    size: Some(number(size)?),
                    device: if device {
                        Some((number(major)?, number(minor)?))
                    } else {
                        None
                    },
                    mode: Some(number(mode)?),
                    mtime: Some(mtime.parse().map_err(|e| format!("`{line}`: {e}"))?),
                    uid: Some(number(uid)?),
                    gid: Some(number(gid)?),
                    uname: Some(unhex(uname)?),
                    gname: Some(unhex(gname)?),
                    data: if *data == "-" {
                        None
                    } else {
                        Some(Data::of(&unhex(data)?))
                    },
                    ..Member::default()
                });
            }
            ["ok"] => end = Some(End::Ok),
            ["error", message] => end = Some(End::Error(unhex(message)?)),
            _ => return Err(format!("a driver's line `{line}`")),
        }
    }
    Ok(Reading {
        members,
        warnings: Vec::new(),
        end: end.ok_or("a driver's reading that does not end")?,
    })
}

/// Undoes the escaping GNU tar's `--quoting-style=escape` and bsdtar apply
/// to a listed name: C's escapes, and three octal digits for any other byte.
fn unescape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text[i] != b'\\' || i + 1 >= text.len() {
            out.push(text[i]);
            i += 1;
            continue;
        }
        let next = text[i + 1];
        let octal = text
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        if let Some(digits) = octal {
            let value = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            out.push(value as u8);
            i += 4;
            continue;
        }
        let byte = match next {
            b'\\' => b'\\',
            b'a' => 0x07,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 0x0b,
            b' ' => b' ',
            _ => {
                out.push(b'\\');
                i += 1;
                continue;
            }
        };
        out.push(byte);
        i += 2;
    }
    out
}

/// The fields of a listing's line before its name: GNU tar's verbose listing
/// has five (mode, owner, size, date, time), bsdtar's eight (mode, links,
/// owner, group, size, month, day, year or time). Returns them and the name,
/// which follows the last field and one space.
fn split_listing(line: &[u8], fields: usize) -> Option<(Vec<&[u8]>, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < fields {
        while line.get(i) == Some(&b' ') {
            i += 1;
        }
        let start = i;
        while i < line.len() && line[i] != b' ' {
            i += 1;
        }
        if start == i {
            return None;
        }
        out.push(&line[start..i]);
    }
    let name = line.get(i + 1..).unwrap_or_default();
    Some((out, name))
}

/// A listing's members.
fn listing(stdout: &[u8], reader: Reader) -> Result<Vec<Member>, String> {
    let (fields, size_field) = match reader {
        Reader::GnuTar => (5, 2),
        _ => (8, 4),
    };
    let mut members = Vec::new();
    // GNU tar pads its time column to the widest time it has shown so far,
    // with spaces after the time, and they are not part of a name.
    let mut time_width = 0;
    for line in stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let unreadable = || {
            format!(
                "{}: an unreadable listing line `{}`",
                reader.name(),
                line.escape_ascii()
            )
        };
        let (mut columns, mut name) = split_listing(line, fields).ok_or_else(unreadable)?;
        // GNU tar shows a time it cannot write as a date as one number, in
        // place of the date and the time.
        if reader == Reader::GnuTar {
            let time = if is_date(columns[3]) {
                columns[3].len() + 1 + columns[4].len()
            } else {
                (columns, name) = split_listing(line, fields - 1).ok_or_else(unreadable)?;
                columns[3].len()
            };
            time_width = time_width.max(time);
            let padding = time_width - time;
            if name.len() < padding || name[..padding].iter().any(|&b| b != b' ') {
                return Err(unreadable());
            }
            name = &name[padding..];
        }
        let listed = columns[0][0];
        let mode = listed_mode(columns[0]).ok_or_else(unreadable)?;
        // A device's numbers stand where a size would, as `major,minor`.
        let column = std::str::from_utf8(columns[size_field]).unwrap_or_default();
        let size = column.parse().ok();
        let device = column
            .split_once(',')
            .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)));
        let mut name = name.to_vec();
        let mut note = None;
        if reader == Reader::GnuTar {
            let label = b"--Volume Header--";
            if let Some(stripped) = name.strip_suffix(label) {
                note = Some(label.to_vec());
                name = stripped.to_vec();
            }
            if let Some(at) = find(&name, b"--Continued at byte ") {
                note = Some(name[at..].to_vec());
                name.truncate(at);
            }
            if let Some(at) = find(&name, b" unknown file type ") {
                note = Some(name[at + 1..].to_vec());
                name.truncate(at);
            }
        }
        // A symbolic link is listed with `->`, a hard link with `link to`;
        // bsdtar lists a hard link that declares data with the mode of a
        // regular file, so the mode does not say which.
        let mut link = None;
        let arrow: &[u8] = if listed == b'l' {
            b" -> "
        } else {
            b" link to "
        };
        if let Some(at) = find(&name, arrow) {
            link = Some(unescape(&name[at + arrow.len()..]));
            name.truncate(at);
        }
        members.push(Member {
            listed: Some(listed),
            path: unescape(&name),
            link,
            size,
            device,
            mode: Some(mode),
            note,
            ..Member::default()
        });
    }
    Ok(members)
}

/// The twelve permission bits a listing's mode column shows: its type
/// character, then `r`, `w` and `x` or `-` for the owner, the group and
/// others, `s` or `S` in the owner's and the group's execute place for
/// setuid and setgid with and without execute, and `t` or `T` in others' for
/// sticky. bsdtar appends `+` where the member carries an access control
/// list. `None` for any other column.
fn listed_mode(column: &[u8]) -> Option<i128> {
    let column = column.strip_suffix(b"+").unwrap_or(column);
    let [_, places @ ..] = column else {
        return None;
    };
    let places: &[u8; 9] = places.try_into().ok()?;
    let mut mode = 0;
    for (class, triple) in places.chunks(3).enumerate() {
        let shift = 6 - 3 * class;
        let special = [0o4000, 0o2000, 0o1000][class];
        let (set, unset) = [(b's', b'S'), (b's', b'S'), (b't', b'T')][class];
        match triple[0] {
            b'r' => mode |= 0o4 << shift,
            b'-' => {}
            _ => return None,
        }
        match triple[1] {
            b'w' => mode |= 0o2 << shift,
            b'-' => {}
            _ => return None,
        }
        match triple[2] {
            b'x' => mode |= 0o1 << shift,
            b'-' => {}
            byte if byte == set => mode |= special | 0o1 << shift,
            byte if byte == unset => mode |= special,
            _ => return None,
        }
    }
    Some(mode)
}

/// Whether a listing's column is a date, `YYYY-MM-DD`, its year of any
/// length and sign.
fn is_date(column: &[u8]) -> bool {
    let digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
    let column = column.strip_prefix(b"-").unwrap_or(column);
    let parts: Vec<&[u8]> = column.split(|&b| b == b'-').collect();
    matches!(parts.as_slice(), [year, month, day]
        if digits(year) && month.len() == 2 && digits(month) && day.len() == 2 && digits(day))
}

/// Where `needle` first appears in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A command's standard error, line by line.
fn warnings(stderr: &[u8]) -> Vec<Vec<u8>> {
    stderr
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn status(output: &Output) -> End {
    End::Exit(output.status.code().unwrap_or(-1))
}

/// GNU tar's reading: its verbose listing, and each regular file's data from
/// an extraction to `gnu-data`, matched to the listing's members by name in
/// order.
fn gnu_tar(dir: &Path) -> Result<Reading, String> {
    let mut list = reader_command(Reader::GnuTar);
    list.args([
        "--numeric-owner",
        "--full-time",
        "--quoting-style=escape",
        "-tvf",
        "case.tar",
    ])
    .current_dir(dir);
    let output = run(list)?;
    let mut members = listing(&output.stdout, Reader::GnuTar)?;

    let data_file = dir.join("data");
    fs::write(&data_file, b"").map_err(|e| e.to_string())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut extract = reader_command(Reader::GnuTar);
    extract
        .arg("-xf")
        .arg("case.tar")
        .arg(format!(
            "--to-command='{}' gnu-data",
            me.display().to_string().replace('\'', "'\\''")
        ))
        .env("FERROTAPE_GNU_DATA", &data_file)
        .current_dir(dir);
    run(extract)?;
    let text = fs::read_to_string(&data_file).map_err(|e| e.to_string())?;
    let mut extracted: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for line in text.lines() {
        let (name, data) = line.split_once('\t').ok_or("a bad gnu-data line")?;
        extracted.push((unhex(name)?, unhex(data)?));
    }
    // GNU tar runs the command for what it extracts as a regular file: a
    // member it lists as one, as contiguous or as of an unknown type, named
    // as it extracts it. It extracts an absolute name without the leading
    // slashes it reports removing, and does not extract a name holding `..`
    // at all, though it reports removing that prefix too.
    let warnings = warnings(&output.stderr);
    let removed: Vec<Vec<u8>> = crate::reading::removed_prefixes(&warnings, "member names")
        .into_iter()
        .filter(|prefix| prefix.iter().all(|byte| *byte == b'/'))
        .collect();
    for member in &mut members {
        if !matches!(member.listed, Some(b'-' | b'C' | b'?')) {
            continue;
        }
        let named = |name: &Vec<u8>| {
            *name == member.path
                || removed
                    .iter()
                    .any(|prefix| member.path.strip_prefix(prefix.as_slice()) == Some(name))
        };
        if let Some(at) = extracted.iter().position(|(name, _)| named(name)) {
            let (_, data) = extracted.remove(at);
            member.data = Some(Data::of(&data));
        }
    }
    Ok(Reading {
        members,
        warnings,
        end: status(&output),
    })
}

/// bsdtar's reading: its verbose listing.
fn bsdtar(dir: &Path) -> Result<Reading, String> {
    let mut list = reader_command(Reader::Bsdtar);
    list.args(["--numeric-owner", "-tvf", "case.tar"])
        .current_dir(dir);
    let output = run(list)?;
    Ok(Reading {
        members: listing(&output.stdout, Reader::Bsdtar)?,
        warnings: warnings(&output.stderr),
        end: status(&output),
    })
}

/// What `gnu-data` does, run by GNU tar for each regular file it extracts:
/// appends the member's name and data, in hexadecimal, to the file
/// `FERROTAPE_GNU_DATA` names.
pub fn gnu_data() -> Result<(), String> {
    use std::io::{Read as _, Write as _};
    let mut data = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let name = std::env::var_os("TAR_FILENAME").unwrap_or_default();
    let name = name_bytes(&name);
    let out = std::env::var_os("FERROTAPE_GNU_DATA").ok_or("FERROTAPE_GNU_DATA is not set")?;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(out)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{}\t{}", hex(&name), hex(&data)).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    name.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_names_are_unescaped() {
        assert_eq!(unescape(b"caf\\351"), b"caf\xe9");
        assert_eq!(unescape(b"a\\\\b"), b"a\\b");
        assert_eq!(unescape(b"tab\\there"), b"tab\there");
    }

    #[test]
    fn listed_modes_are_read_as_their_permission_bits() {
        for (column, mode) in [
            (&b"-rw-r--r--"[..], 0o644),
            (b"-rwsr-xr-x", 0o4755),
            (b"-rwSr--r--", 0o4644),
            (b"drwxrwsr-x", 0o2775),
            (b"drwxr-Sr-x", 0o2745),
            (b"drwxrwxrwt", 0o1777),
            (b"drwxrwxrwT", 0o1776),
            (b"----------", 0),
            (b"-rwxr--r-x+", 0o745),
            (b"d---------+", 0),
            (b"crw-r--r--", 0o644),
            (b"?rw-r--r--", 0o644),
        ] {
            assert_eq!(listed_mode(column), Some(mode), "{}", column.escape_ascii());
        }
        for column in [
            &b"-rw-r--r-"[..],
            b"-rw-r--r--x",
            b"-rwxr-xr-q",
            b"-rtxr-xr-x",
            b"",
        ] {
            assert_eq!(listed_mode(column), None, "{}", column.escape_ascii());
        }
    }

    #[test]
    fn listings_split_into_fields_and_a_name() {
        let gnu = b"hrw-r--r-- 0/0               0 1970-01-01 00:00:00 d/h link to d/f";
        let members = listing(gnu, Reader::GnuTar).unwrap();
        assert_eq!(members[0].path, b"d/h");
        assert_eq!(members[0].link.as_deref(), Some(&b"d/f"[..]));
        let bsd = b"crw-r--r--  0 0      0         1,3 Jan  1  1970 chr";
        let members = listing(bsd, Reader::Bsdtar).unwrap();
        assert_eq!(members[0].path, b"chr");
        assert_eq!(members[0].size, None);
        let empty = b"-rw-r--r-- 0/0               0 1970-01-01 00:00:00 ";
        assert_eq!(listing(empty, Reader::GnuTar).unwrap()[0].path, b"");
        let far = b"-rw-r--r-- 0/0               2 -9223372036854775808 v7file\n\
            -rw-r--r-- 0/0               0 1970-01-01 00:00:00  after\n\
            -rw-r--r-- 0/0               0 1970-01-01 00:00:00   space";
        let members = listing(far, Reader::GnuTar).unwrap();
        assert_eq!(members[0].path, b"v7file");
        assert_eq!(members[0].size, Some(2));
        assert_eq!(members[1].path, b"after");
        assert_eq!(members[2].path, b" space");
        let label = b"Vrw-r--r-- 0/0               0 1970-01-01 00:00:00 VOLUME--Volume Header--";
        let members = listing(label, Reader::GnuTar).unwrap();
        assert_eq!(members[0].path, b"VOLUME");
        assert_eq!(members[0].note.as_deref(), Some(&b"--Volume Header--"[..]));
    }
}
