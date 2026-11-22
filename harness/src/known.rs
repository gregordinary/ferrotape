//! Readings a reader's newer release is known to give otherwise.
//!
//! A reader's newer release can read a case otherwise than the release the
//! catalog pins. Where that change is understood and the pin stays, the
//! change is written to a known-changes file exactly as `check` reports it,
//! and `check --known FILE` reports a change the file holds as known rather
//! than failing on it.
//!
//! A change is matched by its case, its reader, the newer reading and the
//! recorded reading, and not by the newer release's version. A later release
//! that reads the case the same way is therefore known too. A different
//! reading, or a case recorded again, is a change the file does not hold.
//!
//! The file holds the blocks `check` prints, separated by blank lines, and
//! may open with comment lines beginning with `#`.

/// The key a change is matched by: `check`'s report of it without the newer
/// release's version.
///
/// `reading` and `recorded` are as `check` prints them, each ending in a line
/// end: the newer reading, then the recorded reader, its version and its
/// reading, or `nothing`.
#[must_use]
pub fn key(case: &str, reader: &str, reading: &str, recorded: &str) -> String {
    format!("{case}: {reader} now reads:\n{reading}recorded, {recorded}")
}

/// The keys of the changes a known-changes file holds.
///
/// # Errors
///
/// A line before the first change that is neither blank nor a comment.
pub fn parse(text: &str) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    let mut current: Option<(String, Vec<&str>)> = None;
    for (number, line) in text.lines().enumerate() {
        if let Some(header) = header(line) {
            if let Some(block) = current.take() {
                keys.push(finish(block));
            }
            current = Some((header, Vec::new()));
        } else if let Some((_, body)) = current.as_mut() {
            body.push(line);
        } else if !line.trim().is_empty() && !line.starts_with('#') {
            return Err(format!(
                "line {}: expected a change as `check` reports it",
                number.saturating_add(1)
            ));
        }
    }
    if let Some(block) = current {
        keys.push(finish(block));
    }
    Ok(keys)
}

/// A change's first line without the version, if `line` is one:
/// `CASE: READER VERSION now reads:`.
fn header(line: &str) -> Option<String> {
    let rest = line.strip_suffix(" now reads:")?;
    let (case, rest) = rest.split_once(": ")?;
    if !case.ends_with(".case") {
        return None;
    }
    let (reader, version) = rest.split_once(' ')?;
    if reader.is_empty() || version.is_empty() || version.contains(' ') {
        return None;
    }
    Some(format!("{case}: {reader} now reads:"))
}

/// A change's key from its first line and the lines after it, the blank
/// lines that separate it from the next left out.
fn finish((header, mut body): (String, Vec<&str>)) -> String {
    while body.last().is_some_and(|line| line.trim().is_empty()) {
        body.pop();
    }
    let mut key = header;
    key.push('\n');
    for line in body {
        key.push_str(line);
        key.push('\n');
    }
    key
}

#[cfg(test)]
mod tests {
    use super::{key, parse};

    const READING: &str = "member type=0 path=sp size=1024\nmember type=0 path=tail size=6\nok\n";
    const RECORDED: &str = "python 3.12.3:\nmember type=0 path=sp size=1024\nok\n";

    /// `check`'s report of a change, as it prints it.
    fn report(version: &str, reading: &str) -> String {
        format!(
            "catalog/sparse/a.case: python {version} now reads:\n{reading}recorded, {RECORDED}\n"
        )
    }

    #[test]
    fn a_reported_change_is_its_own_key() {
        let keys = parse(&report("3.15.2", READING)).unwrap();
        assert_eq!(
            keys,
            [key("catalog/sparse/a.case", "python", READING, RECORDED)]
        );
    }

    #[test]
    fn a_later_release_reading_the_same_is_known() {
        let keys = parse(&report("3.15.2", READING)).unwrap();
        assert!(keys.contains(&key("catalog/sparse/a.case", "python", READING, RECORDED)));
        let later = parse(&report("3.16.0", READING)).unwrap();
        assert_eq!(keys, later);
    }

    #[test]
    fn another_reading_or_record_is_not() {
        let keys = parse(&report("3.15.2", READING)).unwrap();
        let other = "member type=0 path=sp size=2048\nok\n";
        assert!(!keys.contains(&key("catalog/sparse/a.case", "python", other, RECORDED)));
        assert!(!keys.contains(&key("catalog/sparse/a.case", "go", READING, RECORDED)));
        assert!(!keys.contains(&key("catalog/sparse/b.case", "python", READING, RECORDED)));
        let recorded = "python 3.12.3:\nmember type=0 path=sp size=2048\nok\n";
        assert!(!keys.contains(&key("catalog/sparse/a.case", "python", READING, recorded)));
    }

    #[test]
    fn several_changes_and_comments() {
        let text = format!(
            "# Known.\n\n{}{}",
            report("3.15.2", READING),
            report("3.15.2", "ok\n").replace("sparse/a", "sparse/b")
        );
        let keys = parse(&text).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[1],
            key("catalog/sparse/b.case", "python", "ok\n", RECORDED)
        );
    }

    #[test]
    fn text_before_the_first_change_is_refused() {
        assert!(parse("member type=0\n").is_err());
        assert_eq!(parse("# nothing yet\n\n").unwrap(), Vec::<String>::new());
    }
}
