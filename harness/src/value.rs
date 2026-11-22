//! Byte strings as the catalog writes them, and the words a line is made of.
//!
//! A value is either bare, a run of printable ASCII holding no space, `"` or
//! `\`, which stands for itself; or one or more quoted pieces written with no
//! space between them, each `"` text `"`, optionally followed by `*` and a
//! count, which repeats it. Inside quotes, `\\`, `\"`, `\n`, `\r`, `\t`, `\0`
//! and `\xNN` are escapes, as in a Rust string, and any other byte stands for
//! itself. `"a"*99"/file"` is 99 `a`s followed by `/file`.

use std::fmt::Write as _;

/// Splits a line into its words: runs of characters separated by spaces,
/// where a space inside quotes belongs to its word.
pub fn words(line: &str) -> Result<Vec<&str>, String> {
    let mut words = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            i += 1;
            continue;
        }
        let start = i;
        let mut quoted = false;
        while i < bytes.len() && (quoted || bytes[i] != b' ') {
            match bytes[i] {
                b'"' => quoted = !quoted,
                b'\\' if quoted => i += 1,
                _ => {}
            }
            i += 1;
        }
        if quoted {
            return Err(format!("an unterminated quote in `{line}`"));
        }
        words.push(&line[start..i.min(bytes.len())]);
    }
    Ok(words)
}

/// Splits `key=value` at its first `=` outside quotes.
pub fn split_pair(word: &str) -> Option<(&str, &str)> {
    let bytes = word.as_bytes();
    let mut quoted = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => i += 1,
            b'=' if !quoted => return Some((&word[..i], &word[i + 1..])),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Whether `byte` may stand in a bare value.
fn is_bare(byte: u8) -> bool {
    (0x21..0x7f).contains(&byte) && byte != b'"' && byte != b'\\'
}

/// The bytes a value stands for.
pub fn parse(text: &str) -> Result<Vec<u8>, String> {
    if !text.starts_with('"') {
        if text.is_empty() || !text.bytes().all(is_bare) {
            return Err(format!("`{text}` is neither bare nor quoted"));
        }
        return Ok(text.as_bytes().to_vec());
    }
    let mut out = Vec::new();
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix(b"\"") else {
            return Err(format!("`{text}`: expected a quoted piece"));
        };
        let mut piece = Vec::new();
        let mut i = 0;
        loop {
            let Some(&byte) = after.get(i) else {
                return Err(format!("`{text}`: an unterminated quote"));
            };
            i += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escape = after.get(i).copied();
                    i += 1;
                    piece.push(match escape {
                        Some(b'\\') => b'\\',
                        Some(b'"') => b'"',
                        Some(b'n') => b'\n',
                        Some(b'r') => b'\r',
                        Some(b't') => b'\t',
                        Some(b'0') => 0,
                        Some(b'x') => {
                            let digits = after
                                .get(i..i + 2)
                                .and_then(|d| std::str::from_utf8(d).ok())
                                .and_then(|d| u8::from_str_radix(d, 16).ok())
                                .ok_or_else(|| format!("`{text}`: a bad \\x escape"))?;
                            i += 2;
                            digits
                        }
                        _ => return Err(format!("`{text}`: an unknown escape")),
                    });
                }
                _ => piece.push(byte),
            }
        }
        rest = &after[i..];
        let mut count = 1;
        if let Some(after_star) = rest.strip_prefix(b"*") {
            let digits = after_star.iter().take_while(|b| b.is_ascii_digit()).count();
            count = std::str::from_utf8(&after_star[..digits])
                .ok()
                .and_then(|d| d.parse::<usize>().ok())
                .ok_or_else(|| format!("`{text}`: a bad repeat count"))?;
            rest = &after_star[digits..];
        }
        for _ in 0..count {
            out.extend_from_slice(&piece);
        }
    }
    Ok(out)
}

/// A run of one byte this long or longer is written as a repeated piece.
const RUN: usize = 16;

/// Writes `bytes` as a value: bare where it can be, and quoted otherwise,
/// long runs of one byte as a repeated piece.
pub fn render(bytes: &[u8]) -> String {
    if !bytes.is_empty() && bytes.len() < RUN * 4 && bytes.iter().copied().all(is_bare) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    quoted(bytes)
}

/// Writes `bytes` quoted, whether or not it could be bare.
pub fn quoted(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "\"\"".to_owned();
    }
    let mut out = String::new();
    let mut open = false;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        let run = bytes[i..].iter().take_while(|&&b| b == byte).count();
        if run >= RUN {
            if open {
                out.push('"');
            }
            out.push('"');
            escape(byte, bytes.get(i + 1).copied(), &mut out);
            let _ = write!(out, "\"*{run}");
            open = false;
            i += run;
            continue;
        }
        if !open {
            out.push('"');
            open = true;
        }
        escape(byte, bytes.get(i + 1).copied(), &mut out);
        i += 1;
    }
    if open {
        out.push('"');
    }
    out
}

/// Writes one byte inside quotes. A NUL is `\0` unless a digit follows,
/// where `\x00` reads unambiguously.
fn escape(byte: u8, next: Option<u8>, out: &mut String) {
    match byte {
        b'\\' => out.push_str("\\\\"),
        b'"' => out.push_str("\\\""),
        b'\n' => out.push_str("\\n"),
        b'\r' => out.push_str("\\r"),
        b'\t' => out.push_str("\\t"),
        0 if !next.is_some_and(|b| b.is_ascii_digit()) => out.push_str("\\0"),
        0x20..=0x7e => out.push(char::from(byte)),
        _ => {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        let cases: &[&[u8]] = &[
            b"",
            b"d/f",
            b"hello\n",
            b"caf\xe9",
            b"abc\0def",
            b"\x001",
            b"a b",
            b"quote\"back\\slash",
            &[b'a'; 99],
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/file",
        ];
        for &bytes in cases {
            let text = render(bytes);
            assert_eq!(parse(&text).unwrap(), bytes, "{text}");
            let text = quoted(bytes);
            assert_eq!(parse(&text).unwrap(), bytes, "{text}");
        }
    }

    #[test]
    fn pieces_and_repeats() {
        assert_eq!(parse("\"a\"*3\"/f\"").unwrap(), b"aaa/f");
        assert_eq!(render(&[b'G'; 600]), "\"G\"*600");
        assert_eq!(render(b"\x89PNG"), "\"\\x89PNG\"");
        assert_eq!(quoted(b"\0"), "\"\\0\"");
    }

    #[test]
    fn words_keep_quoted_spaces() {
        assert_eq!(
            words("header name=\"a b\" size=1").unwrap(),
            ["header", "name=\"a b\"", "size=1"]
        );
        assert_eq!(split_pair("name=\"a=b\""), Some(("name", "\"a=b\"")));
        assert_eq!(split_pair("\"k=\"=v"), Some(("\"k=\"", "v")));
    }
}
