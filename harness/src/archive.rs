//! A case's archive, written as items, and the bytes it stands for.
//!
//! Each line of an `[archive]` section is one item, and the archive is the
//! items' bytes in order. `header` writes one header block from its fields;
//! `data` and `records` write a body, padded to whole blocks; `bytes` writes
//! bytes as they are, unpadded; `zeros` writes zero blocks and `end` the two
//! of an end marker. `pax`, `global`, `longname` and `longlink` each write a
//! metadata member, its header and its body. The catalog's README describes
//! each field.

use std::fmt;

use crate::value;

/// The size of a block.
pub const BLOCK: usize = 512;

/// The magic and version a header carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Magic {
    /// POSIX: `ustar\0` and the version `00`.
    Ustar,
    /// GNU: `ustar ` and ` \0`.
    Gnu,
    /// None: a pre-POSIX v7 header, nothing written past the link name.
    V7,
}

/// How a header's checksum is written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checksum {
    /// The sum of the block's bytes as unsigned, as POSIX specifies.
    Unsigned,
    /// The sum of the block's bytes as signed, as some historical writers
    /// computed it.
    Signed,
    /// One more than the unsigned sum, matching neither.
    Bad,
}

/// What a numeric field holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Number {
    /// The value in octal, zero-padded, ending in a NUL.
    Octal(u64),
    /// The value in GNU's base-256 form: two's complement, big-endian, the
    /// first byte's high bit set.
    Base256(i64),
    /// The field's bytes as given.
    Raw(Vec<u8>),
}

/// One header block's fields, as a `header` item sets them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// `name`, at offset 0.
    pub name: Vec<u8>,
    /// `mode`; `0o644` unless set.
    pub mode: Number,
    /// `uid`.
    pub uid: Number,
    /// `gid`.
    pub gid: Number,
    /// `size`; `None` takes the length of a body that follows directly, and
    /// zero where none does.
    pub size: Option<Number>,
    /// `mtime`.
    pub mtime: Number,
    /// How the checksum is written.
    pub checksum: Checksum,
    /// `typeflag`; `0` unless set.
    pub typeflag: u8,
    /// `linkname`.
    pub linkname: Vec<u8>,
    /// The magic, and with it which fields past offset 257 are written.
    pub magic: Magic,
    /// `uname`; `root` unless set.
    pub uname: Vec<u8>,
    /// `gname`; `root` unless set.
    pub gname: Vec<u8>,
    /// `devmajor`.
    pub devmajor: Number,
    /// `devminor`.
    pub devminor: Number,
    /// `prefix`, written in a POSIX header only.
    pub prefix: Vec<u8>,
    /// Bytes written at an offset after every field: `@345="pre"`.
    pub raw: Vec<(usize, Vec<u8>)>,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            name: Vec::new(),
            mode: Number::Octal(0o644),
            uid: Number::Octal(0),
            gid: Number::Octal(0),
            size: None,
            mtime: Number::Octal(0),
            checksum: Checksum::Unsigned,
            typeflag: b'0',
            linkname: Vec::new(),
            magic: Magic::Ustar,
            uname: b"root".to_vec(),
            gname: b"root".to_vec(),
            devmajor: Number::Octal(0),
            devminor: Number::Octal(0),
            prefix: Vec::new(),
            raw: Vec::new(),
        }
    }
}

/// A pax record: its key and its value.
pub type Record = (Vec<u8>, Vec<u8>);

/// One item of an archive.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Item {
    /// A header block.
    Header(Box<Header>),
    /// A body, padded to whole blocks.
    Data(Vec<u8>),
    /// A body of pax records, each `key=value`, framed by its length and
    /// padded to whole blocks.
    Records(Vec<Record>),
    /// Bytes as they are, unpadded.
    Bytes(Vec<u8>),
    /// This many zero blocks.
    Zeros(usize),
}

/// A case's archive: its items, and the lines they were read from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Archive {
    /// The items, the shorthands expanded.
    pub items: Vec<Item>,
}

/// An item that could not be read, with its line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArchiveError {
    /// The line, as written.
    pub line: String,
    /// What is wrong with it.
    pub reason: String,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`: {}", self.line, self.reason)
    }
}

impl Archive {
    /// Reads an `[archive]` section's lines, comments and blank lines
    /// already removed.
    pub fn parse(lines: &[&str]) -> Result<Archive, ArchiveError> {
        let mut items = Vec::new();
        for &line in lines {
            parse_item(line, &mut items).map_err(|reason| ArchiveError {
                line: line.to_owned(),
                reason,
            })?;
        }
        Ok(Archive { items })
    }

    /// The archive's bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (index, item) in self.items.iter().enumerate() {
            match item {
                Item::Header(header) => {
                    let body = match self.items.get(index + 1) {
                        Some(Item::Data(data)) => data.len(),
                        Some(Item::Records(records)) => frame(records).len(),
                        _ => 0,
                    };
                    out.extend_from_slice(&block(header, body as u64));
                }
                Item::Data(data) => padded(data, &mut out),
                Item::Records(records) => padded(&frame(records), &mut out),
                Item::Bytes(bytes) => out.extend_from_slice(bytes),
                Item::Zeros(count) => out.resize(out.len() + count * BLOCK, 0),
            }
        }
        out
    }
}

impl Archive {
    /// The items in their written form, one line each, which [`Archive::parse`]
    /// reads back as items that build the same bytes. A field the header's
    /// magic does not write is left out.
    pub fn lines(&self) -> Vec<String> {
        self.items.iter().map(item_line).collect()
    }
}

/// One item's line.
fn item_line(item: &Item) -> String {
    match item {
        Item::Header(header) => header_line(header),
        Item::Data(data) => format!("data {}", value::quoted(data)),
        Item::Records(records) => {
            let mut line = String::from("records");
            for (key, text) in records {
                // A pair splits at its first `=` outside quotes.
                let key = if key.contains(&b'=') || key.is_empty() {
                    value::quoted(key)
                } else {
                    value::render(key)
                };
                line.push_str(&format!(" {key}={}", value::render(text)));
            }
            line
        }
        Item::Bytes(bytes) => format!("bytes {}", value::quoted(bytes)),
        Item::Zeros(2) => "end".to_owned(),
        Item::Zeros(count) => format!("zeros {count}"),
    }
}

/// A numeric field's written value: octal for a mode, decimal otherwise.
fn number_text(number: &Number, octal: bool) -> String {
    match number {
        Number::Octal(v) if octal => format!("0o{v:o}"),
        Number::Octal(v) => v.to_string(),
        Number::Base256(v) => format!("base256:{v}"),
        Number::Raw(bytes) => value::quoted(bytes),
    }
}

/// A header's line: `header` and each field that differs from its default.
fn header_line(header: &Header) -> String {
    let default = Header::default();
    let mut fields = Vec::new();
    let mut text = |key: &str, bytes: &[u8], unless: &[u8]| {
        if bytes != unless {
            fields.push(format!("{key}={}", value::render(bytes)));
        }
    };
    text("name", &header.name, &default.name);
    text("linkname", &header.linkname, &default.linkname);
    if header.magic != Magic::V7 {
        text("uname", &header.uname, &default.uname);
        text("gname", &header.gname, &default.gname);
    }
    if header.magic == Magic::Ustar {
        text("prefix", &header.prefix, &default.prefix);
    }
    if header.typeflag != default.typeflag {
        fields.push(format!("typeflag={}", value::render(&[header.typeflag])));
    }
    let mut numbers = vec![
        ("mode", &header.mode, &default.mode, true),
        ("uid", &header.uid, &default.uid, false),
        ("gid", &header.gid, &default.gid, false),
        ("mtime", &header.mtime, &default.mtime, false),
    ];
    if header.magic != Magic::V7 {
        numbers.push(("devmajor", &header.devmajor, &default.devmajor, false));
        numbers.push(("devminor", &header.devminor, &default.devminor, false));
    }
    for (key, number, unless, octal) in numbers {
        if number != unless {
            fields.push(format!("{key}={}", number_text(number, octal)));
        }
    }
    if let Some(size) = &header.size {
        fields.push(format!("size={}", number_text(size, false)));
    }
    match header.magic {
        Magic::Ustar => {}
        Magic::Gnu => fields.push("magic=gnu".to_owned()),
        Magic::V7 => fields.push("magic=v7".to_owned()),
    }
    match header.checksum {
        Checksum::Unsigned => {}
        Checksum::Signed => fields.push("checksum=signed".to_owned()),
        Checksum::Bad => fields.push("checksum=bad".to_owned()),
    }
    for (offset, bytes) in &header.raw {
        fields.push(format!("@{offset}={}", value::quoted(bytes)));
    }
    let mut line = String::from("header");
    for field in fields {
        line.push(' ');
        line.push_str(&field);
    }
    line
}

/// Appends `data` and the zeros that pad it to a whole block.
fn padded(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(BLOCK), 0);
}

/// Pax records framed by their lengths: `<length> <key>=<value>\n`, the
/// length counting itself.
pub fn frame(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in records {
        let body = key.len() + value.len() + 3;
        let mut length = body + 1;
        while length.to_string().len() + body != length {
            length += 1;
        }
        out.extend_from_slice(length.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(key);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out
}

/// Writes `bytes` into `block` at `offset`, cut to `width`.
fn put(block: &mut [u8; BLOCK], offset: usize, width: usize, bytes: &[u8]) {
    let n = bytes.len().min(width);
    block[offset..offset + n].copy_from_slice(&bytes[..n]);
}

/// A numeric field's bytes, `width` wide.
fn number(value: &Number, width: usize) -> Vec<u8> {
    match value {
        Number::Octal(v) => {
            let mut text = format!("{v:0digits$o}", digits = width - 1).into_bytes();
            text.push(0);
            text
        }
        Number::Base256(v) => {
            let full = v.to_be_bytes();
            let mut field = vec![if *v < 0 { 0xff } else { 0 }; width.saturating_sub(8)];
            field.extend_from_slice(&full[8usize.saturating_sub(width)..]);
            field[0] |= 0x80;
            field
        }
        Number::Raw(bytes) => bytes.clone(),
    }
}

/// One header block, `body` the length of the body that follows it.
fn block(header: &Header, body: u64) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    put(&mut block, 0, 100, &header.name);
    put(&mut block, 100, 8, &number(&header.mode, 8));
    put(&mut block, 108, 8, &number(&header.uid, 8));
    put(&mut block, 116, 8, &number(&header.gid, 8));
    let size = header.size.clone().unwrap_or(Number::Octal(body));
    put(&mut block, 124, 12, &number(&size, 12));
    put(&mut block, 136, 12, &number(&header.mtime, 12));
    block[156] = header.typeflag;
    put(&mut block, 157, 100, &header.linkname);
    match header.magic {
        Magic::Ustar => put(&mut block, 257, 8, b"ustar\x0000"),
        Magic::Gnu => put(&mut block, 257, 8, b"ustar  \x00"),
        Magic::V7 => {}
    }
    if header.magic != Magic::V7 {
        put(&mut block, 265, 32, &header.uname);
        put(&mut block, 297, 32, &header.gname);
        put(&mut block, 329, 8, &number(&header.devmajor, 8));
        put(&mut block, 337, 8, &number(&header.devminor, 8));
    }
    if header.magic == Magic::Ustar {
        put(&mut block, 345, 155, &header.prefix);
    }
    for (offset, bytes) in &header.raw {
        put(&mut block, *offset, BLOCK - offset, bytes);
    }
    block[148..156].fill(b' ');
    let total: i64 = match header.checksum {
        Checksum::Unsigned => block.iter().map(|&b| i64::from(b)).sum(),
        Checksum::Signed => block.iter().map(|&b| i64::from(b as i8)).sum(),
        Checksum::Bad => block.iter().map(|&b| i64::from(b)).sum::<i64>() + 1,
    };
    let text = format!("{:06o}\0 ", total & 0o777777);
    block[148..156].copy_from_slice(text.as_bytes());
    block
}

/// Reads one line into items, expanding a shorthand into the items it
/// stands for.
fn parse_item(line: &str, items: &mut Vec<Item>) -> Result<(), String> {
    let words = value::words(line)?;
    let (&kind, rest) = words.split_first().ok_or("an empty item")?;
    match kind {
        "header" => items.push(Item::Header(Box::new(header(rest, Header::default())?))),
        "data" | "bytes" => {
            let [text] = rest else {
                return Err(format!("`{kind}` takes one value"));
            };
            let bytes = value::parse(text)?;
            items.push(if kind == "data" {
                Item::Data(bytes)
            } else {
                Item::Bytes(bytes)
            });
        }
        "records" => items.push(Item::Records(records(rest)?)),
        "zeros" => {
            let [count] = rest else {
                return Err("`zeros` takes a count".to_owned());
            };
            let count = count.parse().map_err(|_| "a bad count")?;
            items.push(Item::Zeros(count));
        }
        "end" => {
            if !rest.is_empty() {
                return Err("`end` takes nothing".to_owned());
            }
            items.push(Item::Zeros(2));
        }
        "pax" | "global" => {
            let typeflag = if kind == "pax" { b'x' } else { b'g' };
            let base = Header {
                name: b"PaxHeader".to_vec(),
                typeflag,
                ..Header::default()
            };
            items.push(Item::Header(Box::new(base)));
            items.push(Item::Records(records(rest)?));
        }
        "longname" | "longlink" => {
            let [text] = rest else {
                return Err(format!("`{kind}` takes one value"));
            };
            let mut data = value::parse(text)?;
            data.push(0);
            items.push(Item::Header(Box::new(Header {
                name: b"././@LongLink".to_vec(),
                typeflag: if kind == "longname" { b'L' } else { b'K' },
                magic: Magic::Gnu,
                ..Header::default()
            })));
            items.push(Item::Data(data));
        }
        other => return Err(format!("no item is called `{other}`")),
    }
    Ok(())
}

/// `key=value` words as pax records.
fn records(words: &[&str]) -> Result<Vec<Record>, String> {
    words
        .iter()
        .map(|word| {
            let (key, text) =
                value::split_pair(word).ok_or_else(|| format!("`{word}` is not key=value"))?;
            Ok((value::parse(key)?, value::parse(text)?))
        })
        .collect()
}

/// A numeric field's value: a decimal or `0o` octal number, `base256:` and a
/// signed decimal, or quoted bytes.
fn parse_number(text: &str) -> Result<Number, String> {
    if text.starts_with('"') {
        return value::parse(text).map(Number::Raw);
    }
    if let Some(v) = text.strip_prefix("base256:") {
        return v
            .parse()
            .map(Number::Base256)
            .map_err(|_| format!("`{text}`: a bad number"));
    }
    let parsed = match text.strip_prefix("0o") {
        Some(octal) => u64::from_str_radix(octal, 8),
        None => text.parse(),
    };
    parsed
        .map(Number::Octal)
        .map_err(|_| format!("`{text}`: a bad number"))
}

/// A header's fields over `base`.
fn header(words: &[&str], mut header: Header) -> Result<Header, String> {
    for word in words {
        let (key, text) =
            value::split_pair(word).ok_or_else(|| format!("`{word}` is not field=value"))?;
        match key {
            "name" => header.name = value::parse(text)?,
            "mode" => header.mode = parse_number(text)?,
            "uid" => header.uid = parse_number(text)?,
            "gid" => header.gid = parse_number(text)?,
            "size" => header.size = Some(parse_number(text)?),
            "mtime" => header.mtime = parse_number(text)?,
            "checksum" => {
                header.checksum = match text {
                    "unsigned" => Checksum::Unsigned,
                    "signed" => Checksum::Signed,
                    "bad" => Checksum::Bad,
                    _ => return Err(format!("no checksum is `{text}`")),
                }
            }
            "typeflag" => {
                let bytes = value::parse(text)?;
                let [byte] = bytes[..] else {
                    return Err("a typeflag is one byte".to_owned());
                };
                header.typeflag = byte;
            }
            "linkname" => header.linkname = value::parse(text)?,
            "magic" => {
                header.magic = match text {
                    "ustar" => Magic::Ustar,
                    "gnu" => Magic::Gnu,
                    "v7" => Magic::V7,
                    _ => return Err(format!("no magic is `{text}`")),
                }
            }
            "uname" => header.uname = value::parse(text)?,
            "gname" => header.gname = value::parse(text)?,
            "devmajor" => header.devmajor = parse_number(text)?,
            "devminor" => header.devminor = parse_number(text)?,
            "prefix" => header.prefix = value::parse(text)?,
            raw if raw.starts_with('@') => {
                let offset: usize = raw[1..].parse().map_err(|_| format!("`{raw}`"))?;
                if offset >= BLOCK {
                    return Err(format!("offset {offset} is past the block"));
                }
                header.raw.push((offset, value::parse(text)?));
            }
            other => return Err(format!("no header field is `{other}`")),
        }
    }
    let past_v7 = !header.uname.is_empty() && header.uname != b"root"
        || !header.gname.is_empty() && header.gname != b"root"
        || header.devmajor != Number::Octal(0)
        || header.devminor != Number::Octal(0);
    if header.magic == Magic::V7 && past_v7 {
        return Err("a v7 header has no field past the link name".to_owned());
    }
    if header.magic != Magic::Ustar && !header.prefix.is_empty() {
        return Err("only a POSIX header has a prefix; write its bytes with @345".to_owned());
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(lines: &[&str]) -> Vec<u8> {
        Archive::parse(lines).unwrap().build()
    }

    #[test]
    fn a_header_takes_the_length_of_the_body_after_it() {
        let bytes = build(&["header name=f", "data \"hello\\n\"", "end"]);
        assert_eq!(bytes.len(), 4 * BLOCK);
        assert_eq!(&bytes[124..136], b"00000000006\0");
        assert_eq!(&bytes[BLOCK..BLOCK + 6], b"hello\n");
    }

    #[test]
    fn records_frame_their_lengths() {
        assert_eq!(frame(&[(b"path".to_vec(), b"x".to_vec())]), b"9 path=x\n");
        // A record whose length gains a digit when its own digits are
        // counted: 98 bytes after them make 101, not 100.
        let long = vec![b'v'; 94];
        let framed = frame(&[(b"k".to_vec(), long)]);
        assert_eq!(&framed[..4], b"101 ");
        assert_eq!(framed.len(), 101);
    }

    #[test]
    fn base256_fields() {
        assert_eq!(
            number(&Number::Base256(5), 12),
            b"\x80\0\0\0\0\0\0\0\0\0\0\x05"
        );
        assert_eq!(
            number(&Number::Base256(-86400), 12),
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xae\x80"
        );
    }

    #[test]
    fn a_v7_header_writes_nothing_past_the_link_name() {
        let bytes = build(&["header name=v magic=v7"]);
        assert!(bytes[257..].iter().all(|&b| b == 0));
        assert!(Archive::parse(&["header magic=v7 uname=u"]).is_err());
    }
}
