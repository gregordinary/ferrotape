//! The writer and the reader together: every header the writer encodes
//! reads back as it was set, at each level and in each global-header mode,
//! its data included, but for setuid, setgid or sticky beside an access
//! list, which Strict refuses as documented; a header the writer refuses
//! writes nothing, and the archive goes on.
//!
//! The input steers a generator of up to four members. Their text fields are
//! drawn mostly from an alphabet that reaches each of the writer's rules (the
//! field lengths, `/`, a NUL, `=`, `%`, a newline, bytes that are not UTF-8)
//! and sometimes from any byte; numbers mostly near the limits of the fields
//! that hold them, and sometimes anywhere in their range.

#![no_main]
#![forbid(unsafe_code)]

use ferrotape::{
    Entry, EntryKind, ErrorKind, GlobalHeaders, Header, Level, Reader, Timestamp, WriteError,
    Writer,
};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;

/// What a text field is mostly made of. `a` dominates so that long single
/// components occur; a NUL is one byte in twenty-five.
const ALPHABET: &[u8] = b"aaaaaaaaab-./////=% \n\xc3\xa9\xff\0";

/// Keywords a caller might add records under: some the writer passes
/// through, some it derives itself or refuses.
const KEYWORDS: &[&[u8]] = &[
    b"comment",
    b"SCHILY.acl.access",
    b"SCHILY.acl.default",
    b"SCHILY.fflags",
    b"VENDOR.record",
    b"path",
    b"size",
    b"mtime",
    b"hdrcharset",
    b"SCHILY.xattr.user.k",
    b"LIBARCHIVE.xattr.user.k",
    b"RHT.security.selinux",
    b"GNU.sparse.size",
];

#[derive(Debug)]
struct Spec {
    kind: EntryKind,
    path: Vec<u8>,
    target: Vec<u8>,
    size: u64,
    device: (u32, u32),
    mode: u32,
    owner: (u32, u32),
    names: (Vec<u8>, Vec<u8>),
    mtime: Timestamp,
    atime: Option<Timestamp>,
    ctime: Option<Timestamp>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

fn text(u: &mut Unstructured<'_>, longest: usize) -> Result<Vec<u8>> {
    let length = u.int_in_range(0..=longest)?;
    let any = u.ratio(1, 8)?;
    (0..length)
        .map(|_| {
            if any {
                u.arbitrary::<u8>()
            } else {
                u.choose(ALPHABET).copied()
            }
        })
        .collect()
}

/// A number near one of `edges`, or, now and then, any.
fn near(u: &mut Unstructured<'_>, edges: &[u64]) -> Result<u64> {
    if u.ratio(1, 8)? {
        return u.arbitrary();
    }
    let edge = *u.choose(edges)?;
    let offset = u.int_in_range(0..=2u64)?;
    Ok(if u.arbitrary()? {
        edge.saturating_add(offset)
    } else {
        edge.saturating_sub(offset)
    })
}

/// An id or a device number: the edges of seven and eight octal digits and
/// of the 32-bit range.
fn id(u: &mut Unstructured<'_>) -> Result<u32> {
    let value = near(u, &[0, 0o7777777, 0o77777777, u64::from(u32::MAX)])?;
    Ok(u32::try_from(value).unwrap_or(u32::MAX))
}

fn time(u: &mut Unstructured<'_>) -> Result<Timestamp> {
    let edges = [0, 1 << 31, (1 << 33) - 1, 1 << 33, 10_000_000_000];
    let magnitude = near(u, &edges)?;
    let magnitude = i64::try_from(magnitude).unwrap_or(i64::MAX);
    let secs = if u.ratio(1, 4)? {
        -magnitude
    } else {
        magnitude
    };
    let nanos = if u.ratio(1, 2)? {
        0
    } else {
        u.int_in_range(0..=999_999_999)?
    };
    Ok(Timestamp::new(secs, nanos).unwrap_or(Timestamp::from_secs(secs)))
}

fn spec(u: &mut Unstructured<'_>) -> Result<Spec> {
    let kind = *u.choose(&[
        EntryKind::File,
        EntryKind::Directory,
        EntryKind::Symlink,
        EntryKind::HardLink,
        EntryKind::CharDevice,
        EntryKind::BlockDevice,
        EntryKind::Fifo,
    ])?;
    let path = text(u, 300)?;
    let target = match kind {
        EntryKind::Symlink | EntryKind::HardLink => text(u, 120)?,
        _ => Vec::new(),
    };
    let size = match kind {
        EntryKind::File => u.int_in_range(0..=1500)?,
        _ => 0,
    };
    let device = match kind {
        EntryKind::CharDevice | EntryKind::BlockDevice => (id(u)?, id(u)?),
        _ => (0, 0),
    };
    let mode = if u.ratio(1, 16)? {
        u.arbitrary()?
    } else {
        u.int_in_range(0..=0o7777)?
    };
    let owner = (id(u)?, id(u)?);
    let names = (text(u, 40)?, text(u, 40)?);
    let mtime = time(u)?;
    let atime = if u.ratio(1, 4)? { Some(time(u)?) } else { None };
    let ctime = if u.ratio(1, 4)? { Some(time(u)?) } else { None };
    let mut xattrs = Vec::new();
    for _ in 0..u.int_in_range(0..=3)? {
        let mut name = if u.ratio(3, 4)? {
            b"user.".to_vec()
        } else {
            Vec::new()
        };
        name.extend(text(u, 20)?);
        let value = if u.arbitrary()? {
            text(u, 40)?
        } else {
            let length = u.int_in_range(0..=40)?;
            (0..length)
                .map(|_| u.arbitrary::<u8>())
                .collect::<Result<_>>()?
        };
        xattrs.push((name, value));
    }
    let mut records = Vec::new();
    for _ in 0..u.int_in_range(0..=2)? {
        let keyword = if u.ratio(3, 4)? {
            u.choose(KEYWORDS)?.to_vec()
        } else {
            text(u, 20)?
        };
        records.push((keyword, text(u, 60)?));
    }
    Ok(Spec {
        kind,
        path,
        target,
        size,
        device,
        mode,
        owner,
        names,
        mtime,
        atime,
        ctime,
        xattrs,
        records,
    })
}

impl Spec {
    fn header(&self) -> Header {
        let path = self.path.clone();
        let mut header = match self.kind {
            EntryKind::Directory => Header::directory(path),
            EntryKind::Symlink => Header::symlink(path, self.target.clone()),
            EntryKind::HardLink => Header::hard_link(path, self.target.clone()),
            EntryKind::CharDevice => Header::char_device(path, self.device.0, self.device.1),
            EntryKind::BlockDevice => Header::block_device(path, self.device.0, self.device.1),
            EntryKind::Fifo => Header::fifo(path),
            _ => Header::file(path, self.size),
        };
        header
            .set_mode(self.mode)
            .set_owner(self.owner.0, self.owner.1)
            .set_owner_names(self.names.0.clone(), self.names.1.clone())
            .set_mtime(self.mtime);
        if let Some(atime) = self.atime {
            header.set_atime(atime);
        }
        if let Some(ctime) = self.ctime {
            header.set_ctime(ctime);
        }
        for (name, value) in &self.xattrs {
            header.add_xattr(name.clone(), value.clone());
        }
        for (keyword, value) in &self.records {
            header.add_record(keyword.clone(), value.clone());
        }
        header
    }

    /// The member's data: bytes that differ from block to block, so a
    /// misframed read shows.
    fn data(&self) -> Vec<u8> {
        (0..self.size).map(|at| (at % 251) as u8).collect()
    }

    /// Whether Strict refuses the member: setuid, setgid or sticky beside an
    /// access list, which the writer writes as GNU tar does.
    fn strict_refuses(&self) -> bool {
        self.mode & 0o7000 != 0
            && self
                .records
                .iter()
                .any(|(keyword, _)| keyword == b"SCHILY.acl.access")
    }

    fn check(&self, entry: &Entry) {
        assert_eq!(entry.kind(), self.kind, "{self:?}");
        assert_eq!(entry.path(), self.path, "{self:?}");
        assert_eq!(entry.link_target(), self.target, "{self:?}");
        assert_eq!(entry.size(), self.size, "{self:?}");
        assert_eq!(entry.mode(), self.mode, "{self:?}");
        assert_eq!((entry.uid(), entry.gid()), self.owner, "{self:?}");
        assert_eq!(
            (entry.uname(), entry.gname()),
            (&self.names.0[..], &self.names.1[..]),
            "{self:?}",
        );
        assert_eq!(entry.mtime(), self.mtime, "{self:?}");
        assert_eq!(entry.atime(), self.atime, "{self:?}");
        assert_eq!(entry.ctime(), self.ctime, "{self:?}");
        let device = match self.kind {
            EntryKind::CharDevice | EntryKind::BlockDevice => Some(self.device),
            _ => None,
        };
        assert_eq!(entry.device(), device, "{self:?}");
        let xattrs: Vec<(Vec<u8>, Vec<u8>)> = entry
            .pax_records()
            .xattrs()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(xattrs, self.xattrs, "{self:?}");
        for (keyword, value) in &self.records {
            assert_eq!(
                entry.pax_records().get(keyword),
                Some(&value[..]),
                "{self:?}",
            );
        }
        // The block alone, as a reader that ignores pax records reads it:
        // never a directory's name on anything else, never empty.
        let block = entry.header_block();
        let name = block[..100].split(|byte| *byte == 0).next().unwrap_or(&[]);
        assert!(!name.is_empty(), "{self:?}");
        assert_eq!(
            name.ends_with(b"/"),
            self.kind == EntryKind::Directory && self.path.ends_with(b"/"),
            "{self:?}",
        );
        // Nor a POSIX prefix ending in `/`, which bsdtar joins differently.
        let prefix = block[345..500]
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or(&[]);
        assert!(!prefix.ends_with(b"/"), "{self:?}");
    }
}

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    let mut specs = Vec::new();
    while specs.len() < 4 && !u.is_empty() {
        match spec(&mut u) {
            Ok(spec) => specs.push(spec),
            Err(_) => break,
        }
    }

    let mut writer = Writer::new(Vec::new());
    let mut written = Vec::new();
    for spec in specs {
        let header = spec.header();
        let encoded = header.encode();
        assert_eq!(header.encode(), encoded, "encoding is deterministic");
        let before = writer.get_ref().len();
        match writer.append(&header, &spec.data()[..]) {
            Ok(()) => {
                assert!(encoded.is_ok(), "{spec:?}");
                written.push(spec);
            }
            Err(WriteError::Header(err)) => {
                assert_eq!(Err(err), encoded, "{spec:?}");
                assert_eq!(
                    writer.get_ref().len(),
                    before,
                    "a refused header writes nothing"
                );
            }
            Err(other) => panic!("{spec:?}: {other}"),
        }
    }
    let archive = writer.finish().expect("writing to memory");
    assert_eq!(archive.len() % 512, 0);

    for level in [Level::Strict, Level::Compatible] {
        'setting: for mode in [
            GlobalHeaders::Refuse,
            GlobalHeaders::Apply,
            GlobalHeaders::Defer,
        ] {
            let mut reader = Reader::new(&archive[..])
                .with_level(level)
                .with_global_headers(mode);
            for spec in &written {
                if level == Level::Strict && spec.strict_refuses() {
                    let err = reader.next_entry().expect_err("Strict refuses it");
                    assert_eq!(err.kind(), &ErrorKind::SpecialBitsWithAcl, "{spec:?}");
                    // A refusal is final.
                    continue 'setting;
                }
                let entry = reader
                    .next_entry()
                    .unwrap_or_else(|err| panic!("{level:?} {mode:?} {spec:?}: {err}"))
                    .expect("a member for each header written");
                spec.check(&entry);
                assert_eq!(reader.read_entry(spec.size).unwrap(), spec.data());
            }
            assert!(reader.next_entry().unwrap().is_none());
            reader.finish(512).unwrap();
        }
    }
});
