//! The writer: every header it encodes reads back through the reader as set,
//! and what it refuses.

use std::io::{self, Read, Seek, SeekFrom, Write};

use ferrotape::{
    Entry, EntryKind, ErrorKind, GlobalHeaders, Header, HeaderError, Level, Reader, TextField,
    Timestamp, WriteError, Writer,
};

/// A member to write, and what reading it back must give.
#[derive(Clone, Debug)]
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

impl Spec {
    /// Whether Strict refuses the member: setuid, setgid or sticky beside an
    /// access list, which the writer writes as GNU tar does.
    fn strict_refuses(&self) -> bool {
        self.mode & 0o7000 != 0
            && self
                .records
                .iter()
                .any(|(keyword, _)| keyword == b"SCHILY.acl.access")
    }

    fn new(kind: EntryKind, path: impl Into<Vec<u8>>) -> Spec {
        let mode = match kind {
            EntryKind::Directory => 0o755,
            EntryKind::Symlink => 0o777,
            _ => 0o644,
        };
        let target = match kind {
            EntryKind::Symlink | EntryKind::HardLink => b"target".to_vec(),
            _ => Vec::new(),
        };
        Spec {
            kind,
            path: path.into(),
            target,
            size: 0,
            device: (0, 0),
            mode,
            owner: (0, 0),
            names: (Vec::new(), Vec::new()),
            mtime: Timestamp::from_secs(0),
            atime: None,
            ctime: None,
            xattrs: Vec::new(),
            records: Vec::new(),
        }
    }

    fn file(path: impl Into<Vec<u8>>, size: u64) -> Spec {
        Spec {
            size,
            ..Spec::new(EntryKind::File, path)
        }
    }

    fn header(&self) -> Header {
        let path = self.path.clone();
        let mut header = match self.kind {
            EntryKind::File => Header::file(path, self.size),
            EntryKind::Directory => Header::directory(path),
            EntryKind::Symlink => Header::symlink(path, self.target.clone()),
            EntryKind::HardLink => Header::hard_link(path, self.target.clone()),
            EntryKind::CharDevice => Header::char_device(path, self.device.0, self.device.1),
            EntryKind::BlockDevice => Header::block_device(path, self.device.0, self.device.1),
            EntryKind::Fifo => Header::fifo(path),
            other => panic!("no constructor for {other:?}"),
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

    fn check(&self, entry: &Entry) {
        let what = format!("{:?}", self.path.escape_ascii().to_string());
        assert_eq!(entry.kind(), self.kind, "{what}");
        assert_eq!(entry.path(), self.path, "{what}");
        assert_eq!(entry.link_target(), self.target, "{what}");
        assert_eq!(entry.size(), self.size, "{what}");
        assert_eq!(entry.mode(), self.mode, "{what}");
        assert_eq!((entry.uid(), entry.gid()), self.owner, "{what}");
        assert_eq!(
            (entry.uname(), entry.gname()),
            (&self.names.0[..], &self.names.1[..]),
            "{what}",
        );
        assert_eq!(entry.mtime(), self.mtime, "{what}");
        assert_eq!(entry.atime(), self.atime, "{what}");
        assert_eq!(entry.ctime(), self.ctime, "{what}");
        let device = match self.kind {
            EntryKind::CharDevice | EntryKind::BlockDevice => Some(self.device),
            _ => None,
        };
        assert_eq!(entry.device(), device, "{what}");
        let xattrs: Vec<(Vec<u8>, Vec<u8>)> = entry
            .pax_records()
            .xattrs()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(xattrs, self.xattrs, "{what}");
        for (keyword, value) in &self.records {
            assert_eq!(entry.pax_records().get(keyword), Some(&value[..]), "{what}");
        }
        // The block alone, as a reader that ignores pax records reads it:
        // never a directory's name on anything else, never empty.
        let block = entry.header_block();
        let name = until_nul(&block[0..100]);
        assert!(!name.is_empty(), "{what}");
        let looks_like_directory = name.ends_with(b"/");
        assert_eq!(
            looks_like_directory,
            self.kind == EntryKind::Directory && self.path.ends_with(b"/"),
            "{what}: {}",
            name.escape_ascii(),
        );
    }
}

fn until_nul(field: &[u8]) -> &[u8] {
    field.split(|byte| *byte == 0).next().unwrap()
}

/// `specs` written as one archive.
fn archive(specs: &[Spec]) -> Vec<u8> {
    let mut writer = Writer::new(Vec::new());
    for spec in specs {
        writer.append(&spec.header(), &spec.data()[..]).unwrap();
    }
    writer.finish().unwrap()
}

/// Reads `specs`, written as one archive, back at every level and in every
/// global-header mode, each member as its spec states it, its data included;
/// at Strict, up to a member with setuid, setgid or sticky beside an access
/// list, which Strict refuses.
fn round_trip(specs: &[Spec]) {
    let archive = archive(specs);
    for level in [Level::Strict, Level::Compatible] {
        'setting: for mode in [
            GlobalHeaders::Refuse,
            GlobalHeaders::Apply,
            GlobalHeaders::Defer,
        ] {
            let mut reader = Reader::new(&archive[..])
                .with_level(level)
                .with_global_headers(mode);
            for spec in specs {
                if level == Level::Strict && spec.strict_refuses() {
                    let err = reader.next_entry().unwrap_err();
                    assert_eq!(err.kind(), &ErrorKind::SpecialBitsWithAcl, "{spec:?}");
                    continue 'setting;
                }
                let entry = reader
                    .next_entry()
                    .unwrap_or_else(|err| panic!("{spec:?}: {err}"))
                    .expect("a member");
                spec.check(&entry);
                assert_eq!(reader.read_entry(spec.size).unwrap(), spec.data());
            }
            assert!(reader.next_entry().unwrap().is_none());
            // The end marker's second block is past the first.
            reader.finish(512).unwrap();
        }
    }
}

#[test]
fn every_kind_reads_back_as_written() {
    let mut device = Spec::new(EntryKind::CharDevice, "dev/null");
    device.device = (1, 3);
    let mut block = Spec::new(EntryKind::BlockDevice, "dev/sda");
    block.device = (8, 0);
    let mut hard = Spec::new(EntryKind::HardLink, "second");
    hard.target = b"first".to_vec();
    round_trip(&[
        Spec::new(EntryKind::Directory, "dir/"),
        Spec::new(EntryKind::Directory, "no-slash"),
        Spec::file("first", 5),
        Spec::file("empty", 0),
        Spec::file("two-blocks", 1024),
        Spec::file("partial", 513),
        hard,
        Spec::new(EntryKind::Symlink, "link"),
        device,
        block,
        Spec::new(EntryKind::Fifo, "fifo"),
    ]);
}

#[test]
fn a_header_the_block_holds_needs_no_extended_header() {
    let mut spec = Spec::file("plain", 3);
    spec.mode = 0o4755;
    spec.owner = (2_097_151, 1000);
    spec.names = (b"user".to_vec(), b"group".to_vec());
    spec.mtime = Timestamp::from_secs((1 << 33) - 1);
    let blocks = spec.header().encode().unwrap();
    assert_eq!(blocks.len(), 512);
    assert_eq!(blocks[156], b'0');
    assert_eq!(&blocks[257..265], b"ustar\x0000");
    round_trip(&[spec]);
}

#[test]
fn paths_read_back_whatever_their_length() {
    let component = |byte: u8, length: usize| vec![byte; length];
    let mut specs = Vec::new();
    for length in [1, 99, 100, 101, 155, 156, 254, 255, 256, 257, 1000, 4096] {
        // One component, which no prefix split can hold past 100 bytes.
        specs.push(Spec::file(component(b'a', length), 1));
        // Twenty-byte components, which a split holds up to 256 bytes.
        let mut path = Vec::new();
        while path.len() < length {
            path.extend_from_slice(&component(b'b', 19));
            path.push(b'/');
        }
        path.truncate(length);
        if path.ends_with(b"/") {
            path.pop();
            path.push(b'c');
        }
        specs.push(Spec::file(path.clone(), 1));
        let mut directory = path.clone();
        directory.push(b'/');
        specs.push(Spec::new(EntryKind::Directory, directory));
        specs.push(Spec::new(EntryKind::Directory, path));
    }
    // A name past 100 bytes in a directory whose path fits the prefix; a
    // first component past the prefix's 155; leading, doubled and lone `/`s;
    // a component of 100 bytes exactly after a 155-byte prefix.
    specs.push(Spec::file(
        [&b"dir/"[..], &component(b'n', 120)].concat(),
        1,
    ));
    specs.push(Spec::file(
        [&component(b'p', 200)[..], b"/name"].concat(),
        1,
    ));
    specs.push(Spec::file([&b"/"[..], &component(b'r', 100)].concat(), 1));
    specs.push(Spec::file(
        [&b"/abs/"[..], &component(b's', 150)].concat(),
        1,
    ));
    specs.push(Spec::file(
        [&component(b'd', 60)[..], b"//", &component(b'e', 60)].concat(),
        1,
    ));
    specs.push(Spec::file(
        [&component(b'x', 155)[..], b"/", &component(b'y', 100)].concat(),
        1,
    ));
    specs.push(Spec::new(EntryKind::Directory, component(b'/', 300)));
    // Bytes that are not ASCII, and not UTF-8.
    specs.push(Spec::file("h\u{e9}llo", 1));
    specs.push(Spec::file(b"raw\xff\xfe".to_vec(), 1));
    specs.push(Spec::file(
        [&b"\xff"[..], &component(b'\xfe', 300)].concat(),
        1,
    ));
    round_trip(&specs);
}

#[test]
fn link_targets_read_back_whatever_their_length() {
    let mut specs = Vec::new();
    for length in [1, 100, 101, 4096] {
        let mut symlink = Spec::new(EntryKind::Symlink, format!("symlink-{length}"));
        symlink.target = vec![b't'; length];
        let mut hard = Spec::new(EntryKind::HardLink, format!("hard-{length}"));
        hard.target = vec![b'h'; length];
        specs.push(symlink);
        specs.push(hard);
    }
    round_trip(&specs);
}

#[test]
fn ids_and_owner_names_read_back_whatever_their_size() {
    let mut specs = Vec::new();
    for id in [0, 1, 2_097_151, 2_097_152, u32::MAX] {
        let mut spec = Spec::file(format!("id-{id}"), 0);
        spec.owner = (id, u32::MAX - id);
        specs.push(spec);
    }
    for length in [1, 31, 32, 100] {
        let mut spec = Spec::file(format!("name-{length}"), 0);
        spec.names = (vec![b'u'; length], vec![b'g'; length]);
        specs.push(spec);
    }
    let mut spec = Spec::file("names-not-utf-8", 0);
    spec.names = (b"\xffuser".to_vec(), "gr\u{f6}up".into());
    specs.push(spec);
    let mut spec = Spec::file("uname-only", 0);
    spec.names = (b"user".to_vec(), Vec::new());
    specs.push(spec);
    round_trip(&specs);
}

#[test]
fn times_read_back_to_the_nanosecond_before_1970_and_after_the_block_holds() {
    let times = [
        (0, 0),
        (1, 0),
        ((1 << 33) - 1, 0),
        (1 << 33, 0),
        (1_720_000_000, 123_456_789),
        (1_720_000_000, 500_000_000),
        (1_720_000_000, 1),
        (-1, 0),
        (-6, 0),
        (i64::MAX, 999_999_999),
        (i64::MIN, 0),
    ];
    let mut specs = Vec::new();
    for (index, (secs, nanos)) in times.into_iter().enumerate() {
        let time = Timestamp::new(secs, nanos).unwrap();
        let mut spec = Spec::file(format!("time-{index}"), 0);
        spec.mtime = time;
        spec.atime = Some(time);
        spec.ctime = Some(time);
        specs.push(spec);
    }
    round_trip(&specs);
}

#[test]
fn device_numbers_read_back() {
    let mut specs = Vec::new();
    for (major, minor) in [
        (0, 0),
        (1, 3),
        (4095, 1_048_575),
        (2_097_151, 2_097_151),
        (2_097_152, 3),
        (16_777_215, 16_777_215),
    ] {
        let mut spec = Spec::new(EntryKind::CharDevice, format!("c-{major}-{minor}"));
        spec.device = (major, minor);
        specs.push(spec);
        let mut spec = Spec::new(EntryKind::BlockDevice, format!("b-{major}-{minor}"));
        spec.device = (major, minor);
        specs.push(spec);
    }
    round_trip(&specs);
}

#[test]
fn extended_attributes_and_records_read_back() {
    let mut spec = Spec::file("attributes", 4);
    spec.xattrs = vec![
        (b"user.plain".to_vec(), b"value".to_vec()),
        (b"user.100%".to_vec(), b"raw percent".to_vec()),
        (b"user.sp ace".to_vec(), b"spaced".to_vec()),
        (b"user.\xff\xfe".to_vec(), b"\0binary\nvalue\xff".to_vec()),
        (b"user.new\nline".to_vec(), b"v".to_vec()),
        (
            b"security.capability".to_vec(),
            b"\x01\0\0\x02\x00\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
        ),
        (
            b"system.posix_acl_access".to_vec(),
            b"\x02\0\0\0list".to_vec(),
        ),
    ];
    spec.records = vec![
        (b"SCHILY.acl.access".to_vec(), b"user::rw-".to_vec()),
        (b"comment".to_vec(), b"a\nmulti-line comment".to_vec()),
        (b"APK-TOOLS.checksum.SHA1".to_vec(), b"0123".to_vec()),
        (b"vendor.new\nline".to_vec(), b"v".to_vec()),
    ];
    // A directory's lists as GNU tar writes them, an empty default one among
    // them.
    let mut directory = Spec::new(EntryKind::Directory, "listed/");
    directory.mode = 0o755;
    directory.records = vec![
        (b"SCHILY.acl.access".to_vec(), b"user::rwx".to_vec()),
        (b"SCHILY.acl.default".to_vec(), Vec::new()),
    ];
    round_trip(&[spec.clone(), directory]);

    let archive = archive(&[spec]);
    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    let acl = entry.pax_records().access_acl();
    assert_eq!(
        (acl.binary(), acl.text()),
        (Some(&b"\x02\0\0\0list"[..]), Some(&b"user::rw-"[..])),
    );
}

#[test]
fn sizes_past_the_octal_field_read_back() {
    // A source that holds the archive's header and end marker and reads as
    // zeros between, so a member of many gigabytes needs no memory.
    for size in [(1u64 << 33) - 1, 1 << 33, 1 << 40, (1 << 60) - 1] {
        let blocks = Header::file("big", size).encode().unwrap();
        let mut source = Hollow::new(blocks, size);
        let mut reader = Reader::seeking(&mut source);
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.size(), size);
        assert_eq!(entry.declared_size(), size);
        assert!(reader.next_entry().unwrap().is_none());
    }
}

/// An archive of one member: its header blocks, `size` bytes of zeros and
/// their padding, then the end marker, of which only the header and the
/// marker are held.
struct Hollow {
    header: Vec<u8>,
    end: u64,
    at: u64,
}

impl Hollow {
    fn new(header: Vec<u8>, size: u64) -> Hollow {
        let data_end = header.len() as u64 + size.next_multiple_of(512);
        Hollow {
            header,
            end: data_end + 1024,
            at: 0,
        }
    }
}

impl Read for Hollow {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let header_len = self.header.len() as u64;
        if self.at < header_len {
            let rest = &self.header[self.at as usize..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at += n as u64;
            return Ok(n);
        }
        let n = (self.end - self.at).min(buf.len() as u64) as usize;
        buf[..n].fill(0);
        self.at += n as u64;
        Ok(n)
    }
}

impl Seek for Hollow {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.at = match pos {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => self.end.checked_add_signed(delta).unwrap(),
            SeekFrom::Current(delta) => self.at.checked_add_signed(delta).unwrap(),
        };
        Ok(self.at)
    }
}

#[test]
fn a_header_that_cannot_read_back_as_set_is_refused() {
    let file = |path: &[u8]| Header::file(path.to_vec(), 0);
    let cases: Vec<(Header, HeaderError)> = vec![
        (file(b""), HeaderError::EmptyPath),
        (file(b"a\0b"), HeaderError::Nul(TextField::Path)),
        (file(b"dir/"), HeaderError::TrailingSlash),
        (Header::symlink("link/", "t"), HeaderError::TrailingSlash),
        (Header::symlink("link", ""), HeaderError::EmptyLinkTarget),
        (Header::hard_link("link", ""), HeaderError::EmptyLinkTarget),
        (
            Header::symlink("link", "a\0b"),
            HeaderError::Nul(TextField::LinkTarget),
        ),
        (
            file(b"f").set_owner_names("u\0", "g").clone(),
            HeaderError::Nul(TextField::Uname),
        ),
        (
            file(b"f").set_owner_names("u", "\0g").clone(),
            HeaderError::Nul(TextField::Gname),
        ),
        (
            file(b"f").set_mode(0o10000).clone(),
            HeaderError::Mode(0o10000),
        ),
        (
            file(b"f").set_mode(0o100644).clone(),
            HeaderError::Mode(0o100644),
        ),
        (
            Header::file("f", 1 << 60),
            HeaderError::SizeOutOfRange(1 << 60),
        ),
        (
            Header::file("f", u64::MAX - 510),
            HeaderError::SizeOutOfRange(u64::MAX - 510),
        ),
        (
            Header::char_device("c", 16_777_216, 0),
            HeaderError::DeviceOutOfRange {
                major: 16_777_216,
                minor: 0,
            },
        ),
        (
            Header::block_device("b", 0, u32::MAX),
            HeaderError::DeviceOutOfRange {
                major: 0,
                minor: u32::MAX,
            },
        ),
    ];
    for (header, expected) in cases {
        assert_eq!(header.encode(), Err(expected), "{header:?}");
    }
}

#[test]
fn an_attribute_name_no_spelling_reads_back_alike_is_refused() {
    for name in [
        &b""[..],
        b"user.eq=x",
        b"user.nul\0x",
        b"user.pct%25x",
        b"user.eq%3Dx",
    ] {
        let mut header = Header::file("f", 0);
        header.add_xattr(name, "v");
        assert_eq!(
            header.encode(),
            Err(HeaderError::XattrName {
                name: name.to_vec()
            }),
            "{}",
            name.escape_ascii(),
        );
    }
    // Go reads an empty value as the record's deletion; GNU tar and bsdtar
    // set an empty attribute.
    let mut header = Header::file("f", 0);
    header.add_xattr("user.empty", "");
    assert_eq!(
        header.encode(),
        Err(HeaderError::EmptyXattr {
            name: b"user.empty".to_vec()
        }),
    );
    let mut header = Header::file("f", 0);
    header
        .add_xattr("user.a", "1")
        .add_xattr("user.b", "2")
        .add_xattr("user.a", "1");
    assert_eq!(
        header.encode(),
        Err(HeaderError::RepeatedXattr {
            name: b"user.a".to_vec()
        }),
    );
}

#[test]
fn a_record_the_header_derives_or_readers_part_over_is_refused() {
    for keyword in [
        &b"path"[..],
        b"linkpath",
        b"size",
        b"uid",
        b"gid",
        b"uname",
        b"gname",
        b"mtime",
        b"atime",
        b"ctime",
        b"hdrcharset",
        b"SCHILY.devmajor",
        b"SCHILY.devminor",
        b"SCHILY.realsize",
        b"SCHILY.xattr.user.k",
        b"LIBARCHIVE.xattr.user.k",
        b"RHT.security.selinux",
        b"GNU.sparse.size",
        b"GNU.volume.label",
    ] {
        let mut header = Header::file("f", 0);
        header.add_record(keyword, "v");
        assert_eq!(
            header.encode(),
            Err(HeaderError::ReservedKeyword {
                keyword: keyword.to_vec()
            }),
            "{}",
            keyword.escape_ascii(),
        );
    }
    // A keyword beginning with a space or a tab is one GNU tar reads without
    // them, and the others with them.
    for keyword in [&b""[..], b"a=b", b"a\0b", b" comment", b"\tcomment"] {
        let mut header = Header::file("f", 0);
        header.add_record(keyword, "v");
        assert_eq!(
            header.encode(),
            Err(HeaderError::Keyword {
                keyword: keyword.to_vec()
            }),
        );
    }
    let mut header = Header::file("f", 0);
    header.add_record("comment", "a").add_record("comment", "a");
    assert_eq!(
        header.encode(),
        Err(HeaderError::RepeatedKeyword {
            keyword: b"comment".to_vec()
        }),
    );
    // Keywords that only begin like a reserved one are the caller's.
    let mut header = Header::file("f", 0);
    header
        .add_record("paths", "v")
        .add_record("SCHILY.xattrs", "v");
    assert!(header.encode().is_ok());
}

#[test]
fn setuid_setgid_or_sticky_beside_an_access_list_is_written_as_gnu_tar_writes_it() {
    // GNU tar keeps the three bits beside the list on extraction and bsdtar
    // drops them, so Strict refuses such a member, as `encode` documents;
    // Compatible reads it as set.
    let mut specs = Vec::new();
    for mode in [0o4755, 0o2775, 0o1777, 0o7777] {
        let mut spec = Spec::new(EntryKind::Directory, format!("listed-{mode:o}/"));
        spec.mode = mode;
        spec.records = vec![(
            b"SCHILY.acl.access".to_vec(),
            b"user::rwx,group::r-x,other::r-x".to_vec(),
        )];
        assert!(spec.header().encode().is_ok());
        specs.push(spec);
    }
    for spec in &specs {
        round_trip(std::slice::from_ref(spec));
        let archive = archive(std::slice::from_ref(spec));
        let err = Reader::new(&archive[..]).next_entry().unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::SpecialBitsWithAcl);
    }
    // Without the access list, or with a default list alone, or the list
    // with none of the three bits, Strict reads them too.
    let mut specs = Vec::new();
    for mode in [0o4755, 0o2775, 0o1777] {
        let mut spec = Spec::new(EntryKind::Directory, format!("plain-{mode:o}/"));
        spec.mode = mode;
        specs.push(spec);
        let mut spec = Spec::new(EntryKind::Directory, format!("default-{mode:o}/"));
        spec.mode = mode;
        spec.records = vec![(
            b"SCHILY.acl.default".to_vec(),
            b"user::rwx,group::r-x,other::r-x".to_vec(),
        )];
        specs.push(spec);
    }
    let mut spec = Spec::file("listed", 0);
    spec.mode = 0o755;
    spec.records = vec![(
        b"SCHILY.acl.access".to_vec(),
        b"user::rwx,group::r-x,other::r-x".to_vec(),
    )];
    specs.push(spec);
    assert!(specs.iter().all(|spec| !spec.strict_refuses()));
    round_trip(&specs);
}

#[test]
fn a_default_list_is_written_for_a_directory_alone() {
    // The reader refuses one on any other member: bsdtar reads such a member
    // with mode `000`, and the other readers with the header's mode.
    let headers = [
        Header::file("f", 0),
        Header::symlink("l", "t"),
        Header::hard_link("h", "t"),
        Header::char_device("c", 1, 3),
        Header::block_device("b", 8, 0),
        Header::fifo("p"),
    ];
    for value in [&b"user::rwx,group::r-x,other::r-x"[..], b""] {
        for mut header in headers.clone() {
            header.add_record("SCHILY.acl.default", value);
            assert_eq!(
                header.encode(),
                Err(HeaderError::DefaultAclWithoutDirectory),
                "{header:?}",
            );
        }
        let mut header = Header::directory("d/");
        header.add_record("SCHILY.acl.default", value);
        assert!(header.encode().is_ok());
    }
    assert_eq!(
        HeaderError::DefaultAclWithoutDirectory.to_string(),
        "a default access control list is given for a member that is not a directory",
    );
}

#[test]
fn an_extended_header_a_reader_would_refuse_by_default_is_refused() {
    let mut header = Header::file("f", 0);
    header.add_record("comment", vec![b'c'; 1 << 20]);
    assert_eq!(header.encode(), Err(HeaderError::MetadataTooLarge));
    let mut header = Header::file("f", 0);
    header.add_record("comment", vec![b'c'; (1 << 20) - 100]);
    assert!(header.encode().is_ok());
}

#[test]
fn errors_read_as_text() {
    assert_eq!(
        HeaderError::Nul(TextField::LinkTarget).to_string(),
        "the link target holds a NUL"
    );
    assert_eq!(
        HeaderError::Mode(0o100644).to_string(),
        "the mode 0o100644 has bits beyond the permission bits"
    );
    assert_eq!(
        WriteError::Header(HeaderError::EmptyPath).to_string(),
        "the header cannot be written: the path is empty"
    );
}

#[test]
fn a_header_refused_writes_nothing_and_the_archive_goes_on() {
    let mut writer = Writer::new(Vec::new());
    writer.append(&Header::file("a", 1), &b"a"[..]).unwrap();
    let written = writer.get_ref().len();
    let err = writer.append(&Header::file("", 1), &b"x"[..]).unwrap_err();
    assert!(matches!(err, WriteError::Header(HeaderError::EmptyPath)));
    assert_eq!(writer.get_ref().len(), written);
    writer.append(&Header::file("b", 1), &b"b"[..]).unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = Reader::new(&archive[..]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"a");
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"b");
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn into_inner_returns_the_destination_without_the_end_marker() {
    // A caller appends another archive's members after its own, and that
    // archive's end marker ends the whole.
    let mut writer = Writer::new(Vec::new());
    writer.append(&Header::file("own", 3), &b"own"[..]).unwrap();
    let out = writer.into_inner().unwrap();
    assert_eq!(out.len(), 2 * 512, "the member's header and data alone");

    let mut carried = Writer::new(Vec::new());
    carried
        .append(&Header::file("carried", 7), &b"carried"[..])
        .unwrap();
    let carried = carried.finish().unwrap();
    let archive = [out, carried].concat();
    let mut reader = Reader::new(&archive[..]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"own");
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"carried");
    assert!(reader.next_entry().unwrap().is_none());
    // The carried archive's end marker, its second block past the first.
    reader.finish(512).unwrap();

    // It flushes the destination, and refuses where a failure left the
    // archive inside a member.
    #[derive(Default)]
    struct Flushed(Vec<u8>, bool);
    impl Write for Flushed {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.1 = true;
            Ok(())
        }
    }
    let writer = Writer::new(Flushed::default());
    assert!(writer.into_inner().unwrap().1);
    let mut writer = Writer::new(Vec::new());
    writer
        .append(&Header::file("short", 10), &b"12345"[..])
        .unwrap_err();
    assert!(matches!(writer.into_inner(), Err(WriteError::Broken)));
}

#[test]
fn data_that_ends_early_or_fails_breaks_the_archive() {
    let mut writer = Writer::new(Vec::new());
    let err = writer
        .append(&Header::file("short", 10), &b"12345"[..])
        .unwrap_err();
    match &err {
        WriteError::Data(io) => {
            assert_eq!(io.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(
                io.to_string(),
                "the data ended 5 bytes short of the member's size of 10"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        writer.append(&Header::file("next", 0), &b""[..]),
        Err(WriteError::Broken)
    ));
    assert!(matches!(writer.finish(), Err(WriteError::Broken)));

    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the source failed"))
        }
    }
    let mut writer = Writer::new(Vec::new());
    let err = writer
        .append(&Header::file("failing", 10), Failing)
        .unwrap_err();
    assert!(matches!(&err, WriteError::Data(io) if io.to_string() == "the source failed"));
    let io: io::Error = err.into();
    assert_eq!(io.to_string(), "the source failed");
}

#[test]
fn a_destination_that_fails_breaks_the_archive() {
    struct Full(usize);
    impl Write for Full {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("the destination is full"));
            }
            let n = buf.len().min(self.0);
            self.0 -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer::new(Full(600));
    let err = writer
        .append(&Header::file("f", 200), &[0u8; 200][..])
        .unwrap_err();
    assert!(matches!(&err, WriteError::Io(io) if io.to_string() == "the destination is full"));
    assert!(matches!(
        writer.append(&Header::file("g", 0), &b""[..]),
        Err(WriteError::Broken)
    ));
    let io: io::Error = WriteError::Broken.into();
    assert_eq!(io.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn data_is_read_up_to_the_size_and_no_further() {
    let mut source = &b"helloworld"[..];
    let mut writer = Writer::new(Vec::new());
    writer
        .append(&Header::file("hello", 5), &mut source)
        .unwrap();
    assert_eq!(source, b"world");
    // A member that carries no data reads none.
    writer
        .append(&Header::symlink("link", "hello"), &mut source)
        .unwrap();
    writer
        .append(&Header::directory("dir/"), &mut source)
        .unwrap();
    assert_eq!(source, b"world");
    let archive = writer.finish().unwrap();
    assert_eq!(archive.len(), 512 * 2 + 512 * 2 + 1024);
    assert!(
        archive[archive.len() - 1024..]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn a_reader_that_ignores_pax_records_sees_a_placeholder_in_the_same_place() {
    // The block's own name, for a reader without the `path` record: the last
    // component, as many leading directories as fit, and no `/` at its end
    // but a directory's.
    let path = [
        &[b'd'; 60][..],
        b"/",
        &[b'e'; 60],
        b"/",
        &[b'f'; 60],
        b"/",
        &[b'g'; 120],
    ]
    .concat();
    for (header, directory) in [
        (Header::file(path.clone(), 0), false),
        (Header::directory([&path[..], b"/"].concat()), true),
    ] {
        let blocks = header.encode().unwrap();
        let block = &blocks[blocks.len() - 512..];
        let name = until_nul(&block[0..100]);
        let prefix = until_nul(&block[345..500]);
        assert!(name.starts_with(&[b'g'; 99][..]), "{}", name.escape_ascii());
        assert_eq!(name.ends_with(b"/"), directory);
        assert_eq!(prefix, [&[b'd'; 60][..], b"/", &[b'e'; 60]].concat());
        // The extended header's own name, likewise.
        let extended = until_nul(&blocks[0..100]);
        assert!(!extended.is_empty() && !extended.ends_with(b"/"));
        assert_eq!(blocks[156], b'x');
    }
}

/// A small deterministic generator, so the property below is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn bytes(&mut self, length: usize, alphabet: &[u8]) -> Vec<u8> {
        (0..length)
            .map(|_| alphabet[self.below(alphabet.len() as u64) as usize])
            .collect()
    }
}

#[test]
fn generated_headers_read_back_as_set() {
    let mut rng = Rng(0x5eed_f00d_cafe_d00d);
    let mut alphabet: Vec<u8> = (1..=255).filter(|byte| *byte != b'/').collect();
    alphabet.extend_from_slice(b"//////");
    let kinds = [
        EntryKind::File,
        EntryKind::Directory,
        EntryKind::Symlink,
        EntryKind::HardLink,
        EntryKind::CharDevice,
        EntryKind::BlockDevice,
        EntryKind::Fifo,
    ];
    let lengths = [
        1, 2, 50, 99, 100, 101, 154, 155, 156, 200, 255, 256, 257, 300, 700,
    ];
    let mut specs = Vec::new();
    for index in 0..600 {
        let kind = kinds[rng.below(kinds.len() as u64) as usize];
        let length = lengths[rng.below(lengths.len() as u64) as usize];
        let mut path = rng.bytes(length, &alphabet);
        // Unique, so a hard link's target is an earlier member's path.
        path.extend_from_slice(format!("-{index}").as_bytes());
        if kind == EntryKind::Directory && rng.below(2) == 0 {
            path.push(b'/');
        }
        let mut spec = Spec::new(kind, path);
        if matches!(kind, EntryKind::Symlink | EntryKind::HardLink) {
            let length = lengths[rng.below(lengths.len() as u64) as usize];
            spec.target = rng.bytes(length, &alphabet);
        }
        if kind == EntryKind::File {
            spec.size = [0, 1, 511, 512, 513, 2000][rng.below(6) as usize];
        }
        if matches!(kind, EntryKind::CharDevice | EntryKind::BlockDevice) {
            spec.device = (rng.below(2_097_152) as u32, rng.below(2_097_152) as u32);
        }
        spec.mode = rng.below(0o10000) as u32;
        let id = |rng: &mut Rng| match rng.below(3) {
            0 => rng.below(1000) as u32,
            1 => rng.below(1 << 32) as u32,
            _ => 2_097_151 + rng.below(3) as u32,
        };
        spec.owner = (id(&mut rng), id(&mut rng));
        let names: Vec<u8> = (1..=255).collect();
        let uname_length = [0, 1, 31, 32, 40][rng.below(5) as usize];
        let gname_length = [0, 1, 31, 32, 40][rng.below(5) as usize];
        spec.names = (
            rng.bytes(uname_length, &names),
            rng.bytes(gname_length, &names),
        );
        let time = |rng: &mut Rng| {
            let secs = match rng.below(3) {
                0 => rng.below(1 << 33) as i64,
                1 => rng.next() as i64,
                _ => -(rng.below(1 << 40) as i64),
            };
            // A time before 1970 with a fraction is refused (below).
            let nanos = if secs < 0 || rng.below(2) == 0 {
                0
            } else {
                rng.below(1_000_000_000) as u32
            };
            Timestamp::new(secs, nanos).unwrap()
        };
        spec.mtime = time(&mut rng);
        if rng.below(2) == 0 {
            spec.atime = Some(time(&mut rng));
            spec.ctime = Some(time(&mut rng));
        }
        for attribute in 0..rng.below(3) {
            let mut name = b"user.".to_vec();
            let plain: Vec<u8> = (1..=255)
                .filter(|byte| !matches!(byte, b'=' | b'\n' | b'%'))
                .collect();
            let length = 1 + rng.below(20) as usize;
            name.extend(rng.bytes(length, &plain));
            name.extend_from_slice(format!("-{attribute}").as_bytes());
            // An empty value is refused (below).
            let length = 1 + rng.below(40) as usize;
            let value = rng.bytes(length, &(0..=255).collect::<Vec<u8>>());
            spec.xattrs.push((name, value));
        }
        specs.push(spec);
    }
    round_trip(&specs);
}

#[test]
fn a_record_counts_its_own_length() {
    // `<length> comment=<value>\n`, the length counting its own digits, at
    // values that carry the record across a digit boundary.
    for length in (0..20).chain(80..100).chain(980..1000) {
        let value = vec![b'y'; length];
        let mut header = Header::file("f", 0);
        header.add_record("comment", value.clone());
        let blocks = header.encode().unwrap();
        let size = usize::from_str_radix(
            std::str::from_utf8(until_nul(&blocks[124..136])).unwrap(),
            8,
        )
        .unwrap();
        let record = &blocks[512..512 + size];
        let space = record.iter().position(|byte| *byte == b' ').unwrap();
        let declared: usize = std::str::from_utf8(&record[..space])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, record.len(), "{length}");
        assert_eq!(
            &record[space + 1..],
            [&b"comment="[..], &value, b"\n"].concat()
        );
    }
}

#[test]
fn an_interrupted_read_of_the_data_is_retried() {
    struct Interrupting {
        data: &'static [u8],
        interrupt: bool,
    }
    impl Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.data.len().min(buf.len()).min(2);
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }
    let mut writer = Writer::new(Vec::new());
    let source = Interrupting {
        data: b"hello",
        interrupt: false,
    };
    writer.append(&Header::file("f", 5), source).unwrap();
    let archive = writer.finish().unwrap();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap().unwrap();
    assert_eq!(reader.read_entry(5).unwrap(), b"hello");
}

#[test]
fn the_block_holds_the_nearest_value_where_a_record_holds_the_exact_one() {
    let octal = |field: &[u8]| {
        u64::from_str_radix(std::str::from_utf8(until_nul(field)).unwrap(), 8).unwrap()
    };
    let block = |header: &Header| {
        let blocks = header.encode().unwrap();
        assert_eq!(blocks[156], b'x', "an extended header first");
        blocks[blocks.len() - 512..].to_vec()
    };
    // An id the field cannot hold is clamped to the field's largest, an
    // unprivileged owner's rather than root's.
    let ids = block(Header::file("f", 0).set_owner(2_097_152, u32::MAX));
    assert_eq!(octal(&ids[108..116]), 0o7777777);
    assert_eq!(octal(&ids[116..124]), 0o7777777);
    // A time before 1970 holds the epoch; one past the field, the field's
    // largest; one with a fraction, its whole second.
    for (time, held) in [
        (Timestamp::new(-5, 0).unwrap(), 0),
        (Timestamp::from_secs(1 << 40), (1 << 33) - 1),
        (Timestamp::new(1_700_000_000, 5).unwrap(), 1_700_000_000),
    ] {
        let times = block(Header::file("f", 0).set_mtime(time));
        assert_eq!(octal(&times[136..148]), held, "{time:?}");
    }
    // A size the field cannot hold, exactly, in base-256: it frames the
    // archive for a reader without the record.
    let size = 1u64 << 40;
    let sized = block(&Header::file("f", size));
    assert_eq!(sized[124] & 0x80, 0x80);
    let value = sized[125..136]
        .iter()
        .fold(u64::from(sized[124] & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    assert_eq!(value, size);
    // An owner name too long for the field leaves it empty.
    let names = block(Header::file("f", 0).set_owner_names(vec![b'u'; 32], "g"));
    assert_eq!(until_nul(&names[265..297]), b"");
    assert_eq!(until_nul(&names[297..329]), b"g");
    // A link target too long for the field leaves it empty.
    let link = block(&Header::symlink("l", vec![b't'; 101]));
    assert_eq!(until_nul(&link[157..257]), b"");
}

#[test]
fn a_time_before_1970_with_a_fraction_is_refused() {
    // bsdtar reads `-1.5` as half a second before the epoch; GNU tar, Go
    // and Python as a second and a half.
    let early = Timestamp::new(-2, 500_000_000).unwrap();
    for keyword in [
        ferrotape::Keyword::Mtime,
        ferrotape::Keyword::Atime,
        ferrotape::Keyword::Ctime,
    ] {
        let mut header = Header::file("f", 0);
        match keyword {
            ferrotape::Keyword::Mtime => header.set_mtime(early),
            ferrotape::Keyword::Atime => header.set_atime(early),
            _ => header.set_ctime(early),
        };
        assert_eq!(
            header.encode(),
            Err(HeaderError::FractionBeforeEpoch(keyword))
        );
    }
    assert_eq!(
        HeaderError::FractionBeforeEpoch(ferrotape::Keyword::Atime).to_string(),
        "the atime is before 1970 and has a fraction of a second",
    );
}

#[test]
fn a_header_with_a_text_value_that_is_not_utf_8_says_so() {
    // A long path, link target or owner name that is not UTF-8 goes in a
    // record after `hdrcharset=BINARY`; one that is, or one the block holds,
    // needs none.
    let long = |byte: u8| [&b"dir/"[..], &[byte; 120]].concat();
    let cases: Vec<(Header, bool)> = vec![
        (Header::file(long(b'a'), 0), false),
        (
            Header::file([&long(b'a')[..], "\u{e9}".as_bytes()].concat(), 0),
            false,
        ),
        (Header::file(long(b'\xff'), 0), true),
        (Header::file(b"short\xff".to_vec(), 0), false),
        (Header::symlink("l", long(b'\xfe')), true),
        (
            Header::file("f", 0)
                .set_owner_names(vec![b'\xff'; 40], "g")
                .clone(),
            true,
        ),
        (
            Header::file("f", 0)
                .set_owner_names(vec![b'\xff'; 20], "g")
                .clone(),
            false,
        ),
    ];
    for (header, binary) in cases {
        let mut writer = Writer::new(Vec::new());
        writer.append(&header, &b""[..]).unwrap();
        let archive = writer.finish().unwrap();
        let mut reader = Reader::new(&archive[..]);
        let entry = reader.next_entry().unwrap().unwrap();
        let declared = entry.pax_records().get(b"hdrcharset");
        assert_eq!(declared, binary.then_some(&b"BINARY"[..]), "{header:?}");
        if binary {
            assert_eq!(entry.pax_records().iter().next().unwrap().0, b"hdrcharset");
        }
    }
}

#[test]
fn a_time_is_written_with_as_few_digits_as_hold_it() {
    for (time, spelled) in [
        (
            Timestamp::new(1_720_000_000, 500_000_000).unwrap(),
            &b"1720000000.5"[..],
        ),
        (Timestamp::new(1, 123_456_789).unwrap(), b"1.123456789"),
        (Timestamp::new(0, 1).unwrap(), b"0.000000001"),
        (Timestamp::from_secs(-7), b"-7"),
        (Timestamp::from_secs(1 << 33), b"8589934592"),
    ] {
        let mut writer = Writer::new(Vec::new());
        writer
            .append(Header::file("f", 0).set_mtime(time), &b""[..])
            .unwrap();
        let archive = writer.finish().unwrap();
        let entry = Reader::new(&archive[..]).next_entry().unwrap().unwrap();
        assert_eq!(entry.pax_records().get(b"mtime"), Some(spelled));
    }
}

#[test]
fn a_prefix_never_ends_in_a_slash() {
    // bsdtar joins a prefix that ends in `/` to the name without adding one,
    // reading `a//b` as `a/b`; a name that begins with `/` reads alike.
    for path in [
        [&[b'd'; 60][..], b"//", &[b'e'; 60]].concat(),
        [&[b'd'; 60][..], b"///", &[b'e'; 60]].concat(),
        [&b"/"[..], &[b'f'; 100]].concat(),
        [&b"//"[..], &[b'f'; 100]].concat(),
        [&[b'g'; 150][..], b"//", &[b'h'; 99]].concat(),
        // Too long for any split, with the prefix's cut after a `//`.
        [&[b'a'; 100][..], b"//", &[b'b'; 100], b"/", &[b'c'; 120]].concat(),
    ] {
        let blocks = Header::file(path.clone(), 0).encode().unwrap();
        let block = &blocks[blocks.len() - 512..];
        let prefix = until_nul(&block[345..500]);
        assert!(!prefix.ends_with(b"/"), "{}", path.escape_ascii());
        let entry = Reader::new(&[&blocks[..], &[0u8; 1024][..]].concat()[..])
            .next_entry()
            .unwrap()
            .unwrap();
        assert_eq!(entry.path(), path);
    }
}
