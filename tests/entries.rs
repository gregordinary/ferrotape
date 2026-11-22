//! What an entry reports beyond its name: its kind, its header and where it
//! lies; and the headers that are not members.

mod support;

use std::io::Read;

use ferrotape::{EntryKind, ErrorKind, GlobalHeaders, Level, Reader};
use support::{BLOCK, Header, Magic, Tar, first, paths, paths_at, pax_record};

#[test]
fn every_typeflag_has_a_kind_and_keeps_its_byte() {
    for (typeflag, kind) in [
        (b'0', EntryKind::File),
        (0, EntryKind::File),
        (b'1', EntryKind::HardLink),
        (b'2', EntryKind::Symlink),
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
        (b'5', EntryKind::Directory),
        (b'6', EntryKind::Fifo),
        // A contiguous file is a regular file, as is any typeflag the reader
        // does not know, as POSIX specifies.
        (b'7', EntryKind::File),
        (b'E', EntryKind::File),
        (b'I', EntryKind::File),
        (b'N', EntryKind::File),
        (b'Z', EntryKind::File),
        // GNU's dumpdir, read as GNU tar and bsdtar read it.
        (b'D', EntryKind::Directory),
    ] {
        // A hard link names a target in its header, which every other kind
        // passes over.
        let mut header = Header::new("m", typeflag, 0);
        header.link = b"t".to_vec();
        let entry = first(&Tar::new().header(&header).finish()).unwrap();
        assert_eq!(
            (entry.kind(), entry.typeflag()),
            (kind, typeflag),
            "typeflag {}",
            char::from(typeflag),
        );
    }
}

#[test]
fn an_unknown_typeflag_carries_its_data() {
    let archive = Tar::new()
        .entry(Header::new("unknown", b'E', 0), b"data")
        .file("next", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!((entry.kind(), entry.size()), (EntryKind::File, 4));
    assert_eq!(reader.read_entry(4).unwrap(), b"data");
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"next");
}

#[test]
fn a_dumpdir_is_a_directory_whose_data_is_read() {
    // What a GNU incremental dump writes for a directory: the names it held
    // when the dump was made. GNU tar and bsdtar read a directory; Python and
    // Go an unknown type; all read its data as data.
    let mut header = Header::new("dumpdir/", b'D', 0);
    header.magic = Magic::Gnu;
    let archive = Tar::new()
        .entry(header, b"Yfile\0\0")
        .file("after", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!((entry.kind(), entry.size()), (EntryKind::Directory, 7));
    assert_eq!(reader.read_entry(7).unwrap(), b"Yfile\0\0");
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"after");
}

/// A member `victim` of `typeflag` with `data`, its link target `target`
/// stated by `how` ("header", "long" or "pax"), after a file `target`.
fn link_on(typeflag: u8, magic: Magic, data: &[u8], how: &str) -> Vec<u8> {
    let mut lead = Header::new("target", b'0', 0);
    lead.magic = magic;
    let mut victim = Header::new("victim", typeflag, 0);
    victim.magic = magic;
    let mut archive = Tar::new();
    archive.entry(lead, b"TARGET\n");
    match how {
        "header" => victim.link = b"target".to_vec(),
        "long" => {
            archive.long(b'K', b"target\0");
        }
        _ => {
            archive.pax(b'x', &pax_record(b"linkpath", b"target"));
        }
    }
    archive.entry(victim, data).finish()
}

#[test]
fn a_link_target_on_a_member_that_is_not_a_link_is_refused() {
    // bsdtar extracts such a member as a hard link to the target a long link
    // or a pax record states, and writes the member's data into it; GNU tar
    // and Python make the member as its kind.
    let cases: [(u8, Magic, &[u8], EntryKind); 9] = [
        (b'0', Magic::Ustar, b"VICTIM\n", EntryKind::File),
        (b'0', Magic::Ustar, b"", EntryKind::File),
        (0, Magic::Ustar, b"VICTIM\n", EntryKind::File),
        (b'7', Magic::Ustar, b"VICTIM\n", EntryKind::File),
        (b'Z', Magic::Ustar, b"VICTIM\n", EntryKind::File),
        (b'D', Magic::Gnu, b"VICTIM\n", EntryKind::Directory),
        (b'5', Magic::Ustar, b"", EntryKind::Directory),
        (b'6', Magic::Ustar, b"", EntryKind::Fifo),
        (b'3', Magic::Ustar, b"", EntryKind::CharDevice),
    ];
    for (typeflag, magic, data, kind) in cases {
        for how in ["long", "pax"] {
            let archive = link_on(typeflag, magic, data, how);
            for level in [Level::Strict, Level::Compatible] {
                let mut reader = Reader::new(&archive[..]).with_level(level);
                assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"target");
                let err = reader.next_entry().unwrap_err();
                assert_eq!(
                    err.kind(),
                    &ErrorKind::TargetWithoutLink { kind },
                    "{typeflag:?} {how} {level:?}",
                );
                assert_eq!(err.offset(), 4 * BLOCK as u64, "the member's own header");
            }
        }
        // The header's own field is passed over by every reader there.
        let archive = link_on(typeflag, magic, data, "header");
        let mut reader = Reader::new(&archive[..]).with_level(Level::Compatible);
        reader.next_entry().unwrap();
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!((entry.kind(), entry.link_target()), (kind, &b"target"[..]));
    }
    // A v7 header has no magic for a long link to follow it in, but a pax
    // record applies to it.
    let archive = link_on(0, Magic::V7, b"VICTIM\n", "pax");
    let err = paths_at(&archive, Level::Compatible).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::TargetWithoutLink {
            kind: EntryKind::File
        },
    );
    assert_eq!(
        err.to_string(),
        format!(
            "a regular file, which is not a link, has a link target from a long link or a pax \
             record at offset {}",
            err.offset(),
        ),
    );
}

#[test]
fn a_link_target_from_a_long_link_or_a_record_is_read_on_a_link() {
    for (typeflag, kind) in [(b'1', EntryKind::HardLink), (b'2', EntryKind::Symlink)] {
        for how in ["header", "long", "pax"] {
            let archive = link_on(typeflag, Magic::Ustar, b"", how);
            let mut reader = Reader::new(&archive[..]);
            reader.next_entry().unwrap();
            let entry = reader.next_entry().unwrap().unwrap();
            assert_eq!(
                (entry.kind(), entry.link_target()),
                (kind, &b"target"[..]),
                "{how}"
            );
        }
    }
}

#[test]
fn a_global_link_target_is_applied_to_a_member_that_is_not_a_link() {
    // A global record is applied only for GNU tar and Python, which pass over
    // a link target on a member that is not a link; bsdtar applies none.
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"linkpath", b"target"))
        .file("victim", b"VICTIM\n")
        .finish();
    let entry = Reader::new(&archive[..])
        .with_global_headers(GlobalHeaders::Apply)
        .next_entry()
        .unwrap()
        .unwrap();
    assert_eq!(
        (entry.kind(), entry.link_target()),
        (EntryKind::File, &b"target"[..]),
    );
}

#[test]
fn a_volume_label_is_refused() {
    // GNU tar and bsdtar extract nothing for a label; Python extracts it as a
    // regular file holding its data, and Go reports it as a member. Refused
    // first, as GNU tar's `--label` writes it, after a member, under either
    // magic, with data or without, and after metadata, whose member GNU tar,
    // Go and Python take to be the label and bsdtar the member after it.
    let hidden = Tar::new().file("hidden", b"").unterminated();
    for magic in [Magic::Gnu, Magic::Ustar] {
        for data in [&b""[..], &hidden] {
            let mut label = Header::new("VOLUME", b'V', 0);
            label.magic = magic;
            for before in [
                Tar::new().unterminated(),
                Tar::new().file("first", b"data").unterminated(),
                Tar::new()
                    .pax(b'x', &pax_record(b"path", b"renamed"))
                    .unterminated(),
                Tar::new().long(b'L', b"renamed\0").unterminated(),
                Tar::new().long(b'K', b"retargeted\0").unterminated(),
            ] {
                let archive = Tar::new()
                    .raw(&before)
                    .entry(label.clone(), data)
                    .file("tail", b"")
                    .finish();
                for level in [Level::Strict, Level::Compatible] {
                    let err = paths_at(&archive, level).unwrap_err();
                    assert_eq!(err.kind(), &ErrorKind::VolumeLabel, "{magic:?} {level:?}");
                    assert_eq!(err.offset(), before.len() as u64, "the label's own header");
                }
            }
        }
    }
    let mut label = Header::new("VOLUME", b'V', 0);
    label.magic = Magic::Gnu;
    let archive = Tar::new().header(&label).finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "the archive holds a GNU volume label (typeflag `V`) at offset 0",
    );
}

#[test]
fn a_solaris_acl_is_refused() {
    // bsdtar reads typeflag `A` as metadata for the member after it; GNU tar,
    // Go and Python read a member.
    let archive = Tar::new()
        .entry(Header::new("acl", b'A', 0), b"user::rw-\0")
        .file("victim", b"")
        .finish();
    let err = paths(&archive).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (&ErrorKind::SolarisAcl, 0));
}

#[test]
fn a_continuation_from_another_volume_is_refused() {
    // GNU tar, reading one volume, does not extract an `M` member and reads
    // on past it; bsdtar and Python extract a regular file.
    let archive = Tar::new()
        .entry(Header::new("continued", b'M', 0), &[b'm'; BLOCK])
        .file("tail", b"")
        .finish();
    let err = paths(&archive).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (&ErrorKind::VolumeContinuation, 0)
    );
}

#[test]
fn a_member_holds_its_own_header_and_where_it_lies() {
    // The metadata before a member is not its header: the block is the
    // member's own, as it stated its fields before anything replaced them.
    let archive = Tar::new()
        .file("first", b"0123456789")
        .pax(b'x', &pax_record(b"path", b"a/long/name"))
        .entry(Header::new("short", b'0', 0), b"data")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    let first = reader.next_entry().unwrap().unwrap();
    assert_eq!(
        (first.header_offset(), first.data_offset()),
        (0, BLOCK as u64)
    );
    let second = reader.next_entry().unwrap().unwrap();
    assert_eq!(second.path(), b"a/long/name");
    assert_eq!(second.header_offset(), 4 * BLOCK as u64);
    assert_eq!(second.data_offset(), 5 * BLOCK as u64);
    let header = second.header_block();
    assert_eq!(&header[..6], b"short\0");
    assert_eq!(
        &archive[second.data_offset() as usize..][..4],
        b"data",
        "the data lies where it says",
    );
    let mut data = Vec::new();
    reader.data().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"data");
}

#[test]
fn a_hard_link_with_no_target_is_refused() {
    // GNU tar links it to `.`, the directory it extracts into; bsdtar, Go and
    // Python read the empty name.
    let archive = Tar::new()
        .file("f", b"x")
        .header(&Header::new("h", b'1', 0))
        .finish();
    for level in [Level::Strict, Level::Compatible] {
        let err = paths_at(&archive, level).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::HardLinkWithoutTarget, 2 * BLOCK as u64)
        );
    }
    assert_eq!(
        paths(&archive).unwrap_err().to_string(),
        "a hard link names no target at offset 1024"
    );
    // Every reader reads a symbolic link with no target alike.
    let archive = Tar::new()
        .header(&Header::new("s", b'2', 0))
        .file("after", b"")
        .finish();
    let entry = first(&archive).unwrap();
    assert_eq!(
        (entry.kind(), entry.link_target()),
        (EntryKind::Symlink, &b""[..])
    );
}

#[test]
fn a_typeflag_gnu_tar_does_not_know_named_as_a_directory_is_refused() {
    // bsdtar reads a directory; GNU tar and Python extract a regular file.
    for typeflag in [b'I', b'N', b'Z', b'8', b'E', b'a', 0x01, b' ', 0xff] {
        let archive = Tar::new()
            .header(&Header::new("n/", typeflag, 0))
            .file("after", b"")
            .finish();
        for level in [Level::Strict, Level::Compatible] {
            let err = paths_at(&archive, level).unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (&ErrorKind::UnknownTypeSlash { typeflag }, 0),
                "typeflag {}",
                typeflag.escape_ascii(),
            );
        }
        // Named by a pax record.
        let archive = Tar::new()
            .pax(b'x', &pax_record(b"path", b"n/"))
            .header(&Header::new("n", typeflag, 0))
            .finish();
        assert_eq!(
            paths(&archive).unwrap_err().kind(),
            &ErrorKind::UnknownTypeSlash { typeflag }
        );
        // Without the slash, a regular file to every reader.
        let entry = first(&Tar::new().header(&Header::new("n", typeflag, 0)).finish()).unwrap();
        assert_eq!(entry.kind(), EntryKind::File);
    }
    // A typeflag GNU tar knows, named so, is a directory to GNU tar and
    // bsdtar alike.
    for typeflag in [0, b'0', b'7', b'5', b'D'] {
        let entry = first(&Tar::new().header(&Header::new("n/", typeflag, 0)).finish()).unwrap();
        assert_eq!(entry.kind(), EntryKind::Directory);
    }
    let archive = Tar::new().header(&Header::new("n/", b'I', 0)).finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a member of typeflag `I`, which GNU tar does not know, is named as a directory at offset 0",
    );
}
