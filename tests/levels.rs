//! What each strictness level reads and refuses: the archives the reference
//! readers read alike but another reader in wide use reads otherwise.

mod support;

use std::io::Read;

use ferrotape::{EntryKind, ErrorKind, Level, Metadata, Reader};
use support::{BLOCK, Header, Magic, Tar, first, first_at, paths, paths_at, pax_record};

const LEVELS: [Level; 2] = [Level::Strict, Level::Compatible];

#[test]
fn strict_is_the_default() {
    assert_eq!(Level::default(), Level::Strict);
}

#[test]
fn a_long_name_or_long_link_holding_a_nul_before_its_last_byte_is_refused_in_strict() {
    // GNU tar, bsdtar, Go and Python end the name at its first NUL. The `tar`
    // and `tar-core` crates strip one trailing NUL and keep the rest, so a NUL
    // inside the name, or a second at its end, is part of the name to them.
    for (typeflag, kind) in [(b'L', Metadata::LongName), (b'K', Metadata::LongLink)] {
        for value in [&b"abc\0def\0"[..], b"abc\0def", b"abc\0\0"] {
            let archive = Tar::new()
                .long(typeflag, value)
                .header(&Header::new("short", b'2', 0))
                .finish();
            let err = first(&archive).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::LongNameNul(kind));
            assert_eq!(err.offset(), 0, "the long name's own header");

            let entry = first_at(&archive, Level::Compatible).unwrap();
            let name = if typeflag == b'L' {
                entry.path()
            } else {
                entry.link_target()
            };
            assert_eq!(name, b"abc", "{}", value.escape_ascii());
        }

        // One NUL at the end, as GNU tar writes it, or none: one name to every
        // reader.
        for value in [&b"abc\0"[..], b"abc"] {
            for level in LEVELS {
                let archive = Tar::new()
                    .long(typeflag, value)
                    .header(&Header::new("short", b'2', 0))
                    .finish();
                let entry = first_at(&archive, level).unwrap();
                let name = if typeflag == b'L' {
                    entry.path()
                } else {
                    entry.link_target()
                };
                assert_eq!(name, b"abc");
            }
        }
    }
    let archive = Tar::new().long(b'L', b"a\0b").file("short", b"").finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a GNU long name holds a NUL before its last byte at offset 0",
    );
}

#[test]
fn metadata_in_a_header_without_magic_is_refused_in_strict() {
    // GNU tar, bsdtar, Go and Python apply a v7 header's `x`, `L` or `K` to
    // the member after it, as they would with magic; the `tar` and `tar-core`
    // crates read it as a member, then the next under its own name.
    for (typeflag, data, kind) in [
        (b'x', pax_record(b"path", b"evilname"), Metadata::PaxHeader),
        (b'L', b"evilname\0".to_vec(), Metadata::LongName),
        (b'K', b"evilname\0".to_vec(), Metadata::LongLink),
    ] {
        let mut header = Header::new("v7meta", typeflag, 0);
        header.magic = Magic::V7;
        let mut victim = Header::new("victim", b'2', 0);
        victim.link = b"target".to_vec();
        let archive = Tar::new().entry(header, &data).header(&victim).finish();

        let err = paths(&archive).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::MetadataWithoutMagic(kind), 0)
        );

        let entry = first_at(&archive, Level::Compatible).unwrap();
        let named = if typeflag == b'K' {
            entry.link_target()
        } else {
            entry.path()
        };
        assert_eq!(named, b"evilname");
    }
}

#[test]
fn a_member_of_a_type_that_carries_no_data_reads_none_and_declares_none_in_strict() {
    // GNU tar, bsdtar, Go and Python read no data after these, whatever their
    // header declares; the `tar` crate and `tar-core` 0.1 read the size as
    // data, and so read the headers in it as that data rather than as members.
    for (typeflag, kind) in [
        (b'2', EntryKind::Symlink),
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
        (b'5', EntryKind::Directory),
        (b'6', EntryKind::Fifo),
    ] {
        let hidden = Tar::new().file("hidden", b"").unterminated();
        let archive = Tar::new()
            .header(&Header::new("special", typeflag, hidden.len() as u64))
            .raw(&hidden)
            .file("next", b"")
            .finish();

        let err = paths(&archive).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::SizeWithoutData { kind }, 0)
        );

        let mut reader = Reader::new(&archive[..]).with_level(Level::Compatible);
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!((entry.kind(), entry.size()), (kind, 0));
        assert_eq!(entry.declared_size(), hidden.len() as u64);
        let mut data = Vec::new();
        reader.data().read_to_end(&mut data).unwrap();
        assert!(data.is_empty());
        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"hidden");
        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"next");

        // Declaring nothing, they are read at both levels.
        let archive = Tar::new()
            .header(&Header::new("special", typeflag, 0))
            .finish();
        for level in LEVELS {
            assert_eq!(first_at(&archive, level).unwrap().kind(), kind);
        }
    }
}

#[test]
fn a_size_record_on_a_member_that_carries_no_data_is_refused_at_both_levels() {
    // GNU tar reads the data a pax `size` record declares, where it reads none
    // for the header's own size field; bsdtar, Go and Python read none, and
    // list the headers in the declared body.
    let hidden = Tar::new().file("hidden", b"").unterminated();
    let size = hidden.len().to_string();
    for (typeflag, kind) in [
        (b'2', EntryKind::Symlink),
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
        (b'5', EntryKind::Directory),
        (b'6', EntryKind::Fifo),
    ] {
        let mut special = Header::new("special", typeflag, 0);
        special.link = b"t".to_vec();
        let archive = Tar::new()
            .pax(b'x', &pax_record(b"size", size.as_bytes()))
            .header(&special)
            .raw(&hidden)
            .file("next", b"")
            .finish();
        for level in LEVELS {
            let err = paths_at(&archive, level).unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (&ErrorKind::SizeWithoutData { kind }, 2 * BLOCK as u64)
            );
        }
        // A record of zero, over a header that declares a size, leaves every
        // reader reading no data.
        let mut special = Header::new("special", typeflag, hidden.len() as u64);
        special.link = b"t".to_vec();
        let archive = Tar::new()
            .pax(b'x', &pax_record(b"size", b"0"))
            .header(&special)
            .raw(&hidden)
            .finish();
        for level in LEVELS {
            assert_eq!(
                paths_at(&archive, level).unwrap(),
                [&b"special"[..], b"hidden"]
            );
        }
    }
}

#[test]
fn setuid_setgid_or_sticky_beside_an_access_list_is_refused_in_strict() {
    // GNU tar extracts the three bits beside the list; bsdtar takes the mode
    // from the list and drops them, so a sticky directory extracts as `777`.
    let list = pax_record(b"SCHILY.acl.access", b"user::rwx,group::r-x,other::rwx");
    for mode in [0o4755, 0o2755, 0o1777, 0o6755, 0o7777] {
        let mut member = Header::new("d/", b'5', 0);
        member.mode = mode;
        let archive = Tar::new().pax(b'x', &list).header(&member).finish();
        let err = first(&archive).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::SpecialBitsWithAcl, 2 * BLOCK as u64)
        );
        // Compatible reads the header's mode, as GNU tar extracts it.
        let entry = first_at(&archive, Level::Compatible).unwrap();
        assert_eq!(entry.mode(), mode);
    }
    // Read at both levels: the bits without an access list, or beside a
    // default list or the binary form alone, which neither tar applies by
    // itself; and an access list with none of the three.
    let mut setgid = Header::new("d/", b'5', 0);
    setgid.mode = 0o2775;
    let mut plain = Header::new("d/", b'5', 0);
    plain.mode = 0o775;
    for (records, member) in [
        (Vec::new(), &setgid),
        (
            pax_record(b"SCHILY.acl.default", b"user::rwx,group::r-x,other::r-x"),
            &setgid,
        ),
        (
            pax_record(b"SCHILY.xattr.system.posix_acl_access", b"\x02\0\0\0"),
            &setgid,
        ),
        (list.clone(), &plain),
    ] {
        let mut archive = Tar::new();
        if !records.is_empty() {
            archive.pax(b'x', &records);
        }
        let archive = archive.header(member).finish();
        for level in LEVELS {
            assert_eq!(first_at(&archive, level).unwrap().mode(), member.mode);
        }
    }
    let mut member = Header::new("f", b'0', 0);
    member.mode = 0o4755;
    let archive = Tar::new().pax(b'x', &list).header(&member).finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a member with setuid, setgid or sticky carries an access control list, and readers \
         extract it with different modes at offset 1024",
    );
}

#[test]
fn a_hard_link_declaring_a_size_is_refused_at_both_levels() {
    // POSIX lets a hard link in a pax archive carry its file's data after it;
    // every reference reader reads none.
    let archive = Tar::new()
        .file("orig", b"")
        .header(&{
            let mut link = Header::new("hl", b'1', BLOCK as u64);
            link.link = b"orig".to_vec();
            link
        })
        .body(&[0; BLOCK])
        .finish();
    for level in LEVELS {
        let err = paths_at(&archive, level).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::SizeWithoutData {
                kind: EntryKind::HardLink
            },
        );
        assert_eq!(err.offset(), BLOCK as u64, "the link's own header");
    }
    assert_eq!(
        paths(&archive).unwrap_err().to_string(),
        "a hard link, which carries no data, declares a size at offset 512",
    );
}

#[test]
fn a_zero_block_followed_by_more_is_refused_in_strict() {
    // GNU tar, bsdtar and Python stop at the first zero block, Go refuses;
    // GNU tar with `--ignore-zeros` and `tar-core` 0.1 read on and see
    // `second`.
    let archive = Tar::new()
        .file("first", b"")
        .raw(&[0; BLOCK])
        .file("second", b"")
        .finish();
    let err = paths(&archive).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::TrailingData);
    // The first byte that is not zero: the name of `second`.
    assert_eq!(err.offset(), 2 * BLOCK as u64);
    assert_eq!(paths_at(&archive, Level::Compatible).unwrap(), [b"first"]);

    // A lone zero block where the stream ends, or the second block of the
    // end marker, is an ordinary end.
    for archive in [
        Tar::new().file("only", b"").raw(&[0; BLOCK]).unterminated(),
        Tar::new().file("only", b"").finish(),
        [
            &Tar::new().file("only", b"").raw(&[0; BLOCK]).unterminated()[..],
            &[0; 100],
        ]
        .concat(),
    ] {
        for level in LEVELS {
            assert_eq!(paths_at(&archive, level).unwrap(), [b"only"]);
        }
    }
}

#[test]
fn finish_refuses_anything_but_zeros_after_the_end_in_strict() {
    // Archives joined with `cat`: GNU tar with `--ignore-zeros` reads the
    // second one's members.
    let one = Tar::new().file("real", b"").finish();
    let joined = [&one[..], &Tar::new().file("ghost", b"").finish()[..]].concat();
    let mut reader = Reader::new(&joined[..]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"real");
    assert!(reader.next_entry().unwrap().is_none());
    let err = reader.finish(1 << 20).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (&ErrorKind::TrailingData, one.len() as u64)
    );
    assert_eq!(
        err.to_string(),
        format!(
            "bytes other than zeros follow the end of the archive at offset {}",
            one.len()
        ),
    );

    let mut reader = Reader::new(&joined[..]).with_level(Level::Compatible);
    reader.finish(1 << 20).unwrap();

    // Zeros, as far as the limit allows, are padding at both levels.
    let padded = [&one[..], &[0; 9000]].concat();
    for level in LEVELS {
        Reader::new(&padded[..])
            .with_level(level)
            .finish(BLOCK as u64 + 9000)
            .unwrap();
        let err = Reader::new(&padded[..])
            .with_level(level)
            .finish(BLOCK as u64 + 8999)
            .unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::TrailingLimit { limit: 9511 });
    }
}

#[test]
fn metadata_under_a_magic_and_version_that_are_not_exact_is_refused_in_strict() {
    // GNU tar, bsdtar, Go and Python apply it as under either exact pair; the
    // `tar` and `tar-core` crates read it as a member of its own unless its
    // magic and version are POSIX's `ustar\0` `00` or GNU's `ustar ` ` \0`.
    let mut target = Header::new("victim", b'2', 0);
    target.link = b"hdrtarget".to_vec();
    for (typeflag, data, kind) in [
        (b'x', pax_record(b"path", b"evilname"), Metadata::PaxHeader),
        (b'L', b"evilname\0".to_vec(), Metadata::LongName),
        (b'K', b"evilname\0".to_vec(), Metadata::LongLink),
    ] {
        for (magic_version, exact) in [
            (b"ustar 00", false),
            (b"ustar \0\0", false),
            (b"ustar\0\0\0", false),
            (b"ustar\0xx", false),
            (b"ustar\x0000", true),
            (b"ustar  \0", true),
        ] {
            let mut meta = Header::new("meta", typeflag, data.len() as u64).block();
            meta[257..265].copy_from_slice(magic_version);
            support::seal(&mut meta);
            let archive = Tar::new().block(&meta).body(&data).header(&target).finish();
            let strict = first(&archive);
            if exact {
                assert!(strict.is_ok(), "{}", magic_version.escape_ascii());
            } else {
                let err = strict.unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::MetadataWithoutMagic(kind), 0),
                    "{}",
                    magic_version.escape_ascii(),
                );
            }
            let entry = first_at(&archive, Level::Compatible).unwrap();
            let named = if typeflag == b'K' {
                entry.link_target()
            } else {
                entry.path()
            };
            assert_eq!(named, b"evilname");
        }
    }
    let mut meta = Header::new("meta", b'L', 9).block();
    meta[257..265].copy_from_slice(b"ustar 00");
    support::seal(&mut meta);
    let archive = Tar::new()
        .block(&meta)
        .body(b"evilname\0")
        .file("x", b"")
        .finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a header whose magic and version are not exactly POSIX's or GNU's is a GNU long name \
         at offset 0",
    );
}
