//! Global extended headers: what each mode reads and refuses, and how their
//! records reach the caller.

mod support;

use ferrotape::{
    Entry, Error, ErrorKind, GlobalHeaders, Keyword, Level, Metadata, Numeric, PaxFraming, Reader,
};
use support::{Header, Tar, paths, pax_record, pax_records};

const MODES: [GlobalHeaders; 3] = [
    GlobalHeaders::Refuse,
    GlobalHeaders::Apply,
    GlobalHeaders::Defer,
];

/// Every member of `archive` read with `mode`, or the first error.
fn members(archive: &[u8], mode: GlobalHeaders) -> Result<Vec<Entry>, Error> {
    let mut reader = Reader::new(archive).with_global_headers(mode);
    let mut members = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        members.push(entry);
    }
    Ok(members)
}

#[test]
fn a_global_header_holding_only_a_comment_is_passed_over() {
    // The record `git archive` writes at the head of every archive, and one
    // between members, which no reader applies to either.
    let archive = Tar::new()
        .pax(
            b'g',
            &pax_record(b"comment", b"0123456789abcdef0123456789abcdef01234567"),
        )
        .file("first", b"")
        .pax(b'g', &pax_record(b"comment", b"another"))
        .pax(b'x', &pax_record(b"path", b"pax-path"))
        .file("second", b"")
        .pax(b'g', &pax_record(b"comment", b"trailing"))
        .finish();
    assert_eq!(paths(&archive).unwrap(), [&b"first"[..], b"pax-path"]);
}

#[test]
fn a_global_header_setting_any_other_record_is_refused() {
    for (records, keyword) in [
        (pax_record(b"size", b"0"), &b"size"[..]),
        (pax_record(b"path", b"renamed"), b"path"),
        (pax_record(b"linkpath", b"elsewhere"), b"linkpath"),
        (pax_record(b"uid", b"1234"), b"uid"),
        (pax_record(b"mtime", b"1000000"), b"mtime"),
        // GNU tar does not apply a global extended attribute that Python
        // reports on each member.
        (
            pax_record(b"SCHILY.xattr.user.k", b"v"),
            b"SCHILY.xattr.user.k",
        ),
        (
            [
                pax_record(b"comment", b"c"),
                pax_record(b"uname", b"someone"),
            ]
            .concat(),
            b"uname",
        ),
    ] {
        let archive = Tar::new().pax(b'g', &records).file("plain", b"").finish();
        let err = paths(&archive).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::GlobalRecord {
                keyword: keyword.to_vec()
            },
        );
        assert_eq!(err.offset(), 0);
    }
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"path", b"renamed"))
        .file("plain", b"")
        .finish();
    assert_eq!(
        paths(&archive).unwrap_err().to_string(),
        "a global extended header sets `path`, a record other than `comment` at offset 0",
    );

    // Records that do not frame are refused as an extended header's are.
    let archive = Tar::new()
        .pax(b'g', b"99 comment=x\n")
        .file("plain", b"")
        .finish();
    assert_eq!(
        paths(&archive).unwrap_err().kind(),
        &ErrorKind::PaxFraming(PaxFraming::LengthOutOfBounds),
    );
}

#[test]
fn a_global_header_does_not_fall_between_metadata_and_its_member() {
    // Go lets a global header consume an extended header or a long name
    // waiting for its member, which GNU tar, bsdtar and Python apply to the
    // member; and bsdtar refuses two global headers in a row.
    let comment = Tar::new()
        .pax(b'g', &pax_record(b"comment", b"c"))
        .unterminated();
    for (before, kind) in [
        (
            Tar::new()
                .pax(b'x', &pax_record(b"path", b"name"))
                .unterminated(),
            ErrorKind::GlobalBetweenMetadata,
        ),
        (
            Tar::new().long(b'L', b"long-name\0").unterminated(),
            ErrorKind::GlobalBetweenMetadata,
        ),
        (
            Tar::new().long(b'K', b"long-target\0").unterminated(),
            ErrorKind::GlobalBetweenMetadata,
        ),
        (
            comment.clone(),
            ErrorKind::RepeatedMetadata(Metadata::GlobalHeader),
        ),
    ] {
        let archive = Tar::new()
            .raw(&before)
            .raw(&comment)
            .file("plain", b"")
            .finish();
        let err = paths(&archive).unwrap_err();
        assert_eq!(err.kind(), &kind);
        assert_eq!(err.offset(), before.len() as u64, "the global header's own");
    }
}

#[test]
fn each_global_headers_records_reach_the_member_after_it_once() {
    // In stream order, on the member that follows the header, whatever the
    // mode; and one after the last member through the reader.
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"comment", b"one"))
        .file("a", b"")
        .file("b", b"")
        .pax(b'g', &pax_record(b"comment", b"two"))
        .file("c", b"")
        .pax(b'g', &pax_record(b"comment", b"three"))
        .finish();
    for mode in MODES {
        let mut reader = Reader::new(&archive[..]).with_global_headers(mode);
        let comments: Vec<Option<Vec<u8>>> = std::iter::from_fn(|| reader.next_entry().unwrap())
            .map(|entry| entry.global().get(b"comment").map(<[u8]>::to_vec))
            .collect();
        assert_eq!(
            comments,
            [Some(b"one".to_vec()), None, Some(b"two".to_vec())],
            "{mode:?}",
        );
        assert_eq!(
            reader.trailing_global().get(b"comment"),
            Some(&b"three"[..])
        );
    }

    // With none after the last member, there is none to deliver.
    let archive = Tar::new().file("a", b"").finish();
    let mut reader = Reader::new(&archive[..]);
    while reader.next_entry().unwrap().is_some() {}
    assert!(reader.trailing_global().is_empty());
}

#[test]
fn a_global_header_out_of_place_is_refused_in_every_mode() {
    // Two in a row, and one between metadata and its member: the families
    // read neither alike.
    for mode in MODES {
        for (archive, kind, at) in [
            (
                Tar::new()
                    .pax(b'g', &pax_record(b"comment", b"one"))
                    .pax(b'g', &pax_record(b"comment", b"two"))
                    .file("a", b"")
                    .finish(),
                ErrorKind::RepeatedMetadata(Metadata::GlobalHeader),
                2,
            ),
            (
                Tar::new()
                    .pax(b'x', &pax_record(b"path", b"xname"))
                    .pax(b'g', &pax_record(b"comment", b"c"))
                    .file("a", b"")
                    .finish(),
                ErrorKind::GlobalBetweenMetadata,
                2,
            ),
        ] {
            let err = members(&archive, mode).unwrap_err();
            assert_eq!((err.kind(), err.offset()), (&kind, at * 512), "{mode:?}");
        }
    }
}

#[test]
fn applied_records_lie_beneath_each_members_own() {
    // GNU tar and Python apply a global header's owner and time records to
    // every later member, the member's own extended header over them, and
    // both over the member's own header.
    let mut owned = Header::new("a", b'0', 0);
    owned.uid = 7;
    owned.gid = 8;
    let archive = Tar::new()
        .pax(
            b'g',
            &pax_records(&[
                (b"uid", b"1234"),
                (b"gid", b"4321"),
                (b"uname", b"guser"),
                (b"gname", b"ggroup"),
                (b"mtime", b"1000000.5"),
            ]),
        )
        .header(&owned)
        .pax(b'x', &pax_records(&[(b"uid", b"9"), (b"uname", b"own")]))
        .file("b", b"")
        .finish();
    let read = members(&archive, GlobalHeaders::Apply).unwrap();
    let owners: Vec<_> = read
        .iter()
        .map(|entry| (entry.uid(), entry.gid(), entry.uname(), entry.gname()))
        .collect();
    assert_eq!(
        owners,
        [
            (1234, 4321, &b"guser"[..], &b"ggroup"[..]),
            (9, 4321, b"own", b"ggroup"),
        ],
    );
    for entry in &read {
        assert_eq!(
            (entry.mtime().secs(), entry.mtime().nanos()),
            (1_000_000, 500_000_000)
        );
    }

    // Read in either of the other modes, the members are their own.
    let read = members(&archive, GlobalHeaders::Defer).unwrap();
    assert_eq!(
        (
            read[0].uid(),
            read[0].gid(),
            read[0].uname(),
            read[0].mtime().secs()
        ),
        (7, 8, &b""[..], 0),
    );
}

#[test]
fn an_applied_path_names_every_member_its_own_records_do_not() {
    let archive = Tar::new()
        .pax(
            b'g',
            &pax_records(&[(b"uid", b"1234"), (b"path", b"common")]),
        )
        .pax(b'x', &pax_record(b"path", b"one"))
        .file("a", b"")
        .pax(b'x', &pax_record(b"path", b"two"))
        .file("b", b"")
        .file("c", b"")
        .finish();
    let read = members(&archive, GlobalHeaders::Apply).unwrap();
    let names: Vec<&[u8]> = read.iter().map(Entry::path).collect();
    assert_eq!(names, [&b"one"[..], b"two", b"common"]);

    // A long name and an applied path that differ are refused, as a long name
    // and a member's own path record are; that agree, are read.
    for (long, refused) in [(&b"other\0"[..], true), (b"common\0", false)] {
        let archive = Tar::new()
            .pax(b'g', &pax_record(b"path", b"common"))
            .long(b'L', long)
            .file("short", b"")
            .finish();
        let result = members(&archive, GlobalHeaders::Apply);
        if refused {
            assert_eq!(
                result.unwrap_err().kind(),
                &ErrorKind::LongNameConflict {
                    keyword: Keyword::Path
                },
            );
        } else {
            assert_eq!(result.unwrap()[0].path(), b"common");
        }
    }
}

#[test]
fn an_applied_link_target_is_every_members() {
    // GNU tar and Python point every symbolic link at it; Python reports it
    // on a regular file as well.
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"linkpath", b"gtarget"))
        .header(&{
            let mut link = Header::new("l", b'2', 0);
            link.link = b"own".to_vec();
            link
        })
        .file("reg", b"")
        .finish();
    let read = members(&archive, GlobalHeaders::Apply).unwrap();
    let targets: Vec<&[u8]> = read.iter().map(Entry::link_target).collect();
    assert_eq!(targets, [&b"gtarget"[..], b"gtarget"]);
    let read = members(&archive, GlobalHeaders::Defer).unwrap();
    assert_eq!(read[0].link_target(), b"own");
}

#[test]
fn applying_refuses_what_gnu_tar_and_python_read_apart() {
    for (records, kind) in [
        // GNU tar frames the members after it by a global size; Python frames
        // each by its own header's and reports the global one.
        (
            pax_record(b"size", b"0"),
            ErrorKind::GlobalRecord {
                keyword: b"size".to_vec(),
            },
        ),
        // GNU tar does not apply a global attribute; Python reports it on
        // every member.
        (
            pax_record(b"SCHILY.xattr.user.k", b"v"),
            ErrorKind::GlobalRecord {
                keyword: b"SCHILY.xattr.user.k".to_vec(),
            },
        ),
        // Not measured against both.
        (
            pax_record(b"atime", b"1"),
            ErrorKind::GlobalRecord {
                keyword: b"atime".to_vec(),
            },
        ),
        // GNU tar reports a malformed header; Python reads an empty value.
        (
            pax_record(b"uid", b""),
            ErrorKind::PaxValue {
                keyword: Keyword::Uid,
                problem: Numeric::Unreadable,
            },
        ),
        (
            pax_record(b"uname", b""),
            ErrorKind::EmptyPaxValue {
                keyword: Keyword::Uname,
            },
        ),
    ] {
        let archive = Tar::new().pax(b'g', &records).file("a", b"").finish();
        let err = members(&archive, GlobalHeaders::Apply).unwrap_err();
        assert_eq!((err.kind(), err.offset()), (&kind, 0));
    }
}

#[test]
fn applying_refuses_a_global_header_after_one_that_set_a_field() {
    // GNU tar replaces the first header's records with the second's, so the
    // first's uid no longer applies; Python merges the two and keeps it. (With
    // no member between them, the second is refused for where it falls.)
    for between in [
        Tar::new().file("a", b"").unterminated(),
        Tar::new().file("a", b"").file("b", b"x").unterminated(),
    ] {
        let archive = Tar::new()
            .pax(b'g', &pax_record(b"uid", b"1234"))
            .raw(&between)
            .pax(b'g', &pax_record(b"comment", b"later"))
            .file("b", b"")
            .finish();
        let err = members(&archive, GlobalHeaders::Apply).unwrap_err();
        assert_eq!(err.kind(), &ErrorKind::SecondGlobal);
        assert_eq!(err.offset(), 2 * 512 + between.len() as u64);
        assert_eq!(
            err.to_string(),
            format!(
                "a global extended header follows one whose records apply to members at offset {}",
                err.offset(),
            ),
        );
    }

    // After one that set nothing, a later one is read: replacing a comment
    // and merging with one state the same fields.
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"comment", b"c"))
        .file("a", b"")
        .pax(b'g', &pax_record(b"uid", b"1234"))
        .file("b", b"")
        .finish();
    let uids: Vec<u32> = members(&archive, GlobalHeaders::Apply)
        .unwrap()
        .iter()
        .map(Entry::uid)
        .collect();
    assert_eq!(uids, [0, 1234]);
}

#[test]
fn deferring_applies_nothing_and_delivers_everything() {
    // bsdtar and Go read each member from its own headers, a global size
    // included; the records reach the caller.
    let records = pax_records(&[
        (b"size", b"0"),
        (b"path", b"renamed"),
        (b"uid", b"1234"),
        (b"SCHILY.xattr.user.k", b"v"),
        (b"vendor.anything", b""),
    ]);
    let archive = Tar::new()
        .pax(b'g', &records)
        .file("gfile", &[b'G'; 600])
        .file("next", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]).with_global_headers(GlobalHeaders::Defer);
    let gfile = reader.next_entry().unwrap().unwrap();
    assert_eq!(
        (gfile.path(), gfile.size(), gfile.uid()),
        (&b"gfile"[..], 600, 0)
    );
    assert_eq!(gfile.global().iter().count(), 5);
    assert_eq!(gfile.global().get(b"path"), Some(&b"renamed"[..]));
    assert!(gfile.pax_records().is_empty());
    assert_eq!(reader.read_entry(600).unwrap(), [b'G'; 600]);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"next");
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn a_global_keyword_repeated_with_different_values_is_refused_in_strict_and_where_applied() {
    // POSIX and Python take the last value, GNU tar the first, so the mode
    // that applies a global header refuses it at both levels. The others
    // read the records as they stand, the last value holding.
    let archive = Tar::new()
        .pax(
            b'g',
            &pax_records(&[(b"comment", b"one"), (b"comment", b"two")]),
        )
        .file("a", b"")
        .finish();
    let repeated = ErrorKind::RepeatedKeyword {
        keyword: b"comment".to_vec(),
    };
    for mode in MODES {
        let err = members(&archive, mode).unwrap_err();
        assert_eq!(err.kind(), &repeated);
        let mut reader = Reader::new(&archive[..])
            .with_global_headers(mode)
            .with_level(Level::Compatible);
        if mode == GlobalHeaders::Apply {
            assert_eq!(reader.next_entry().unwrap_err().kind(), &repeated);
            continue;
        }
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.global().get(b"comment"), Some(&b"two"[..]));
    }
    // An applied keyword given twice: GNU tar names the member `one`, Python
    // `two`.
    let archive = Tar::new()
        .pax(b'g', &pax_records(&[(b"path", b"one"), (b"path", b"two")]))
        .file("a", b"")
        .finish();
    for level in [Level::Strict, Level::Compatible] {
        let mut reader = Reader::new(&archive[..])
            .with_global_headers(GlobalHeaders::Apply)
            .with_level(level);
        let err = reader.next_entry().unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (
                &ErrorKind::RepeatedKeyword {
                    keyword: b"path".to_vec()
                },
                0
            ),
        );
    }
    let mut reader = Reader::new(&archive[..])
        .with_global_headers(GlobalHeaders::Defer)
        .with_level(Level::Compatible);
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"a");
}

#[test]
fn a_v7_global_header_is_a_global_header() {
    // Every reader reads a `g` without magic as it reads one with it.
    let mut header = Header::new("g", b'g', 0);
    header.magic = support::Magic::V7;
    for (records, refused) in [
        (pax_record(b"comment", b"c"), false),
        (pax_record(b"path", b"evilname"), true),
    ] {
        let archive = Tar::new()
            .entry(header.clone(), &records)
            .file("victim", b"")
            .finish();
        let result = paths(&archive);
        assert_eq!(result.is_err(), refused);
        if !refused {
            assert_eq!(result.unwrap(), [b"victim"]);
        }
    }
}

#[test]
fn a_deferred_global_header_lists_its_attributes_as_spelled() {
    // Applied to no member, a global header's attribute records are not held
    // to the rules a member's are; the modes that apply records refuse them.
    let records = pax_records(&[
        (b"SCHILY.xattr.user.eq%3Dx", b"v"),
        (b"LIBARCHIVE.xattr.user.k", b"bGli"),
    ]);
    let archive = Tar::new().pax(b'g', &records).file("member", b"").finish();
    let read = members(&archive, GlobalHeaders::Defer).unwrap();
    let names: Vec<&[u8]> = read[0].global().xattrs().map(|(name, _)| name).collect();
    assert_eq!(names, [&b"user.eq%3Dx"[..]]);
    assert!(read[0].pax_records().xattrs().next().is_none());
    for mode in [GlobalHeaders::Refuse, GlobalHeaders::Apply] {
        assert_eq!(
            members(&archive, mode).unwrap_err().kind(),
            &ErrorKind::GlobalRecord {
                keyword: b"SCHILY.xattr.user.eq%3Dx".to_vec(),
            },
        );
    }
}

#[test]
fn an_empty_global_header_is_refused_in_every_mode() {
    // bsdtar fails on it, reading nothing after it; GNU tar, Go and Python
    // read on.
    let leading = Tar::new().pax(b'g', b"").file("a", b"").finish();
    let trailing = Tar::new().file("a", b"").pax(b'g', b"").finish();
    for (archive, at) in [(leading, 0), (trailing, 512)] {
        for mode in MODES {
            for level in [Level::Strict, Level::Compatible] {
                let err = Reader::new(&archive[..])
                    .with_global_headers(mode)
                    .with_level(level);
                let err = members_of(err).unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::EmptyMetadata(Metadata::GlobalHeader), at)
                );
            }
        }
    }
}

fn members_of(mut reader: Reader<&[u8]>) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry()? {
        entries.push(entry);
    }
    Ok(entries)
}
