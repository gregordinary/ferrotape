//! Pax extended headers: framing, the records the reader applies, and the
//! records a member carries.

mod support;

use ferrotape::{
    EntryKind, Error, ErrorKind, Keyword, Level, Numeric, PaxFraming, Reader, Timestamp,
};
use support::{
    BLOCK, Header, Tar, first_at, pax_record, pax_records, with_records, with_records_at,
};

/// An archive whose extended header holds `records`, then a directory.
fn directory_with(records: &[u8]) -> Vec<u8> {
    Tar::new()
        .pax(b'x', records)
        .header(&Header::new("d/", b'5', 0))
        .finish()
}

/// The kind of the error reading a member whose extended header holds
/// `records` fails with.
fn refusal(records: &[u8]) -> ErrorKind {
    with_records(records)
        .expect_err("the records are refused")
        .kind()
        .clone()
}

#[test]
fn records_override_the_header_they_describe() {
    let records = pax_records(&[
        (b"path", b"some/long/file/name"),
        (b"size", b"5"),
        (b"mtime", b"1720000000.25"),
    ]);
    let archive = Tar::new()
        .pax(b'x', &records)
        .header(&support::Header::new("short", b'0', 0))
        .body(b"hello")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!(entry.path(), b"some/long/file/name");
    assert_eq!(entry.size(), 5);
    assert_eq!(entry.mtime().secs(), 1_720_000_000);
    assert_eq!(reader.read_entry(5).unwrap(), b"hello");
    assert!(reader.next_entry().unwrap().is_none());
}

#[test]
fn every_record_is_kept_in_order_those_applied_included() {
    let records = pax_records(&[
        (b"uid", b"1000"),
        (b"gname", b"users"),
        (b"SCHILY.fflags", b"nodump"),
        (b"comment", b"anything"),
    ]);
    let entry = with_records(&records).unwrap();
    assert_eq!((entry.uid(), entry.gname()), (1000, &b"users"[..]));
    let held: Vec<_> = entry.pax_records().iter().collect();
    assert_eq!(
        held,
        [
            (&b"uid"[..], &b"1000"[..]),
            (b"gname", b"users"),
            (b"SCHILY.fflags", b"nodump"),
            (b"comment", b"anything"),
        ],
    );
    assert_eq!(
        entry.pax_records().get(b"SCHILY.fflags"),
        Some(&b"nodump"[..])
    );
    assert_eq!(entry.pax_records().get(b"absent"), None);

    // A member no extended header precedes has none.
    let plain = support::first(&Tar::new().file("plain", b"").finish()).unwrap();
    assert!(plain.pax_records().is_empty());
    assert_eq!(plain.pax_records().iter().count(), 0);
}

#[test]
fn a_keyword_repeated_with_different_values_is_refused_in_strict_and_read_as_its_last_in_compatible()
 {
    // POSIX gives the last record of a keyword precedence, and GNU tar,
    // bsdtar, Go and Python take it; the `tar` crate takes the first. Any
    // keyword counts, a vendor's included, since the records reach the caller.
    for (keyword, first, last) in [
        (&b"path"[..], &b"first"[..], &b"second"[..]),
        (b"mtime", b"1", b"2"),
        (b"comment", b"first", b"second"),
        (b"SCHILY.xattr.user.k", b"a", b"b"),
    ] {
        // Another record between the two, so that they are not neighbours.
        let records = pax_records(&[(keyword, first), (b"uid", b"7"), (keyword, last)]);
        assert_eq!(
            *with_records(&records).unwrap_err().kind(),
            ErrorKind::RepeatedKeyword {
                keyword: keyword.to_vec(),
            },
        );
        let entry = with_records_at(&records, Level::Compatible).unwrap();
        assert_eq!(entry.pax_records().get(keyword), Some(last));
        assert_eq!(entry.pax_records().iter().count(), 3);
        if keyword == b"path" {
            assert_eq!(entry.path(), last);
        }
    }
}

#[test]
fn a_keyword_repeated_with_one_value_is_read_at_both_levels() {
    let records = pax_records(&[(b"path", b"same"), (b"comment", b"c"), (b"path", b"same")]);
    for level in [Level::Strict, Level::Compatible] {
        let entry = with_records_at(&records, level).unwrap();
        assert_eq!(entry.path(), b"same");
        assert_eq!(entry.pax_records().iter().count(), 3);
    }
}

#[test]
fn access_and_change_times_are_read_where_pax_states_them() {
    let entry = with_records(&pax_records(&[
        (b"atime", b"1700000000.5"),
        (b"ctime", b"-3"),
    ]))
    .unwrap();
    let atime = entry.atime().unwrap();
    assert_eq!((atime.secs(), atime.nanos()), (1_700_000_000, 500_000_000));
    assert_eq!(entry.ctime().unwrap().secs(), -3);

    let plain = support::first(&Tar::new().file("plain", b"").finish()).unwrap();
    assert_eq!((plain.atime(), plain.ctime()), (None, None));
}

#[test]
fn a_record_is_framed_by_its_length_so_a_value_may_hold_a_newline() {
    let records = pax_records(&[(b"SCHILY.xattr.user.k", b"a\nb"), (b"comment", b"after")]);
    let entry = with_records(&records).unwrap();
    assert_eq!(entry.pax_records().xattr(b"user.k"), Some(&b"a\nb"[..]));
    assert_eq!(entry.pax_records().get(b"comment"), Some(&b"after"[..]));
}

#[test]
fn a_record_that_does_not_frame_is_refused() {
    for (records, framing) in [
        // The length overruns the header's data.
        (&b"30 uid=1000\n"[..], PaxFraming::LengthOutOfBounds),
        (b"999 path=x\n", PaxFraming::LengthOutOfBounds),
        // The length ends before the keyword.
        (b"2 path=x\n", PaxFraming::LengthOutOfBounds),
        (b"0 path=x\n", PaxFraming::LengthOutOfBounds),
        // The length ends inside the record, or inside the next one: the
        // record it frames does not end in a newline.
        (b"3 path=x\n", PaxFraming::NoNewline),
        (b"22 uid=1000\n23 gname=abc\n", PaxFraming::NoNewline),
        (b"path=x\n", PaxFraming::NoDelimiter),
        // An integer parser's sign is not a digit.
        (b"+12 uid=1000\n", PaxFraming::BadLength),
        (b"8 path=x", PaxFraming::NoNewline),
        (b"9 pathxx\n", PaxFraming::NoEquals),
    ] {
        assert_eq!(
            refusal(records),
            ErrorKind::PaxFraming(framing),
            "{}",
            records.escape_ascii(),
        );
    }
    let err = with_records(b"999 path=x\n").unwrap_err();
    assert_eq!(err.offset(), 0, "the extended header's own offset");
    assert_eq!(
        err.to_string(),
        "a pax record's length is out of bounds at offset 0",
    );
}

#[test]
fn a_pax_time_floors_to_the_nanosecond() {
    // Digits past the nanosecond are dropped. A time before 1970 is read in
    // whole seconds; one with a fraction is refused (below).
    for (spelled, secs, nanos) in [
        (&b"1720000000.25"[..], 1_720_000_000, 250_000_000),
        (b"1.123456789", 1, 123_456_789),
        (b"1.1234567899", 1, 123_456_789),
        // A zero fraction is no fraction, in either direction.
        (b"-1.0", -1, 0),
        (b"-1.0000000000", -1, 0),
        (b"-1", -1, 0),
        (b"-0.0", 0, 0),
        (b"7.", 7, 0),
    ] {
        for keyword in [&b"mtime"[..], b"atime", b"ctime"] {
            let entry = with_records(&pax_record(keyword, spelled)).unwrap();
            let time = match keyword {
                b"mtime" => entry.mtime(),
                b"atime" => entry.atime().unwrap(),
                _ => entry.ctime().unwrap(),
            };
            assert_eq!(
                (time.secs(), time.nanos()),
                (secs, nanos),
                "{}={}",
                keyword.escape_ascii(),
                spelled.escape_ascii(),
            );
        }
    }
}

#[test]
fn a_time_before_1970_with_a_fraction_is_refused() {
    // bsdtar reads the fraction forward from the second the digits name:
    // `-1.5` as -0.5, where GNU tar, Go and Python read -1.5.
    for spelled in [
        &b"-1.5"[..],
        b"-0.5",
        b"-0.1234567891",
        b"-0.9999999999",
        b"-1.0000000001",
    ] {
        for (keyword, known) in [
            (&b"mtime"[..], Keyword::Mtime),
            (b"atime", Keyword::Atime),
            (b"ctime", Keyword::Ctime),
        ] {
            for level in [Level::Strict, Level::Compatible] {
                assert_eq!(
                    *with_records_at(&pax_record(keyword, spelled), level)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::FractionBeforeEpoch { keyword: known },
                    "{}={}",
                    keyword.escape_ascii(),
                    spelled.escape_ascii(),
                );
            }
        }
    }
    assert_eq!(
        with_records(&pax_record(b"mtime", b"-1.5"))
            .unwrap_err()
            .to_string(),
        "a pax `mtime` record is before 1970 and has a fraction of a second at offset 0",
    );
}

#[test]
fn a_keyword_holding_a_nul_is_refused() {
    // GNU tar and bsdtar end a keyword at a NUL, and Go refuses the archive:
    // `SCHILY.xattr.user.a\0b` is malformed for GNU tar, `user.a` for bsdtar.
    let records = pax_record(b"SCHILY.xattr.user.a\0b", b"v");
    for level in [Level::Strict, Level::Compatible] {
        assert_eq!(
            *with_records_at(&records, level).unwrap_err().kind(),
            ErrorKind::PaxFraming(PaxFraming::KeywordNul),
        );
    }
    assert_eq!(
        refusal(&pax_record(b"comm\0ent", b"c")),
        ErrorKind::PaxFraming(PaxFraming::KeywordNul)
    );
    // A NUL in a value is the value's: a binary attribute holds them.
    let entry = with_records(&pax_record(b"SCHILY.xattr.user.k", b"a\0b")).unwrap();
    assert_eq!(entry.pax_records().xattr(b"user.k"), Some(&b"a\0b"[..]));
}

#[test]
fn a_real_size_record_other_than_a_file_s_size_is_refused() {
    // bsdtar takes `SCHILY.realsize` as a file's size, and extracts that many
    // bytes, where GNU tar, Go and Python ignore it.
    let member = |records: &[u8], header: Header, data: &[u8]| {
        Tar::new().pax(b'x', records).entry(header, data).finish()
    };
    for value in [&b"100000"[..], b"3", b"x", b"", b"+6", b" 6"] {
        for typeflag in *b"07Z" {
            let archive = member(
                &pax_record(b"SCHILY.realsize", value),
                Header::new("f", typeflag, 6),
                b"hello\n",
            );
            for level in [Level::Strict, Level::Compatible] {
                let err = Reader::new(&archive[..])
                    .with_level(level)
                    .next_entry()
                    .unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::RealSizeRecord, 2 * BLOCK as u64),
                    "{} {} {level:?}",
                    value.escape_ascii(),
                    char::from(typeflag),
                );
            }
        }
    }
    // A hard link takes it as its size too.
    let mut link = Header::new("h", b'1', 0);
    link.link = b"f".to_vec();
    let archive = Tar::new()
        .file("f", b"x")
        .pax(b'x', &pax_record(b"SCHILY.realsize", b"5"))
        .header(&link)
        .finish();
    let mut reader = Reader::new(&archive[..]);
    reader.next_entry().unwrap();
    assert_eq!(
        reader.next_entry().unwrap_err().kind(),
        &ErrorKind::RealSizeRecord
    );
    // The member's own size is read, as are the kinds bsdtar ignores it on.
    for value in [&b"6"[..], b"06"] {
        let archive = member(
            &pax_record(b"SCHILY.realsize", value),
            Header::new("f", b'0', 6),
            b"hello\n",
        );
        assert_eq!(first_at(&archive, Level::Strict).unwrap().size(), 6);
    }
    for (name, typeflag) in [("d/", b'5'), ("p", b'6'), ("c", b'3'), ("b", b'4')] {
        let archive = member(
            &pax_record(b"SCHILY.realsize", b"100000"),
            Header::new(name, typeflag, 0),
            b"",
        );
        assert!(first_at(&archive, Level::Strict).is_ok(), "{name}");
    }
    let mut symlink = Header::new("l", b'2', 0);
    symlink.link = b"t".to_vec();
    let archive = Tar::new()
        .pax(b'x', &pax_record(b"SCHILY.realsize", b"100000"))
        .header(&symlink)
        .finish();
    assert!(first_at(&archive, Level::Strict).is_ok());
}

#[test]
fn a_keyword_beginning_with_a_space_or_a_tab_is_refused() {
    // GNU tar passes over spaces and tabs after the length's space and applies
    // the record by the keyword after them; bsdtar, Go and Python keep them,
    // and apply nothing. `21  path=evil/passwd` names the member for GNU tar
    // alone, and ` size=512` hides the member after it from GNU tar alone.
    for keyword in [
        &b" path"[..],
        b"\tpath",
        b" \tpath",
        b" size",
        b" SCHILY.xattr.user.k",
    ] {
        for level in [Level::Strict, Level::Compatible] {
            let err = with_records_at(&pax_record(keyword, b"512"), level).unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (&ErrorKind::PaxFraming(PaxFraming::BlankBeforeKeyword), 0),
                "{} {level:?}",
                keyword.escape_ascii(),
            );
        }
    }
    // Every reader reads a blank after or inside a keyword, or any other
    // byte before it, as part of a keyword none applies.
    for keyword in [
        &b"path "[..],
        b"pa th",
        b"path\t",
        b"\npath",
        b"\x0bpath",
        b"\x0cpath",
        b"\rpath",
    ] {
        let entry = with_records(&pax_record(keyword, b"evil")).unwrap();
        assert_ne!(entry.path(), b"evil", "{}", keyword.escape_ascii());
        assert_eq!(entry.pax_records().get(keyword), Some(&b"evil"[..]));
    }
}

#[test]
fn an_empty_keyword_is_refused() {
    // GNU tar and bsdtar read on past the record. Python ends the archive at
    // its member, having listed the members before it, and Go fails there.
    let archive = Tar::new()
        .file("one", b"1\n")
        .pax(b'x', &pax_record(b"", b"x"))
        .file("two", b"2\n")
        .finish();
    for level in [Level::Strict, Level::Compatible] {
        let mut reader = Reader::new(&archive[..]).with_level(level);
        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"one");
        let err = reader.next_entry().unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (
                &ErrorKind::PaxFraming(PaxFraming::EmptyKeyword),
                2 * BLOCK as u64
            ),
            "{level:?}",
        );
    }
    assert_eq!(
        refusal(&pax_record(b"", b"x")).to_string(),
        "a pax record's keyword is empty",
    );
}

#[test]
fn times_order_chronologically() {
    let at = |secs, nanos| Timestamp::new(secs, nanos).unwrap();
    // -1.5 seconds is the second -2 and half a second past it.
    let mut times = [
        at(1, 500_000_000),
        at(-2, 500_000_000),
        at(0, 0),
        at(-1, 750_000_000),
        at(1, 0),
        at(-2, 0),
    ];
    times.sort();
    assert_eq!(
        times,
        [
            at(-2, 0),
            at(-2, 500_000_000),
            at(-1, 750_000_000),
            at(0, 0),
            at(1, 0),
            at(1, 500_000_000),
        ]
    );
    assert_eq!(Timestamp::new(0, 1_000_000_000), None);
    assert_eq!(Timestamp::from_secs(-3), at(-3, 0));
}

#[test]
fn a_number_is_decimal_digits_and_nothing_else() {
    // An integer parser also takes a leading `+`, which no writer emits; GNU
    // tar refuses a `size` of `+5`, and bsdtar misframes the archive on it.
    for (keyword, spelled, known) in [
        (&b"size"[..], &b"+1234"[..], Keyword::Size),
        (b"uid", b"+1000", Keyword::Uid),
        (b"gid", b" 1000", Keyword::Gid),
        (b"mtime", b"+1000", Keyword::Mtime),
        (b"mtime", b"1000.+5", Keyword::Mtime),
        (b"mtime", b"1.2.3", Keyword::Mtime),
        (b"mtime", b".5", Keyword::Mtime),
        (b"mtime", b"-", Keyword::Mtime),
        (b"uid", b"-1000", Keyword::Uid),
        (b"gid", b"zzzz", Keyword::Gid),
    ] {
        assert_eq!(
            refusal(&pax_record(keyword, spelled)),
            ErrorKind::PaxValue {
                keyword: known,
                problem: Numeric::Unreadable,
            },
            "{}",
            spelled.escape_ascii(),
        );
    }

    // The extremes the forms reach still read.
    let entry = with_records(&pax_record(b"mtime", b"-9223372036854775808")).unwrap();
    assert_eq!((entry.mtime().secs(), entry.mtime().nanos()), (i64::MIN, 0));
    for (keyword, spelled, known) in [
        (&b"mtime"[..], &b"9223372036854775808"[..], Keyword::Mtime),
        (b"mtime", b"-9223372036854775808.5", Keyword::Mtime),
        (b"size", b"99999999999999999999999", Keyword::Size),
    ] {
        assert_eq!(
            refusal(&pax_record(keyword, spelled)),
            ErrorKind::PaxValue {
                keyword: known,
                problem: Numeric::OutOfRange,
            },
            "{}",
            spelled.escape_ascii(),
        );
    }
}

#[test]
fn ownership_records_are_read_and_held_to_32_bits() {
    // GNU tar writes these where an id does not fit the header's octal field,
    // so an archive of a tree with high ids carries its ownership here and
    // nowhere else.
    let entry = with_records(&pax_records(&[
        (b"uid", b"888888"),
        (b"gid", b"4294967295"),
    ]))
    .unwrap();
    assert_eq!((entry.uid(), entry.gid()), (888_888, u32::MAX));

    // GNU tar refuses an id of 2^32, and the other readers read one; ids are
    // 32-bit here.
    assert_eq!(
        refusal(&pax_record(b"uid", b"4294967296")),
        ErrorKind::PaxValue {
            keyword: Keyword::Uid,
            problem: Numeric::OutOfRange,
        },
    );
}

#[test]
fn a_size_of_2_to_the_60_or_more_is_refused() {
    // bsdtar stops at a member declaring 2^60 or more, where GNU tar, Go and
    // Python read on. The member is not read past its header, so its data
    // need not be there.
    let entry = with_records(&pax_record(b"size", b"1152921504606846975")).unwrap();
    assert_eq!(entry.size(), (1 << 60) - 1);
    for size in [&b"1152921504606846976"[..], b"18446744073709551105"] {
        assert_eq!(
            refusal(&pax_record(b"size", size)),
            ErrorKind::PaxValue {
                keyword: Keyword::Size,
                problem: Numeric::OutOfRange,
            },
        );
    }
}

#[test]
fn a_name_link_target_or_owner_holding_a_nul_is_refused() {
    // A record's length, not a NUL, ends its value, and the readers disagree
    // over what such a name names: GNU tar and bsdtar cut it at the NUL,
    // Python keeps it, and Go refuses the archive.
    for (keyword, known) in [
        (&b"path"[..], Keyword::Path),
        (b"linkpath", Keyword::Linkpath),
        (b"uname", Keyword::Uname),
        (b"gname", Keyword::Gname),
    ] {
        assert_eq!(
            refusal(&pax_record(keyword, b"abc\0def")),
            ErrorKind::PaxNul { keyword: known },
        );
    }
    // A record the reader does not apply may hold one.
    let entry = with_records(&pax_record(b"comment", b"abc\0def")).unwrap();
    assert_eq!(entry.pax_records().get(b"comment"), Some(&b"abc\0def"[..]));
}

#[test]
fn an_empty_name_link_target_or_owner_is_refused() {
    // bsdtar and Go read an empty value as the record deleted, the header's
    // own field standing; Python reads it as the empty value, and GNU tar does
    // for each of these but `path`.
    for (keyword, known) in [
        (&b"path"[..], Keyword::Path),
        (b"linkpath", Keyword::Linkpath),
        (b"uname", Keyword::Uname),
        (b"gname", Keyword::Gname),
    ] {
        assert_eq!(
            refusal(&pax_record(keyword, b"")),
            ErrorKind::EmptyPaxValue { keyword: known },
        );
    }
    // A numeric record refuses one as no number.
    for (keyword, known) in [
        (&b"size"[..], Keyword::Size),
        (b"uid", Keyword::Uid),
        (b"gid", Keyword::Gid),
        (b"mtime", Keyword::Mtime),
    ] {
        assert_eq!(
            refusal(&pax_record(keyword, b"")),
            ErrorKind::PaxValue {
                keyword: known,
                problem: Numeric::Unreadable,
            },
        );
    }
    // A record the reader does not apply keeps its empty value, as GNU tar
    // writes an empty default list for a directory without one.
    let entry = first_at(
        &directory_with(&pax_records(&[
            (b"SCHILY.acl.default", b""),
            (b"comment", b""),
        ])),
        Level::Strict,
    )
    .unwrap();
    assert_eq!(
        entry.pax_records().get(b"SCHILY.acl.default"),
        Some(&b""[..])
    );
    // An attribute's empty value is refused: GNU tar and bsdtar set an empty
    // attribute, and Go reads the record as deleted.
    for level in [Level::Strict, Level::Compatible] {
        assert_eq!(
            *with_records_at(&pax_record(b"SCHILY.xattr.user.k", b""), level)
                .unwrap_err()
                .kind(),
            ErrorKind::EmptyXattr {
                keyword: b"SCHILY.xattr.user.k".to_vec(),
            },
        );
    }
    assert_eq!(
        with_records(&pax_record(b"SCHILY.xattr.user.k", b""))
            .unwrap_err()
            .to_string(),
        "`SCHILY.xattr.user.k` sets an empty attribute, which readers read as set and as \
         deleted at offset 0",
    );

    let err = with_records(&pax_record(b"path", b"")).unwrap_err();
    assert_eq!(err.offset(), 0, "the extended header's own offset");
    assert_eq!(err.to_string(), "a pax `path` record is empty at offset 0");
}

/// The `SCHILY.xattr.` keyword of the attribute `name`.
fn schily(name: &[u8]) -> Vec<u8> {
    [&b"SCHILY.xattr."[..], name].concat()
}

/// The `LIBARCHIVE.xattr.` keyword of the attribute `name`.
fn libarchive(name: &[u8]) -> Vec<u8> {
    [&b"LIBARCHIVE.xattr."[..], name].concat()
}

#[test]
fn extended_attribute_names_are_read_as_spelled() {
    // Every spelling here is extracted under this name by GNU tar 1.35 and
    // bsdtar, and reported so by Go: GNU tar decodes only `%3D` and `%25`, in
    // that case, and the others read a name as spelled. GNU tar writes a name
    // holding a space or a byte above 0x7e as its bytes.
    let names: [&[u8]; 8] = [
        b"user.plain",
        b"user.lower%3dx",
        b"user.other%41x",
        b"user.trail%",
        b"user.short%3",
        b"user.sp ace",
        b"user.hi\xc3\xa9",
        b"user.raw\xff",
    ];
    let mut records = Vec::new();
    for (index, name) in names.iter().enumerate() {
        records.extend(pax_record(&schily(name), format!("v{index}").as_bytes()));
    }
    // A record that names no attribute is passed over.
    records.extend(pax_record(b"comment", b"c"));
    for level in [Level::Strict, Level::Compatible] {
        let entry = with_records_at(&records, level).unwrap();
        let read: Vec<(Vec<u8>, Vec<u8>)> = entry
            .pax_records()
            .xattrs()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        let expected: Vec<(Vec<u8>, Vec<u8>)> = names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.to_vec(), format!("v{index}").into_bytes()))
            .collect();
        assert_eq!(read, expected);
        assert_eq!(
            entry.pax_records().xattr(b"user.other%41x"),
            Some(&b"v2"[..])
        );
        assert_eq!(entry.pax_records().xattr(b"user.otherAx"), None);
    }
}

#[test]
fn an_attribute_name_the_readers_extract_differently_is_refused() {
    // GNU tar writes `=` in a name as `%3D` and `%` as `%25`, and extracts
    // `user.eq%3Dsign` as `user.eq=sign`; bsdtar extracts it as spelled, and
    // Go reports it so.
    for spelled in [
        &b"user.eq%3Dsign"[..],
        b"user.pct%25sign",
        b"user.dbl%2525",
        b"user.both%25%3D",
        b"%3D",
        // No reader extracts an attribute with an empty name; Go reports one.
        b"",
    ] {
        let records = pax_records(&[(b"comment", b"c"), (&schily(spelled), b"v")]);
        for level in [Level::Strict, Level::Compatible] {
            assert_eq!(
                *with_records_at(&records, level).unwrap_err().kind(),
                ErrorKind::XattrName {
                    keyword: schily(spelled),
                },
                "{}",
                spelled.escape_ascii(),
            );
        }
    }
    let err = with_records(&pax_record(b"SCHILY.xattr.user.eq%3Dx", b"v")).unwrap_err();
    assert_eq!(err.offset(), 0, "the extended header's own offset");
    assert_eq!(
        err.to_string(),
        "readers extract the attribute `SCHILY.xattr.user.eq%3Dx` names differently at offset 0",
    );
}

#[test]
fn a_libarchive_record_that_repeats_its_schily_record_is_read() {
    // bsdtar writes the `LIBARCHIVE.xattr.` record first, its value base64
    // without padding; either order and either padding is extracted alike by
    // every reader.
    let cases: [&[(&[u8], &[u8])]; 5] = [
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZQ"),
            (b"SCHILY.xattr.user.k", b"same"),
        ],
        &[
            (b"SCHILY.xattr.user.k", b"same"),
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZQ"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZQ=="),
            (b"SCHILY.xattr.user.k", b"same"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZTI="),
            (b"SCHILY.xattr.user.k", b"same2"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"bGli"),
            (b"SCHILY.xattr.user.k", b"lib"),
        ],
    ];
    for case in cases {
        let records = pax_records(case);
        for level in [Level::Strict, Level::Compatible] {
            let entry = with_records_at(&records, level).unwrap();
            let schily_value = case
                .iter()
                .find(|(keyword, _)| keyword.starts_with(b"SCHILY."))
                .map(|(_, value)| *value);
            assert_eq!(entry.pax_records().xattr(b"user.k"), schily_value);
            assert_eq!(entry.pax_records().xattrs().count(), 1);
            assert_eq!(entry.pax_records().iter().count(), 2);
        }
    }

    // A binary value, as `security.capability`'s, among other attributes.
    let capability = b"\x01\0\0\x02\x00\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let records = pax_records(&[
        (b"LIBARCHIVE.xattr.user.a", b"YQ"),
        (
            b"LIBARCHIVE.xattr.security.capability",
            b"AQAAAgAgAAAAAAAAAAAAAAAAAAA",
        ),
        (b"SCHILY.xattr.user.a", b"a"),
        (b"SCHILY.xattr.security.capability", capability),
    ]);
    let entry = with_records(&records).unwrap();
    assert_eq!(
        entry.pax_records().xattr(b"security.capability"),
        Some(&capability[..]),
    );
}

#[test]
fn a_libarchive_record_that_no_schily_record_repeats_is_refused() {
    // bsdtar applies a `LIBARCHIVE.xattr.` record, URL-decoding its name and
    // base64-decoding its value, and lets a later record of a name replace an
    // earlier one; GNU tar and Go do not apply it at all.
    let cases: [&[(&[u8], &[u8])]; 15] = [
        // Alone: bsdtar extracts `user.k`, GNU tar nothing.
        &[(b"LIBARCHIVE.xattr.user.k", b"bGli")],
        // Another value, in either order: bsdtar takes the later.
        &[
            (b"LIBARCHIVE.xattr.user.k", b"bGli"),
            (b"SCHILY.xattr.user.k", b"sch"),
        ],
        &[
            (b"SCHILY.xattr.user.k", b"sch"),
            (b"LIBARCHIVE.xattr.user.k", b"bGli"),
        ],
        // Another name, with that name's value: by case either way, and one
        // that sorts after the attribute the archive holds.
        &[
            (b"LIBARCHIVE.xattr.user.K", b"c2No"),
            (b"SCHILY.xattr.user.k", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2No"),
            (b"SCHILY.xattr.user.K", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.z", b"c2No"),
            (b"SCHILY.xattr.user.a", b"sch"),
        ],
        // A name bsdtar decodes: its own spelling of `user.sp ace`, which GNU
        // tar extracts as `user.sp%20ace` and bsdtar as both names.
        &[
            (b"LIBARCHIVE.xattr.user.sp%20ace", b"c2No"),
            (b"SCHILY.xattr.user.sp%20ace", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.low%3dx", b"c2No"),
            (b"SCHILY.xattr.user.low%3dx", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.trail%", b"c2No"),
            (b"SCHILY.xattr.user.trail%", b"sch"),
        ],
        // Values bsdtar decodes to `sch`, but not as base64 is written: the
        // padding short or long, a byte it skips, bits past the last byte.
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2No="),
            (b"SCHILY.xattr.user.k", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZQ="),
            (b"SCHILY.xattr.user.k", b"same"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZQ==="),
            (b"SCHILY.xattr.user.k", b"same"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2!No"),
            (b"SCHILY.xattr.user.k", b"sch"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"c2FtZR"),
            (b"SCHILY.xattr.user.k", b"same"),
        ],
        &[
            (b"LIBARCHIVE.xattr.user.k", b"!!notb64"),
            (b"SCHILY.xattr.user.k", b"sch"),
        ],
    ];
    for case in cases {
        let records = pax_records(case);
        let keyword = case
            .iter()
            .find(|(keyword, _)| keyword.starts_with(b"LIBARCHIVE."))
            .map(|(keyword, _)| keyword.to_vec())
            .unwrap();
        for level in [Level::Strict, Level::Compatible] {
            assert_eq!(
                *with_records_at(&records, level).unwrap_err().kind(),
                ErrorKind::XattrConflict {
                    keyword: keyword.clone(),
                },
                "{case:?}",
            );
        }
    }
    let err = with_records(&pax_record(&libarchive(b"user.k"), b"bGli")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "`LIBARCHIVE.xattr.user.k` states an attribute no `SCHILY.xattr.` record states alike \
         at offset 0",
    );
}

#[test]
fn a_libarchive_record_repeats_the_last_schily_record_of_its_name() {
    // A name's records repeated with different values are refused in Strict.
    // In Compatible the last holds, for GNU tar as for bsdtar, which applies
    // every record of the name in order; a `LIBARCHIVE.xattr.` record holding
    // an earlier value would leave bsdtar with that value where it falls
    // last.
    let last = pax_records(&[
        (b"SCHILY.xattr.user.k", b"one"),
        (b"SCHILY.xattr.user.k", b"two"),
        (b"LIBARCHIVE.xattr.user.k", b"dHdv"),
    ]);
    let entry = with_records_at(&last, Level::Compatible).unwrap();
    assert_eq!(entry.pax_records().xattr(b"user.k"), Some(&b"two"[..]));
    assert_eq!(entry.pax_records().xattrs().count(), 2);
    assert_eq!(
        *with_records(&last).unwrap_err().kind(),
        ErrorKind::RepeatedKeyword {
            keyword: schily(b"user.k"),
        },
    );

    let earlier = pax_records(&[
        (b"SCHILY.xattr.user.k", b"one"),
        (b"SCHILY.xattr.user.k", b"two"),
        (b"LIBARCHIVE.xattr.user.k", b"b25l"),
    ]);
    assert_eq!(
        *with_records_at(&earlier, Level::Compatible)
            .unwrap_err()
            .kind(),
        ErrorKind::XattrConflict {
            keyword: libarchive(b"user.k"),
        },
    );
}

#[test]
fn both_forms_of_an_access_control_list_are_delivered_as_the_archive_holds_them() {
    // GNU tar writes a list as the attribute's binary value with `--xattrs`,
    // and as text with `--acls`; an archive may hold either, or both.
    let records = pax_records(&[
        (b"SCHILY.xattr.system.posix_acl_access", b"\x02\0\0\0list"),
        (
            b"SCHILY.xattr.system.posix_acl_default",
            b"\x02\0\0\0default",
        ),
        (b"SCHILY.xattr.user.comment", b"other"),
        (b"SCHILY.acl.access", b"user::rw-"),
        (b"SCHILY.acl.default", b"user::rwx"),
    ]);
    let entry = first_at(&directory_with(&records), Level::Strict).unwrap();
    let records = entry.pax_records();
    assert_eq!(
        records.xattr(b"system.posix_acl_access"),
        Some(&b"\x02\0\0\0list"[..]),
    );
    assert_eq!(
        records.xattr(b"system.posix_acl_default"),
        Some(&b"\x02\0\0\0default"[..]),
    );
    assert_eq!(records.get(b"SCHILY.acl.access"), Some(&b"user::rw-"[..]));
    assert_eq!(records.get(b"SCHILY.acl.default"), Some(&b"user::rwx"[..]));
    assert_eq!(records.xattr(b"user.comment"), Some(&b"other"[..]));

    // Each list's two forms, together.
    let access = records.access_acl();
    assert_eq!(
        (access.binary(), access.text()),
        (Some(&b"\x02\0\0\0list"[..]), Some(&b"user::rw-"[..])),
    );
    let default = records.default_acl();
    assert_eq!(
        (default.binary(), default.text()),
        (Some(&b"\x02\0\0\0default"[..]), Some(&b"user::rwx"[..])),
    );
}

#[test]
fn an_access_control_list_in_one_form_is_delivered_in_that_form() {
    // GNU tar writes an empty `SCHILY.acl.default` for a directory with no
    // default list: a form, holding nothing.
    let entry = first_at(
        &directory_with(&pax_records(&[
            (b"SCHILY.xattr.system.posix_acl_access", b"\x02\0\0\0list"),
            (b"SCHILY.acl.default", b""),
        ])),
        Level::Strict,
    )
    .unwrap();
    let access = entry.pax_records().access_acl();
    assert_eq!(
        (access.binary(), access.text()),
        (Some(&b"\x02\0\0\0list"[..]), None)
    );
    let default = entry.pax_records().default_acl();
    assert_eq!((default.binary(), default.text()), (None, Some(&b""[..])));
    assert!(!default.is_empty());

    let plain = support::first(&Tar::new().file("plain", b"").finish()).unwrap();
    assert!(plain.pax_records().access_acl().is_empty());
    assert!(plain.pax_records().default_acl().is_empty());
}

#[test]
fn a_default_list_on_a_member_that_is_not_a_directory_is_refused() {
    // bsdtar takes the mode of such a member from its lists' text, `000`, and
    // GNU tar, Go and Python read the header's; the kernel refuses the list.
    let kinds = [
        (b'0', EntryKind::File),
        (0, EntryKind::File),
        (b'7', EntryKind::File),
        (b'Z', EntryKind::File),
        (b'1', EntryKind::HardLink),
        (b'2', EntryKind::Symlink),
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
        (b'6', EntryKind::Fifo),
    ];
    for (typeflag, kind) in kinds {
        for value in [&b"user::rwx,group::r-x,other::r-x"[..], b""] {
            let mut member = Header::new("m", typeflag, 0);
            member.link = b"t".to_vec();
            let archive = Tar::new()
                .file("t", b"")
                .pax(b'x', &pax_record(b"SCHILY.acl.default", value))
                .header(&member)
                .finish();
            for level in [Level::Strict, Level::Compatible] {
                let mut reader = Reader::new(&archive[..]).with_level(level);
                reader.next_entry().unwrap();
                let err = reader.next_entry().unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (
                        &ErrorKind::DefaultAclWithoutDirectory { kind },
                        3 * BLOCK as u64
                    ),
                    "{typeflag:?} {value:?} {level:?}: the member's own header",
                );
            }
        }
    }
    // Beside an access list too, which no writer writes either.
    let records = pax_records(&[
        (b"SCHILY.acl.access", b"user::rw-,group::r--,other::r--"),
        (b"SCHILY.acl.default", b"user::rwx,group::r-x,other::r-x"),
    ]);
    let err = with_records(&records).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::DefaultAclWithoutDirectory {
            kind: EntryKind::File
        },
    );
    assert_eq!(
        err.to_string(),
        "a regular file, which is not a directory, has a default access control list at \
         offset 1024",
    );

    // A directory carries one at both levels, a GNU dumpdir among them; so
    // does any member its binary form alone, which bsdtar lists with the
    // header's mode.
    let list = pax_record(b"SCHILY.acl.default", b"user::rwx,group::r-x,other::r-x");
    let mut dumpdir = Header::new("dump/", b'D', 0);
    dumpdir.magic = support::Magic::Gnu;
    for member in [
        Header::new("d/", b'5', 0),
        Header::new("d", b'5', 0),
        dumpdir,
    ] {
        let archive = Tar::new().pax(b'x', &list).header(&member).finish();
        for level in [Level::Strict, Level::Compatible] {
            let entry = first_at(&archive, level).unwrap();
            assert_eq!(entry.kind(), EntryKind::Directory);
            assert_eq!(
                entry.pax_records().default_acl().text(),
                Some(&b"user::rwx,group::r-x,other::r-x"[..])
            );
        }
    }
    let binary = pax_record(b"SCHILY.xattr.system.posix_acl_default", b"\x02\0\0\0list");
    for level in [Level::Strict, Level::Compatible] {
        let entry: Result<_, Error> = with_records_at(&binary, level);
        assert_eq!(
            entry.unwrap().pax_records().default_acl().binary(),
            Some(&b"\x02\0\0\0list"[..]),
        );
    }
}

#[test]
fn a_vendor_record_is_passed_through_whatever_it_holds() {
    // A vendor keyword is the vendor's to read. apk writes this one for every
    // file of a package; one that is not a digest at all is still the
    // caller's to judge.
    for value in [&b"000102030405060708090a0b0c0d0e0f10111213"[..], b"not hex"] {
        let entry = with_records(&pax_record(b"APK-TOOLS.checksum.SHA1", value)).unwrap();
        assert_eq!(
            entry.pax_records().get(b"APK-TOOLS.checksum.SHA1"),
            Some(value),
        );
    }
}

#[test]
fn records_debug_as_text() {
    let entry = with_records(&pax_records(&[(b"comment", b"a\"b\n")])).unwrap();
    assert_eq!(
        format!("{:?}", entry.pax_records()),
        r#"{"comment": "a\"b\n"}"#,
    );
}

#[test]
fn an_access_or_change_time_that_does_not_read_is_refused() {
    // GNU tar reports either as a malformed header, bsdtar ignores a bad one
    // with an error, Go refuses a bad one, and Python reads both.
    for (keyword, known) in [(&b"atime"[..], Keyword::Atime), (b"ctime", Keyword::Ctime)] {
        for spelled in [&b""[..], b"abc", b"+1", b"1.5e3"] {
            assert_eq!(
                refusal(&pax_record(keyword, spelled)),
                ErrorKind::PaxValue {
                    keyword: known,
                    problem: Numeric::Unreadable,
                },
                "{}={}",
                keyword.escape_ascii(),
                spelled.escape_ascii(),
            );
        }
    }
}

#[test]
fn an_selinux_label_is_read_only_in_the_form_gnu_tar_writes() {
    // GNU tar's `--selinux --xattrs` writes the label's context in an
    // `RHT.security.selinux` record, then in the attribute's own record with
    // the NUL the kernel stores; every reader extracts that form alike.
    const LABEL: &[u8] = b"system_u:object_r:tmp_t:s0";
    let with_nul = [LABEL, b"\0"].concat();
    let read: [Vec<(&[u8], Vec<u8>)>; 4] = [
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
        ],
        // A record between them, and bsdtar's own spelling of the attribute
        // stating it alike.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"comment", b"c".to_vec()),
            (
                b"LIBARCHIVE.xattr.security.selinux",
                b"c3lzdGVtX3U6b2JqZWN0X3I6dG1wX3Q6czAA".to_vec(),
            ),
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
        ],
        // Repeated with one value.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
        ],
        // The attribute's record alone is any other attribute.
        vec![(b"SCHILY.xattr.security.selinux", LABEL.to_vec())],
    ];
    for case in read {
        let records: Vec<u8> = case.iter().flat_map(|(k, v)| pax_record(k, v)).collect();
        for level in [Level::Strict, Level::Compatible] {
            let entry = with_records_at(&records, level).unwrap();
            let expected = &case.last().unwrap().1;
            assert_eq!(
                entry.pax_records().xattr(b"security.selinux"),
                Some(&expected[..])
            );
        }
    }

    let other = b"unconfined_u:object_r:user_home_t:s0";
    let other_nul = [&other[..], b"\0"].concat();
    let refused: [Vec<(&[u8], Vec<u8>)>; 8] = [
        // Alone, given twice, or holding a NUL.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"RHT.security.selinux", LABEL.to_vec()),
        ],
        vec![(b"RHT.security.selinux", with_nul.clone())],
        // The attribute's record without the NUL: GNU tar's `--selinux`
        // appends one, bsdtar does not.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"SCHILY.xattr.security.selinux", LABEL.to_vec()),
        ],
        // After the attribute's record: bsdtar ends with the label as `RHT`
        // holds it, GNU tar with the NUL.
        vec![
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
            (b"RHT.security.selinux", LABEL.to_vec()),
        ],
        // Another label, in either order.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"SCHILY.xattr.security.selinux", other_nul.clone()),
        ],
        vec![
            (b"SCHILY.xattr.security.selinux", other_nul.clone()),
            (b"RHT.security.selinux", other.to_vec()),
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
        ],
        // An empty one, which GNU tar applies as a NUL and bsdtar as nothing.
        vec![(b"RHT.security.selinux", Vec::new())],
        // GNU tar's form, then another label, which bsdtar ends with.
        vec![
            (b"RHT.security.selinux", LABEL.to_vec()),
            (b"SCHILY.xattr.security.selinux", with_nul.clone()),
            (b"SCHILY.xattr.security.selinux", other_nul.clone()),
        ],
    ];
    // Alone, as GNU tar's `--selinux` writes it on a labelled system: GNU
    // tar with `--selinux` and bsdtar apply the context, and no reader
    // another.
    let records = pax_record(b"RHT.security.selinux", LABEL);
    for level in [Level::Strict, Level::Compatible] {
        let entry = with_records_at(&records, level).unwrap();
        assert_eq!(
            entry.pax_records().get(b"RHT.security.selinux"),
            Some(LABEL)
        );
    }
    for case in refused {
        let records: Vec<u8> = case.iter().flat_map(|(k, v)| pax_record(k, v)).collect();
        assert_eq!(
            *with_records_at(&records, Level::Compatible)
                .unwrap_err()
                .kind(),
            ErrorKind::SelinuxConflict,
            "{case:?}",
        );
    }
    let records: Vec<u8> = [
        pax_record(b"RHT.security.selinux", LABEL),
        pax_record(b"SCHILY.xattr.security.selinux", LABEL),
    ]
    .concat();
    let err = with_records(&records).unwrap_err();
    assert_eq!(
        err.to_string(),
        "an `RHT.security.selinux` record is in a form the readers apply differently at offset 0",
    );
}

#[test]
fn an_empty_pax_header_is_refused() {
    // bsdtar fails on it, reading nothing after it; GNU tar, Go and Python
    // read on.
    let archive = Tar::new().pax(b'x', b"").file("a", b"x").finish();
    for level in [Level::Strict, Level::Compatible] {
        let err = Reader::new(&archive[..])
            .with_level(level)
            .next_entry()
            .unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::EmptyMetadata(ferrotape::Metadata::PaxHeader), 0)
        );
    }
    assert_eq!(
        Reader::new(&archive[..])
            .next_entry()
            .unwrap_err()
            .to_string(),
        "a pax extended header is empty at offset 0"
    );
}

#[test]
fn a_hdrcharset_naming_neither_of_posix_s_character_sets_is_refused() {
    // bsdtar reports another value and reads a path ending in `/` over a
    // regular file as a file, where GNU tar, ignoring the record, reads a
    // directory.
    for value in [
        &b"6"[..],
        b"binary",
        b"",
        b"UTF-8",
        b"ISO-IR 10646 2000 UTF-8 ",
        b"BINARY\n",
    ] {
        let records = pax_records(&[(b"hdrcharset", value), (b"path", b"d/")]);
        for level in [Level::Strict, Level::Compatible] {
            let err = with_records_at(&records, level).unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (
                    &ErrorKind::UnknownCharset {
                        value: value.to_vec()
                    },
                    0
                ),
                "{}",
                value.escape_ascii(),
            );
        }
    }
    for value in [&b"BINARY"[..], b"ISO-IR 10646 2000 UTF-8"] {
        let records = pax_records(&[(b"hdrcharset", value), (b"path", b"d/")]);
        let entry = with_records(&records).unwrap();
        assert_eq!(entry.kind(), ferrotape::EntryKind::Directory);
    }
    let err = with_records(&pax_record(b"hdrcharset", b"6")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "a pax `hdrcharset` record names `6`, neither of POSIX's character sets at offset 0"
    );
}

#[test]
fn a_regular_member_named_as_a_directory_carries_only_records_every_reader_reads_alike() {
    // bsdtar reads such a member as a regular file after any record it fails
    // to parse, and as a directory otherwise; GNU tar as a directory.
    for (keyword, value) in [
        (&b"SCHILY.acl.access"[..], &b"smuggled"[..]),
        (b"SCHILY.acl.access", b"user::rwx,group::r-x,other::r-x"),
        (b"SCHILY.acl.default", b"smuggled"),
        (b"LIBARCHIVE.creationtime", b"x"),
        (b"LIBARCHIVE.symlinktype", b"x"),
        (b"SCHILY.devmajor", b"1"),
        (b"VENDOR.k", b"v"),
    ] {
        let records = pax_records(&[(keyword, value), (b"path", b"d/")]);
        for level in [Level::Strict, Level::Compatible] {
            let err = with_records_at(&records, level).unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (
                    &ErrorKind::DirectoryWithRecord {
                        keyword: keyword.to_vec()
                    },
                    1024
                ),
            );
        }
    }
    // The records the reader applies, `comment` and POSIX's `hdrcharset`.
    let records = pax_records(&[
        (b"path", b"d/"),
        (b"mtime", b"5"),
        (b"uname", b"u"),
        (b"comment", b"c"),
        (b"hdrcharset", b"BINARY"),
    ]);
    let entry = with_records(&records).unwrap();
    assert_eq!(entry.kind(), ferrotape::EntryKind::Directory);
    // A directory of typeflag `5`, and a regular file not named as one, carry
    // any record.
    let acl = pax_record(b"SCHILY.acl.access", b"smuggled");
    let archive = Tar::new()
        .pax(b'x', &acl)
        .header(&support::Header::new("d/", b'5', 0))
        .pax(b'x', &acl)
        .file("f", b"")
        .finish();
    let mut reader = Reader::new(&archive[..]);
    assert_eq!(
        reader.next_entry().unwrap().unwrap().kind(),
        ferrotape::EntryKind::Directory
    );
    assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"f");
    // Named by its header, or a contiguous file.
    for typeflag in [b'0', 0, b'7'] {
        let archive = Tar::new()
            .pax(b'x', &acl)
            .header(&support::Header::new("d/", typeflag, 0))
            .finish();
        assert_eq!(
            Reader::new(&archive[..]).next_entry().unwrap_err().kind(),
            &ErrorKind::DirectoryWithRecord {
                keyword: b"SCHILY.acl.access".to_vec()
            },
        );
    }
    let err = with_records(&pax_records(&[(b"VENDOR.k", b"v"), (b"path", b"d/")])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "a regular member named as a directory has `VENDOR.k`, after which readers part \
         over its type at offset 1024",
    );
}
