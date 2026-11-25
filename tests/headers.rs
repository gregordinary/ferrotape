//! The header block: its numeric fields, its checksum, its magic, and the
//! names and owner it carries.

mod support;

use ferrotape::{EntryKind, ErrorKind, GlobalHeaders, HeaderField, Level, Numeric, Reader};
use support::{BLOCK, Header, Magic, Tar, first, octal, paths_at, pax_record, pax_records, seal};

/// The first member of an archive holding `block` and the end marker.
fn read(block: &[u8; BLOCK]) -> Result<ferrotape::Entry, ferrotape::Error> {
    first(&Tar::new().block(block).finish())
}

/// A regular file's header block, its `range` overwritten with `field` and
/// its checksum written again.
fn with_field(range: std::ops::Range<usize>, field: &[u8]) -> [u8; BLOCK] {
    let mut block = Header::new("file.txt", b'0', 0).block();
    block[range].copy_from_slice(field);
    seal(&mut block);
    block
}

#[test]
fn octal_fields_read_as_writers_pad_them() {
    for (spelled, mode) in [
        (&b"0000755\0"[..], 0o755),
        (b"   755 \0", 0o755),
        (b"0000755 ", 0o755),
        (b"644 \0\0 \0", 0o644),
        // A field of NULs alone, or of spaces and NULs alone with a space
        // first, is zero to every reader.
        (b"\0\0\0\0\0\0\0\0", 0),
        (b"       \0", 0),
        (b"  \0  \0  ", 0),
    ] {
        let entry = read(&with_field(100..108, spelled)).unwrap();
        assert_eq!(entry.mode(), mode, "{spelled:?}");
    }
}

#[test]
fn a_blank_field_is_refused() {
    // GNU tar reads a field of spaces as all bits set and reports it, where
    // the others read zero. After a leading NUL, GNU tar and Go read the
    // digits that follow, and bsdtar and Python read zero. After spaces and
    // a NUL, Go reads the digits that follow, or fails at the header, and the
    // others read zero.
    let fields = [
        (100..108, HeaderField::Mode),
        (108..116, HeaderField::Uid),
        (116..124, HeaderField::Gid),
        (124..136, HeaderField::Size),
        (136..148, HeaderField::Mtime),
    ];
    for (range, field) in fields {
        let width = range.len();
        let mut spaces = vec![b' '; width];
        let mut nul_then_digits = vec![b'0'; width];
        nul_then_digits[0] = 0;
        let mut nul_then_spaces = vec![b' '; width];
        nul_then_spaces[0] = 0;
        let mut nul_then_one = vec![0; width];
        nul_then_one[width - 1] = b'1';
        let mut spaces_nul_digits = vec![b'0'; width];
        spaces_nul_digits[..3].copy_from_slice(b"  \0");
        let mut spaces_nul_letter = vec![b' '; width];
        spaces_nul_letter[1..3].copy_from_slice(b"\0x");
        let mut spaces_nul_zero = vec![0; width];
        spaces_nul_zero[..2].copy_from_slice(b" \0");
        spaces_nul_zero[width - 1] = b'0';
        for spelled in [
            &mut spaces,
            &mut nul_then_digits,
            &mut nul_then_spaces,
            &mut nul_then_one,
            &mut spaces_nul_digits,
            &mut spaces_nul_letter,
            &mut spaces_nul_zero,
        ] {
            let err = read(&with_field(range.clone(), spelled)).unwrap_err();
            assert_eq!(
                err.kind(),
                &ErrorKind::HeaderField {
                    field,
                    problem: Numeric::Unreadable,
                },
                "{field:?} {spelled:?}",
            );
        }
    }
}

#[test]
fn a_blank_device_number_is_refused_on_a_device_alone() {
    // GNU tar reads the device fields of a device alone: on any other member
    // a blank one is read as zero where what follows its leading spaces and
    // NULs reads as a number, as every reader but Go reads it. Go reads that
    // number, which names no device on such a member.
    for (range, field) in [
        (329..337, HeaderField::DevMajor),
        (337..345, HeaderField::DevMinor),
    ] {
        for spelled in [&b"        "[..], b"\x000000005", b"  \0 0005", b"\0 0005  "] {
            for typeflag in *b"34" {
                let mut block = Header::new("dev", typeflag, 0).block();
                block[range.clone()].copy_from_slice(spelled);
                seal(&mut block);
                let err = read(&block).unwrap_err();
                assert_eq!(
                    err.kind(),
                    &ErrorKind::HeaderField {
                        field,
                        problem: Numeric::Unreadable,
                    },
                    "{spelled:?} {}",
                    char::from(typeflag),
                );
            }
            for typeflag in *b"056" {
                let mut block = Header::new("member", typeflag, 0).block();
                block[range.clone()].copy_from_slice(spelled);
                seal(&mut block);
                let entry = read(&block).unwrap();
                assert_eq!(entry.device(), None, "{spelled:?}");
            }
        }
        // Go fails at the header where what follows does not read, on any
        // member.
        for spelled in [
            &b"\0x      "[..],
            b"  \0x    ",
            b"\x0010 1   ",
            b"0010 \0x ",
        ] {
            for typeflag in *b"0345" {
                let mut block = Header::new("member", typeflag, 0).block();
                block[range.clone()].copy_from_slice(spelled);
                seal(&mut block);
                let err = read(&block).unwrap_err();
                assert_eq!(
                    err.kind(),
                    &ErrorKind::HeaderField {
                        field,
                        problem: Numeric::Unreadable,
                    },
                    "{spelled:?} {}",
                    char::from(typeflag),
                );
            }
        }
    }
}

#[test]
fn a_checksum_in_base256_is_refused() {
    // GNU tar and bsdtar pass over such a header and read the next block as
    // one, where Python reads it: here, a setuid member's header hidden in
    // the member's data.
    let mut block = Header::new("cover", b'0', BLOCK as u64).block();
    block[148..156].fill(b' ');
    let sum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    block[148] = 0x80;
    block[149..156].copy_from_slice(&sum.to_be_bytes()[1..]);
    let mut hidden = Header::new("hidden-setuid", b'0', 0);
    hidden.mode = 0o4755;
    let hidden = hidden.block();
    let archive = Tar::new().block(&block).block(&hidden).finish();
    let err = first(&archive).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (&ErrorKind::Checksum, 0));
    // The same sum in octal is read.
    let mut octal_sum = block;
    seal(&mut octal_sum);
    assert_eq!(
        first(&Tar::new().block(&octal_sum).block(&hidden).finish())
            .unwrap()
            .path(),
        b"cover"
    );
}

/// A regular file's header holding `prefix` from byte 345, with star's
/// trailer where `trailer` says.
fn star_header(prefix: &[u8], trailer: bool) -> [u8; BLOCK] {
    let mut block = Header::new("f", b'0', 0).block();
    block[345..345 + prefix.len()].copy_from_slice(prefix);
    if trailer {
        block[508..512].copy_from_slice(b"tar\0");
    }
    seal(&mut block);
    block
}

#[test]
fn a_prefix_longer_than_stars_under_its_trailer_is_refused() {
    // Go reads a POSIX header ending in `tar\0` as star's, its prefix the
    // first 131 bytes; GNU tar, bsdtar and Python join the whole prefix.
    // star's times after a prefix of 131 bytes run the prefix on for the
    // readers that do not read star's format.
    let mut times = [b'p'; 155];
    times[131..143].copy_from_slice(b"00000000001\0");
    for level in [Level::Strict, Level::Compatible] {
        let err = Reader::new(&Tar::new().block(&star_header(&times[..143], true)).finish()[..])
            .with_level(level)
            .next_entry()
            .unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::StarPrefix, 0),
            "{level:?}"
        );
    }
    // A prefix star's field holds, or a long one without the trailer, is read.
    let long = [b'p'; 140];
    let entry = first(&Tar::new().block(&star_header(&long[..131], true)).finish()).unwrap();
    assert_eq!(entry.path().len(), 133);
    let entry = first(&Tar::new().block(&star_header(&long, false)).finish()).unwrap();
    assert_eq!(entry.path().len(), 142);
    // A pax `path` replaces the prefix for every reader.
    let archive = Tar::new()
        .pax(b'x', &pax_record(b"path", b"named"))
        .block(&star_header(&times[..143], true))
        .finish();
    assert_eq!(first(&archive).unwrap().path(), b"named");
}

#[test]
fn stars_times_under_its_trailer_must_read() {
    // Go reads bytes 476 to 499 of a POSIX header ending in star's trailer
    // as star's access and change times, and fails at the header where they
    // do not read. GNU tar, bsdtar and Python ignore them.
    let with_times = |times: &[u8; 24]| {
        let mut prefix = [0; 155];
        prefix[..3].copy_from_slice(b"dir");
        prefix[131..].copy_from_slice(times);
        Tar::new().block(&star_header(&prefix, true)).finish()
    };
    for (times, field) in [
        (&b"xxxxxxxxxxx\x0000000000000\0"[..], HeaderField::Atime),
        (b"00000001750\0xxxxxxxxxxx\0", HeaderField::Ctime),
        (b"000001750 \0x", HeaderField::Atime),
        (b"  \0 0001750\x0000000003720\0", HeaderField::Atime),
    ]
    .map(|(times, field)| {
        let mut padded = [0; 24];
        padded[..times.len()].copy_from_slice(times);
        (padded, field)
    }) {
        for level in [Level::Strict, Level::Compatible] {
            let err = Reader::new(&with_times(&times)[..])
                .with_level(level)
                .next_entry()
                .unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (
                    &ErrorKind::HeaderField {
                        field,
                        problem: Numeric::Unreadable,
                    },
                    0
                ),
                "{times:?} {level:?}",
            );
        }
    }
    // A prefix that runs on past star's 131 bytes, as letters, is a time Go
    // cannot read, even where a pax `path` names the member.
    let archive = Tar::new()
        .pax(b'x', &pax_record(b"path", b"named"))
        .block(&star_header(&[b'p'; 140], true))
        .finish();
    let err = first(&archive).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::HeaderField {
            field: HeaderField::Atime,
            problem: Numeric::Unreadable,
        },
    );
    // Times as star writes them, NULs, and the same bytes without the
    // trailer are read, and report no time.
    for times in [
        b"00000001750 15301417061 ",
        b"00000001750\x0000000003720\0",
        &[0; 24],
    ] {
        let entry = first(&with_times(times)).unwrap();
        assert_eq!(entry.path(), b"dir/f");
        assert_eq!((entry.atime(), entry.ctime()), (None, None));
    }
    let mut prefix = [0; 155];
    prefix[..3].copy_from_slice(b"dir");
    prefix[131..142].copy_from_slice(b"xxxxxxxxxxx");
    let entry = first(&Tar::new().block(&star_header(&prefix, false)).finish()).unwrap();
    assert_eq!(entry.path(), b"dir/f");
}

#[test]
fn a_field_that_is_not_octal_is_refused() {
    for spelled in [&b"0012x4\0\0"[..], b"0000008\0"] {
        let err = read(&with_field(100..108, spelled)).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::HeaderField {
                field: HeaderField::Mode,
                problem: Numeric::Unreadable,
            },
            "{spelled:?}",
        );
    }
}

#[test]
fn digits_followed_by_anything_but_spaces_and_nuls_are_refused() {
    // Digits, a space and more: GNU tar and bsdtar read the first digits, Go
    // cannot read the field, and Python ends the archive at its header.
    // Digits, a space, a NUL and more: Go fails at the header. Digits, a NUL
    // and more: bsdtar refuses the archive where the header is its first.
    for spelled in [
        &b"00644 11"[..],
        b"644 1\0\0\0",
        b"00644  x",
        b" 644 7 \0",
        b"0644 \0 1",
        b"0644  \x001",
        b"644  \0x1",
        b"00644\0 x",
        b"000644\x001",
    ] {
        let err = read(&with_field(100..108, spelled)).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::HeaderField {
                field: HeaderField::Mode,
                problem: Numeric::Unreadable,
            },
            "{spelled:?}",
        );
    }
    let err = read(&with_field(124..136, b"000000 00007")).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::HeaderField {
            field: HeaderField::Size,
            problem: Numeric::Unreadable,
        },
    );
    // Spaces and NULs alone after the digits.
    for spelled in [&b"644     "[..], b"644  \0\0 ", b"000644\0 ", b"0644 \0  "] {
        let entry = read(&with_field(100..108, spelled)).unwrap();
        assert_eq!(entry.mode(), 0o644, "{spelled:?}");
    }
}

#[test]
fn a_checksum_with_more_than_spaces_and_nuls_after_its_digits_is_refused() {
    // bsdtar passes over a header as damaged where a byte of its checksum
    // after the digits is not an octal digit, a space or a NUL, and reads the
    // next block as a header; the others read the digits. After a space and a
    // NUL, Go fails at the header.
    let spelled = |spelling: &[u8; 8]| {
        let mut block = Header::new("odd", b'0', 0).block();
        block[148..156].fill(b' ');
        let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
        let digits = spelling.iter().filter(|byte| **byte == b'#').count();
        let mut sum = format!("{sum:0digits$o}").into_bytes().into_iter();
        for (at, byte) in spelling.iter().enumerate() {
            block[148 + at] = if *byte == b'#' {
                sum.next().unwrap()
            } else {
                *byte
            };
        }
        let archive = Tar::new()
            .file("first", b"1\n")
            .block(&block)
            .file("after", b"")
            .finish();
        paths_at(&archive, Level::Strict)
    };
    for spelling in [b"######\0x", b"##### \0x", b"######\0\x01", b"######\x000"] {
        let err = spelled(spelling).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (&ErrorKind::Checksum, BLOCK as u64 * 2),
            "{spelling:?}"
        );
    }
    for spelling in [b"######\0 ", b"###### \0", b"#####\0 \0", b"######  "] {
        assert_eq!(
            spelled(spelling).unwrap(),
            [&b"first"[..], b"odd", b"after"],
            "{spelling:?}"
        );
    }
}

#[test]
fn base256_fields_read() {
    // 8 GiB + 1, too large for the octal size field. The member is not read
    // past its header, so its data need not be there.
    let mut size = [0u8; 12];
    size[0] = 0x80;
    size[7] = 0x02;
    size[11] = 0x01;
    let entry = read(&with_field(124..136, &size)).unwrap();
    assert_eq!(entry.declared_size(), (2 << 32) + 1);

    // -1 in two's complement: a time before 1970 is read.
    let entry = read(&with_field(136..148, &[0xff; 12])).unwrap();
    assert_eq!((entry.mtime().secs(), entry.mtime().nanos()), (-1, 0));
}

#[test]
fn a_header_size_of_2_to_the_60_or_more_is_refused() {
    // bsdtar stops at a member declaring 2^60 or more ("entry size
    // overflow"), where GNU tar, Go and Python read on; for a member that
    // carries no data, Compatible would read on too.
    let base256 = |size: u64| {
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[4..].copy_from_slice(&size.to_be_bytes());
        field
    };
    let entry = read(&with_field(124..136, &base256((1 << 60) - 1))).unwrap();
    assert_eq!(entry.declared_size(), (1 << 60) - 1);
    for size in [1 << 60, (1 << 63) - 1] {
        for level in [Level::Strict, Level::Compatible] {
            let err = Reader::new(&with_field(124..136, &base256(size))[..])
                .with_level(level)
                .next_entry()
                .unwrap_err();
            assert_eq!(
                err.kind(),
                &ErrorKind::HeaderField {
                    field: HeaderField::Size,
                    problem: Numeric::OutOfRange,
                },
                "{size} {level:?}",
            );
        }
    }
}

/// Pax records, as keyword and value.
type Records<'a> = &'a [(&'a [u8], &'a [u8])];

/// A device's records and header block, and the numbers every reader reads.
type Agreeing<'a> = (Records<'a>, [u8; BLOCK], Option<(u32, u32)>);

#[test]
fn device_records_that_state_other_numbers_than_the_header_are_refused() {
    // bsdtar takes a device's numbers from these records, a missing one as 0;
    // GNU tar, Go and Python read the header's.
    let device = |typeflag: u8, major: u64, minor: u64| {
        let mut block = Header::new("dev", typeflag, 0).block();
        octal(&mut block[329..337], major);
        octal(&mut block[337..345], minor);
        seal(&mut block);
        block
    };
    let archive = |records: Records<'_>, block: &[u8; BLOCK]| {
        Tar::new()
            .pax(b'x', &pax_records(records))
            .block(block)
            .finish()
    };
    let refused: [(Records<'_>, [u8; BLOCK]); 7] = [
        (&[(b"SCHILY.devmajor", b"512")], device(b'3', 1, 3)),
        (&[(b"SCHILY.devminor", b"70000")], device(b'4', 8, 0)),
        // As bsdtar writes a minor of 262,144 or more: the record alone,
        // which it reads back with the major 0.
        (&[(b"SCHILY.devminor", b"262144")], device(b'3', 8, 262_144)),
        (&[(b"SCHILY.devmajor", b"1")], device(b'3', 1, 3)),
        (&[(b"SCHILY.devmajor", b"abc")], device(b'3', 0, 0)),
        (&[(b"SCHILY.devmajor", b"")], device(b'3', 0, 0)),
        (
            &[(b"SCHILY.devmajor", b"1"), (b"SCHILY.devminor", b"4")],
            device(b'3', 1, 3),
        ),
    ];
    for (records, block) in &refused {
        for level in [Level::Strict, Level::Compatible] {
            let err = Reader::new(&archive(records, block)[..])
                .with_level(level)
                .next_entry()
                .unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (&ErrorKind::DeviceConflict, 2 * BLOCK as u64),
                "{records:?} {level:?}",
            );
        }
    }
    assert_eq!(
        Reader::new(&archive(refused[0].0, &refused[0].1)[..])
            .next_entry()
            .unwrap_err()
            .to_string(),
        "a device's `SCHILY.devmajor` or `SCHILY.devminor` record states other numbers than \
         its header, and readers read the two differently at offset 1024",
    );
    // Records that state the header's numbers, a missing one where it is 0,
    // are read alike; so are records on a member that is not a device.
    let read: [Agreeing<'_>; 4] = [
        (
            &[(b"SCHILY.devmajor", b"1"), (b"SCHILY.devminor", b"3")],
            device(b'3', 1, 3),
            Some((1, 3)),
        ),
        (
            &[(b"SCHILY.devmajor", b"8")],
            device(b'4', 8, 0),
            Some((8, 0)),
        ),
        (
            &[(b"SCHILY.devminor", b"5")],
            device(b'3', 0, 5),
            Some((0, 5)),
        ),
        (&[(b"SCHILY.devmajor", b"9")], device(b'0', 1, 3), None),
    ];
    for (records, block, numbers) in &read {
        for level in [Level::Strict, Level::Compatible] {
            let entry = Reader::new(&archive(records, block)[..])
                .with_level(level)
                .next_entry()
                .unwrap()
                .unwrap();
            assert_eq!(entry.device(), *numbers, "{records:?} {level:?}");
        }
    }
}

#[test]
fn a_negative_mode_or_id_is_refused_rather_than_wrapped() {
    // The base-256 form is two's complement. Wrapped into a `u32`, -1 would be
    // uid 4294967295, the kernel's overflow id, or, masked as a mode, 0o7777:
    // every permission bit with setuid, setgid and sticky, from a header no
    // archive can have meant.
    for (range, field) in [
        (100..108, HeaderField::Mode),
        (108..116, HeaderField::Uid),
        (116..124, HeaderField::Gid),
    ] {
        let err = read(&with_field(range, &[0xff; 8])).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::HeaderField {
                field,
                problem: Numeric::OutOfRange,
            },
        );
        assert_eq!(err.offset(), 0);
    }
    let err = read(&with_field(100..108, &[0xff; 8])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "the header's mode field holds a value out of its range at offset 0",
    );

    // The same fields in octal read, so what is refused is the sign.
    let entry = read(&with_field(108..116, b"0001750\0")).unwrap();
    assert_eq!(entry.uid(), 0o1750);
}

#[test]
fn a_numeric_field_refusal_names_the_field_and_what_is_wrong_with_it() {
    let err = read(&with_field(108..116, b"00017x0\0")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "the header's uid field is neither octal nor base-256 at offset 0",
    );

    // A negative size, which no member has.
    let err = read(&with_field(124..136, &[0xff; 12])).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::HeaderField {
            field: HeaderField::Size,
            problem: Numeric::OutOfRange,
        },
    );

    // More significant bits than an `i64` holds.
    let mut mtime = [0xff; 12];
    mtime[0] = 0x80;
    mtime[1] = 0x7f;
    let err = read(&with_field(136..148, &mtime)).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::HeaderField {
            field: HeaderField::Mtime,
            problem: Numeric::OutOfRange,
        },
    );
}

#[test]
fn a_damaged_header_is_refused_for_its_checksum() {
    // The magic says the block was meant to be a header, so a checksum that
    // does not match is a damaged archive, even in the first block.
    let mut block = Header::new("file.txt", b'0', 0).block();
    block[0] = b'X';
    let err = read(&block).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Checksum);
    assert_eq!(
        err.to_string(),
        "the header checksum does not match at offset 0"
    );

    // So is a checksum field that does not read as a number.
    let mut block = Header::new("file.txt", b'0', 0).block();
    block[148..156].copy_from_slice(b"zzzzzz\0 ");
    assert_eq!(read(&block).unwrap_err().kind(), &ErrorKind::Checksum);
}

#[test]
fn the_signed_checksum_is_accepted() {
    // Some historical writers summed the bytes as signed. A byte past 0x7f in
    // the name makes the two sums differ.
    let mut block = Header::new(b"caf\xe9", b'0', 0).block();
    block[148..156].copy_from_slice(b"        ");
    let signed: i64 = block.iter().map(|byte| i64::from(byte.cast_signed())).sum();
    let unsigned: i64 = block.iter().map(|byte| i64::from(*byte)).sum();
    assert_ne!(signed, unsigned);
    block[148..156].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
    assert_eq!(read(&block).unwrap().path(), b"caf\xe9");
}

#[test]
fn a_block_with_neither_magic_nor_a_matching_checksum_is_not_a_header() {
    // With v7 read, the checksum is all that tells a header from other
    // bytes. First in the stream, such a block says the stream is no archive.
    let mut block = Header::new("file.txt", b'0', 0);
    block.magic = Magic::V7;
    let mut block = block.block();
    block[0] = b'X';
    let err = read(&block).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::NotATar);

    // After a member, it is a damaged archive.
    let archive = Tar::new().file("first", b"").block(&block).finish();
    let err = support::paths(&archive).unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::NotAHeader);
    assert_eq!(err.offset(), BLOCK as u64);
}

#[test]
fn a_posix_prefix_joins_onto_the_name() {
    let mut header = Header::new("file.txt", b'0', 0);
    header.prefix = b"a/very/long/directory".to_vec();
    assert_eq!(
        read(&header.block()).unwrap().path(),
        b"a/very/long/directory/file.txt",
    );

    // An empty prefix prepends no separator.
    let header = Header::new("file.txt", b'0', 0);
    assert_eq!(read(&header.block()).unwrap().path(), b"file.txt");
}

#[test]
fn a_posix_prefix_ending_in_a_slash_is_refused() {
    // GNU tar, Go and Python join the prefix with a `/` and read `a//b` and
    // `//x`; bsdtar adds no `/` after one and reads `a/b` and `/x`.
    for (prefix, name) in [
        (&b"a/"[..], &b"b"[..]),
        (b"/", b"x"),
        (b"a//", b"b"),
        (b"a/b/", b"/c"),
    ] {
        let mut header = Header::new(name, b'0', 0);
        header.prefix = prefix.to_vec();
        for level in [Level::Strict, Level::Compatible] {
            let archive = Tar::new().file("first", b"").header(&header).finish();
            let mut reader = Reader::new(&archive[..]).with_level(level);
            reader.next_entry().unwrap();
            let err = reader.next_entry().unwrap_err();
            assert_eq!(*err.kind(), ErrorKind::PrefixSlash, "{prefix:?} {level:?}");
            assert_eq!(err.offset(), BLOCK as u64, "the member's own header");
        }
    }
    let mut header = Header::new("b", b'0', 0);
    header.prefix = b"a/".to_vec();
    assert_eq!(
        read(&header.block()).unwrap_err().to_string(),
        "a member's name prefix ends in `/`, which readers join differently at offset 0",
    );

    // A name that begins with `/` after a prefix without one is joined alike
    // by every reader.
    let mut header = Header::new("/b", b'0', 0);
    header.prefix = b"a".to_vec();
    assert_eq!(read(&header.block()).unwrap().path(), b"a//b");
}

#[test]
fn a_prefix_ending_in_a_slash_is_read_where_a_longer_name_replaces_it() {
    // Every reader then takes the pax `path` or the long name, and none reads
    // the header's own name.
    let mut header = Header::new("b", b'0', 0);
    header.prefix = b"a/".to_vec();
    let archive = Tar::new()
        .pax(b'x', &pax_record(b"path", b"from/the/record"))
        .header(&header)
        .finish();
    assert_eq!(first(&archive).unwrap().path(), b"from/the/record");
    let archive = Tar::new()
        .long(b'L', b"from/the/long/name\0")
        .header(&header)
        .finish();
    assert_eq!(first(&archive).unwrap().path(), b"from/the/long/name");

    // A global `path` replaces it where global headers are applied, and only
    // there.
    let archive = Tar::new()
        .pax(b'g', &pax_record(b"path", b"from/the/global"))
        .header(&header)
        .finish();
    let entry = Reader::new(&archive[..])
        .with_global_headers(GlobalHeaders::Apply)
        .next_entry()
        .unwrap()
        .unwrap();
    assert_eq!(entry.path(), b"from/the/global");
    let err = Reader::new(&archive[..])
        .with_global_headers(GlobalHeaders::Defer)
        .next_entry()
        .unwrap_err();
    assert_eq!(*err.kind(), ErrorKind::PrefixSlash);
}

#[test]
fn a_header_without_posix_magic_and_with_a_prefix_is_refused() {
    // GNU uses the bytes POSIX gives the prefix for other fields, an
    // incremental dump's access and change times among them, and v7 has no
    // field there. GNU tar, bsdtar and Go never join those bytes to the name;
    // Python does, and names the member differently.
    for magic in [Magic::Gnu, Magic::V7] {
        let mut header = Header::new("file.txt", b'0', 0);
        header.magic = magic;
        let mut block = header.block();
        block[345..357].copy_from_slice(b"00001234567\0");
        seal(&mut block);
        let err = read(&block).unwrap_err();
        assert_eq!(*err.kind(), ErrorKind::PrefixArea, "{magic:?}");
        assert_eq!(err.offset(), 0);
    }
}

#[test]
fn a_prefix_area_whose_first_byte_is_nul_is_no_prefix_to_any_reader() {
    // A multi-volume member's offset lies past the area's first field. Every
    // reader, Python included, reads an area that begins with a NUL as no
    // prefix at all.
    for magic in [Magic::Gnu, Magic::V7] {
        let mut header = Header::new("file.txt", b'0', 0);
        header.magic = magic;
        let mut block = header.block();
        block[369..381].copy_from_slice(b"00000001000\0");
        seal(&mut block);
        assert_eq!(read(&block).unwrap().path(), b"file.txt", "{magic:?}");
    }
}

#[test]
fn a_v7_header_reads_without_magic() {
    let mut header = Header::new("file.txt", 0, 0);
    header.magic = Magic::V7;
    let entry = read(&header.block()).unwrap();
    assert_eq!(entry.path(), b"file.txt");
    // A v7 header's NUL typeflag is a regular file.
    assert_eq!(entry.typeflag(), 0);
    assert_eq!(entry.kind(), EntryKind::File);
    assert_eq!(entry.mode(), 0o644);
    // Nor has it fields for device numbers.
    assert_eq!(entry.device(), None);
}

#[test]
fn an_owner_is_read_by_name_as_well_as_by_id() {
    // The header's own fields, and a pax record past them, the record winning
    // as it does for every field it states.
    let mut helper = Header::new("helper", b'0', 0);
    helper.mode = 0o4750;
    helper.gid = 101;
    helper.uname = b"root".to_vec();
    helper.gname = b"messagebus".to_vec();
    let mut next = Header::new("next", b'0', 0);
    next.uname = b"root".to_vec();
    next.gname = b"messagebus".to_vec();
    let archive = Tar::new()
        .entry(helper, b"x")
        .pax(
            b'x',
            &support::pax_record(b"gname", b"a-group-name-longer-than-the-header-field"),
        )
        .entry(next, b"y")
        .finish();
    let mut reader = ferrotape::Reader::new(&archive[..]);
    let helper = reader.next_entry().unwrap().unwrap();
    assert_eq!(
        (helper.uname(), helper.gname(), helper.gid(), helper.mode()),
        (&b"root"[..], &b"messagebus"[..], 101, 0o4750),
    );
    let next = reader.next_entry().unwrap().unwrap();
    assert_eq!(next.gname(), b"a-group-name-longer-than-the-header-field");
    assert_eq!(next.uname(), b"root");

    // A v7 header has no field for a name, so it names no one.
    let mut old = Header::new("old", b'0', 0);
    old.magic = Magic::V7;
    old.uid = 1000;
    let old = read(&old.block()).unwrap();
    assert!(old.uname().is_empty() && old.gname().is_empty());
    assert_eq!(old.uid(), 1000);
}

#[test]
fn a_device_reads_its_numbers() {
    for (typeflag, kind) in [
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
    ] {
        let mut block = Header::new("dev", typeflag, 0).block();
        block[329..337].copy_from_slice(b"0000010\0");
        block[337..345].copy_from_slice(b"0000003\0");
        seal(&mut block);
        let entry = read(&block).unwrap();
        assert_eq!((entry.kind(), entry.device()), (kind, Some((8, 3))));
    }

    // Another member has no device, whatever its fields hold.
    let block = with_field(329..337, b"0000010\0");
    assert_eq!(read(&block).unwrap().device(), None);
}

#[test]
fn a_device_field_that_does_not_read_is_refused_whatever_the_type() {
    // bsdtar, Go and Python refuse a header whose device field does not read,
    // a regular file's included; GNU tar reads the regular file, and warns of
    // the device. A field that does not parse is refused as malformed.
    for typeflag in *b"035" {
        for (range, field) in [
            (329..337, HeaderField::DevMajor),
            (337..345, HeaderField::DevMinor),
        ] {
            for (spelled, problem) in [
                (*b"zzzzzzz\0", Numeric::Unreadable),
                // -1 in base-256: no device number is negative.
                ([0xff; 8], Numeric::OutOfRange),
            ] {
                let mut block = Header::new("m", typeflag, 0).block();
                block[range.clone()].copy_from_slice(&spelled);
                seal(&mut block);
                assert_eq!(
                    *read(&block).unwrap_err().kind(),
                    ErrorKind::HeaderField { field, problem },
                    "typeflag {}",
                    char::from(typeflag),
                );
            }
        }
    }
}

/// `header`'s block with `magic_version` at bytes 257 to 265, and each of
/// `fields` written at its offset, sealed again.
fn with_magic(header: &Header, magic_version: &[u8; 8], fields: &[(usize, &[u8])]) -> [u8; BLOCK] {
    let mut block = header.block();
    block[257..265].copy_from_slice(magic_version);
    for (at, bytes) in fields {
        block[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    seal(&mut block);
    block
}

#[test]
fn owner_names_or_device_numbers_under_another_magic_are_refused() {
    // Python reads owner names and device numbers under any magic, bsdtar
    // where the magic begins `ustar`, and GNU tar and Go only under POSIX's
    // magic, with any version, and GNU's magic and version exactly.
    let names: &[(usize, &[u8])] = &[(265, b"root"), (297, b"wheel")];
    let mut device = [0u8; 8];
    octal(&mut device, 5);
    let device: &[(usize, &[u8])] = &[(329, &device)];
    let file = Header::new("f", b'0', 0);
    let chr = Header::new("c", b'3', 0);
    for magic_version in [
        b"ustar 00",
        b"ustar \0\0",
        b"ustarx00",
        b"xxxxxx00",
        &[0; 8],
    ] {
        for (header, fields) in [(&file, names), (&chr, device)] {
            let archive = Tar::new()
                .block(&with_magic(header, magic_version, fields))
                .finish();
            for level in [Level::Strict, Level::Compatible] {
                let err = Reader::new(&archive[..])
                    .with_level(level)
                    .next_entry()
                    .unwrap_err();
                assert_eq!(
                    (err.kind(), err.offset()),
                    (&ErrorKind::UnknownMagic, 0),
                    "{}",
                    magic_version.escape_ascii(),
                );
            }
        }
        // The same headers with nothing in those fields are read: a device
        // as 0,0, and a regular file's device numbers, which no reader
        // applies, passed over.
        let blank = Tar::new()
            .block(&with_magic(&chr, magic_version, &[]))
            .finish();
        let entry = first(&blank).unwrap();
        assert_eq!((entry.device(), entry.uname()), (Some((0, 0)), &b""[..]));
        let numbered = Tar::new()
            .block(&with_magic(&file, magic_version, device))
            .finish();
        assert_eq!(first(&numbered).unwrap().kind(), EntryKind::File);
    }
    // POSIX's magic with any version, and GNU's exactly: the names and
    // numbers are read.
    for magic_version in [b"ustar\x0000", b"ustar\0\0\0", b"ustar\0xx", b"ustar  \0"] {
        let archive = Tar::new()
            .block(&with_magic(&file, magic_version, names))
            .finish();
        let entry = first(&archive).unwrap();
        assert_eq!(
            (entry.uname(), entry.gname()),
            (&b"root"[..], &b"wheel"[..])
        );
        let archive = Tar::new()
            .block(&with_magic(&chr, magic_version, device))
            .finish();
        assert_eq!(first(&archive).unwrap().device(), Some((5, 0)));
    }
    let archive = Tar::new()
        .block(&with_magic(&file, b"xxxxxx00", names))
        .finish();
    assert_eq!(
        first(&archive).unwrap_err().to_string(),
        "a header whose magic is neither POSIX's nor GNU's holds an owner name or a device \
         number, which readers read differently at offset 0",
    );
}

#[test]
fn a_device_in_a_header_with_no_device_fields_is_0_0() {
    // Every reader reports a v7 device as 0,0, and extracts that node.
    for (typeflag, kind) in [
        (b'3', EntryKind::CharDevice),
        (b'4', EntryKind::BlockDevice),
    ] {
        let mut header = Header::new("dev", typeflag, 0);
        header.magic = Magic::V7;
        let entry = first(&Tar::new().header(&header).finish()).unwrap();
        assert_eq!((entry.kind(), entry.device()), (kind, Some((0, 0))));
    }
    let mut header = Header::new("f", b'0', 0);
    header.magic = Magic::V7;
    assert_eq!(
        first(&Tar::new().header(&header).finish())
            .unwrap()
            .device(),
        None
    );
}

#[test]
fn device_fields_that_do_not_read_are_refused_in_every_header() {
    // Python reads every header's device fields, and ends the archive at one
    // it cannot read; GNU tar, bsdtar and Go read on past a v7 header's.
    for (at, field) in [(329, HeaderField::DevMajor), (337, HeaderField::DevMinor)] {
        for magic_version in [&[0u8; 8], b"ustarx00", b"xxxxxx00"] {
            let file = Header::new("b", b'0', 0);
            let block = with_magic(&file, magic_version, &[(at, b"xx\0")]);
            for lead in [false, true] {
                let mut archive = Tar::new();
                if lead {
                    archive.file("a", b"x");
                }
                let archive = archive.block(&block).file("c", b"z").finish();
                let at_offset = if lead { 2 * BLOCK as u64 } else { 0 };
                for level in [Level::Strict, Level::Compatible] {
                    let mut reader = Reader::new(&archive[..]).with_level(level);
                    if lead {
                        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"a");
                    }
                    let err = reader.next_entry().unwrap_err();
                    assert_eq!(
                        (err.kind(), err.offset()),
                        (
                            &ErrorKind::HeaderField {
                                field,
                                problem: Numeric::Unreadable
                            },
                            at_offset
                        ),
                        "{}",
                        magic_version.escape_ascii(),
                    );
                }
            }
        }
    }
    // Octal zeros there, as GNU tar's v7 format writes them, or nothing.
    let mut zeros = [0u8; 8];
    octal(&mut zeros, 0);
    for fields in [&[(329, &zeros[..]), (337, &zeros[..])][..], &[]] {
        let block = with_magic(&Header::new("b", b'0', 0), &[0; 8], fields);
        let archive = Tar::new().block(&block).finish();
        assert_eq!(first(&archive).unwrap().path(), b"b");
    }
}

#[test]
fn old_sparse_fields_belong_to_a_sparse_member() {
    // bsdtar reads a GNU header's real size as a regular file's size, and
    // fails on its slots, whatever the typeflag.
    let with = |typeflag: u8, at: usize, bytes: &[u8]| {
        let size = if typeflag == b'0' { 512 } else { 0 };
        let mut header = Header::new("x", typeflag, size);
        header.magic = Magic::Gnu;
        let mut block = header.block();
        block[at..at + bytes.len()].copy_from_slice(bytes);
        seal(&mut block);
        Tar::new()
            .block(&block)
            .body(&vec![b'S'; size as usize])
            .finish()
    };
    let refused = [
        with(b'0', 483, b"00000004000\0"),
        with(b'0', 386, b"00000002000\0"),
        with(b'5', 386, b"00000002000\0"),
    ];
    for archive in refused {
        for level in [Level::Strict, Level::Compatible] {
            let err = paths_at(&archive, level).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::SparseFields);
        }
    }
    for archive in [with(b'5', 483, b"00000004000\0"), with(b'0', 482, b"\x01")] {
        assert_eq!(paths_at(&archive, Level::Strict).unwrap(), [b"x"]);
    }
}
