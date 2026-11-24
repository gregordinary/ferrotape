//! Sparse members: each of GNU's four forms read, the file delivered with its
//! holes and the stored data without, and each rule a map keeps.
//!
//! The catalog's `sparse/` cases hold the reference readers' readings that
//! each rule rests on; these tests hold the API to them.

#![forbid(unsafe_code)]

mod support;

use std::io::{Cursor, Read};

use ferrotape::{Entry, ErrorKind, Level, Limits, Reader, Region, SparseFlaw};
use support::{BLOCK, Header, Magic, Tar, pax_record, pax_records, read_whole, seal};

/// Twelve bytes of GNU's octal form: eleven digits and a NUL.
fn octal12(value: u64) -> [u8; 12] {
    let mut field = [0u8; 12];
    let digits = format!("{value:011o}");
    field[..11].copy_from_slice(digits.as_bytes());
    field
}

/// An old GNU sparse header (typeflag `S`) for `regions` of a file of
/// `real_size` bytes, its first four slots filled and its extension flag set
/// where `extended`, declaring `stored` bytes.
fn old_header(
    name: &str,
    regions: &[(u64, u64)],
    real_size: u64,
    stored: u64,
    extended: bool,
) -> [u8; BLOCK] {
    let mut header = Header::new(name, b'S', stored);
    header.magic = Magic::Gnu;
    let mut block = header.block();
    for (slot, (offset, length)) in regions.iter().take(4).enumerate() {
        let at = 386 + slot * 24;
        block[at..at + 12].copy_from_slice(&octal12(*offset));
        block[at + 12..at + 24].copy_from_slice(&octal12(*length));
    }
    block[482] = u8::from(extended);
    block[483..495].copy_from_slice(&octal12(real_size));
    seal(&mut block);
    block
}

/// An old GNU extension block holding up to 21 slots.
fn extension(regions: &[(u64, u64)], extended: bool) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    for (slot, (offset, length)) in regions.iter().enumerate() {
        let at = slot * 24;
        block[at..at + 12].copy_from_slice(&octal12(*offset));
        block[at + 12..at + 24].copy_from_slice(&octal12(*length));
    }
    block[504] = u8::from(extended);
    block
}

/// The stored data of `regions`: each region's bytes, a letter per region.
fn stored(regions: &[(u64, u64)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (index, (_, length)) in regions.iter().enumerate() {
        data.extend(std::iter::repeat_n(b'A' + index as u8, *length as usize));
    }
    data
}

/// The file `regions` of `real_size` bytes stand for.
fn file(regions: &[(u64, u64)], real_size: u64) -> Vec<u8> {
    let mut data = vec![0u8; real_size as usize];
    for (index, (offset, length)) in regions.iter().enumerate() {
        data[*offset as usize..(*offset + *length) as usize].fill(b'A' + index as u8);
    }
    data
}

/// A format 1.0 map's text.
fn map10(regions: &[(u64, u64)]) -> Vec<u8> {
    let mut text = format!("{}\n", regions.len());
    for (offset, length) in regions {
        text += &format!("{offset}\n{length}\n");
    }
    text.into_bytes()
}

/// `data` padded with zeros to a whole number of blocks.
fn padded(mut data: Vec<u8>) -> Vec<u8> {
    data.resize(data.len().next_multiple_of(BLOCK), 0);
    data
}

/// The regions GNU tar writes for a file of 4096 bytes with data at 1024 and
/// 2560: the last an empty region at the real size.
const REGIONS: [(u64, u64); 3] = [(1024, 512), (2560, 512), (4096, 0)];
const REAL: u64 = 4096;

/// The archive of an old GNU sparse member `sparse` of [`REGIONS`], then a
/// member `after`.
fn old_archive() -> Vec<u8> {
    let data = stored(&REGIONS);
    Tar::new()
        .block(&old_header(
            "sparse",
            &REGIONS,
            REAL,
            data.len() as u64,
            false,
        ))
        .body(&data)
        .file("after", b"tail")
        .finish()
}

/// The pax records of a member in format 1.0.
fn records10(name: &[u8], real_size: u64) -> Vec<u8> {
    let real = real_size.to_string();
    pax_records(&[
        (b"GNU.sparse.major", b"1"),
        (b"GNU.sparse.minor", b"0"),
        (b"GNU.sparse.name", name),
        (b"GNU.sparse.realsize", real.as_bytes()),
    ])
}

/// The archive of a format 1.0 member of [`REGIONS`] named `sparse`.
fn archive10() -> Vec<u8> {
    let mut body = padded(map10(&REGIONS));
    body.extend(stored(&REGIONS));
    Tar::new()
        .pax(b'x', &records10(b"sparse", REAL))
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
            &body,
        )
        .file("after", b"tail")
        .finish()
}

/// The archive of a format 0.1 member of [`REGIONS`].
fn archive01() -> Vec<u8> {
    let map: Vec<String> = REGIONS
        .iter()
        .flat_map(|(o, l)| [o.to_string(), l.to_string()])
        .collect();
    let map = map.join(",");
    let records = pax_records(&[
        (b"GNU.sparse.size", REAL.to_string().as_bytes()),
        (
            b"GNU.sparse.numblocks",
            REGIONS.len().to_string().as_bytes(),
        ),
        (b"GNU.sparse.name", b"sparse"),
        (b"GNU.sparse.map", map.as_bytes()),
    ]);
    Tar::new()
        .pax(b'x', &records)
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', 1024),
            &stored(&REGIONS),
        )
        .file("after", b"tail")
        .finish()
}

/// The archive of a format 0.0 member of [`REGIONS`].
fn archive00() -> Vec<u8> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b"GNU.sparse.size".to_vec(), REAL.to_string().into_bytes()),
        (
            b"GNU.sparse.numblocks".to_vec(),
            REGIONS.len().to_string().into_bytes(),
        ),
    ];
    for (offset, length) in REGIONS {
        pairs.push((
            b"GNU.sparse.offset".to_vec(),
            offset.to_string().into_bytes(),
        ));
        pairs.push((
            b"GNU.sparse.numbytes".to_vec(),
            length.to_string().into_bytes(),
        ));
    }
    let borrowed: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    Tar::new()
        .pax(b'x', &pax_records(&borrowed))
        .entry(Header::new("sparse", b'0', 1024), &stored(&REGIONS))
        .file("after", b"tail")
        .finish()
}

/// Reads the first member at `level`, its file through `data`, then the
/// next member's path.
fn read_first(archive: &[u8], level: Level) -> Result<(Entry, Vec<u8>, Vec<u8>), ferrotape::Error> {
    let mut reader = Reader::new(archive).with_level(level);
    let entry = reader.next_entry()?.expect("a member");
    let data = read_whole(reader.data(), entry.size())
        .map_err(|e| e.downcast::<ferrotape::Error>().unwrap())?;
    let next = reader.next_entry()?.expect("a second member");
    Ok((entry, data, next.path().to_vec()))
}

fn regions(entry: &Entry) -> Vec<(u64, u64)> {
    entry
        .sparse()
        .expect("a sparse member")
        .regions()
        .iter()
        .map(|r: &Region| (r.offset(), r.length()))
        .collect()
}

#[test]
fn each_form_is_read_as_the_file_it_stands_for() {
    // The pax forms' data begins past the extended header, its records and
    // the member's header; 1.0's past its map's block too.
    let forms = [
        ("old GNU", old_archive(), BLOCK as u64, 1024),
        ("0.0", archive00(), 3 * BLOCK as u64, 1024),
        ("0.1", archive01(), 3 * BLOCK as u64, 1024),
        ("1.0", archive10(), 4 * BLOCK as u64, 1536),
    ];
    for (form, archive, data_offset, declared) in forms {
        let (entry, data, next) = read_first(&archive, Level::Compatible).unwrap();
        assert_eq!(entry.path(), b"sparse", "{form}");
        assert_eq!(entry.kind(), ferrotape::EntryKind::File, "{form}");
        assert_eq!(entry.size(), REAL, "{form}");
        assert_eq!(entry.declared_size(), declared, "{form}");
        assert_eq!(entry.data_offset(), data_offset, "{form}");
        let map = entry.sparse().unwrap();
        assert_eq!((map.real_size(), map.stored_size()), (REAL, 1024), "{form}");
        assert_eq!(regions(&entry), REGIONS, "{form}");
        assert_eq!(data, file(&REGIONS, REAL), "{form}");
        assert_eq!(next, b"after", "{form}");
    }
}

#[test]
fn strict_reads_old_gnu_and_refuses_the_pax_forms() {
    let (entry, data, _) = read_first(&old_archive(), Level::Strict).unwrap();
    assert_eq!((entry.size(), data.len() as u64), (REAL, REAL));
    for archive in [archive00(), archive01(), archive10()] {
        let err = read_first(&archive, Level::Strict).unwrap_err();
        // Format 0.0 repeats its keywords, which Strict refuses first.
        assert!(
            matches!(
                err.kind(),
                ErrorKind::Sparse(SparseFlaw::PaxForm) | ErrorKind::RepeatedKeyword { .. }
            ),
            "{err}"
        );
    }
}

#[test]
fn stored_data_is_the_regions_alone() {
    for archive in [old_archive(), archive00(), archive01(), archive10()] {
        let mut reader = Reader::new(archive.as_slice()).with_level(Level::Compatible);
        let entry = reader.next_entry().unwrap().unwrap();
        let stored_size = entry.sparse().expect("a sparse member").stored_size();
        let data = read_whole(reader.stored_data(), stored_size).unwrap();
        assert_eq!(data, stored(&REGIONS));
        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"after");
    }
}

#[test]
fn both_views_move_through_one_position() {
    let mut reader = Reader::new(Cursor::new(archive10())).with_level(Level::Compatible);
    let entry = reader.next_entry().unwrap().unwrap();
    // The first region through the stored view: its 512 bytes, the hole
    // before it passed over.
    let mut first = vec![0u8; 512];
    reader.stored_data().read_exact(&mut first).unwrap();
    assert_eq!(first, vec![b'A'; 512]);
    // The rest of the file from the end of that region.
    let rest = read_whole(reader.data(), entry.size()).unwrap();
    assert_eq!(rest, file(&REGIONS, REAL)[1536..]);
    // Nothing is left for either.
    assert_eq!(reader.stored_data().read(&mut [0u8; 8]).unwrap(), 0);
}

#[test]
fn read_entry_holds_the_real_size_to_its_limit() {
    let archive = archive10();
    let mut reader = Reader::new(archive.as_slice()).with_level(Level::Compatible);
    reader.next_entry().unwrap().unwrap();
    let err = reader.read_entry(REAL - 1).unwrap_err();
    assert_eq!(
        err.kind(),
        &ErrorKind::EntryLimit {
            size: REAL,
            limit: REAL - 1
        }
    );
    assert_eq!(reader.read_entry(REAL).unwrap(), file(&REGIONS, REAL));
}

#[test]
fn a_seeking_reader_skips_the_stored_data() {
    for archive in [old_archive(), archive10()] {
        let mut reader = Reader::seeking(Cursor::new(archive)).with_level(Level::Compatible);
        let entry = reader.next_entry().unwrap().unwrap();
        assert!(entry.sparse().is_some());
        assert_eq!(reader.next_entry().unwrap().unwrap().path(), b"after");
        assert!(reader.next_entry().unwrap().is_none());
    }
}

#[test]
fn an_old_gnu_map_continues_in_extension_blocks() {
    // Thirty regions and the terminal one: four in the header, 21 and 6 in
    // two extension blocks.
    let mut regions: Vec<(u64, u64)> = (0..30).map(|i| (i * 1024, 512)).collect();
    regions.push((30 * 1024, 0));
    let real = 30 * 1024;
    let data = stored(&regions);
    let archive = Tar::new()
        .block(&old_header("many", &regions, real, data.len() as u64, true))
        .block(&extension(&regions[4..25], true))
        .block(&extension(&regions[25..], false))
        .body(&data)
        .file("after", b"tail")
        .finish();
    let (entry, file_data, next) = read_first(&archive, Level::Strict).unwrap();
    assert_eq!(regions_of(&entry), regions);
    assert_eq!(entry.data_offset(), 3 * BLOCK as u64);
    assert_eq!(file_data, file(&regions, real));
    assert_eq!(next, b"after");

    // An extension block beyond the limit is refused: the header's block and
    // two extension blocks are three blocks of map.
    let mut limits = Limits::default();
    limits.metadata = 2 * BLOCK as u64;
    let mut reader = Reader::new(archive.as_slice()).with_limits(limits);
    let err = reader.next_entry().unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Sparse(SparseFlaw::MapLimit));
    limits.metadata = 3 * BLOCK as u64;
    let mut reader = Reader::new(archive.as_slice()).with_limits(limits);
    assert!(reader.next_entry().unwrap().is_some());
}

fn regions_of(entry: &Entry) -> Vec<(u64, u64)> {
    regions(entry)
}

#[test]
fn a_format_1_0_map_may_run_past_its_first_block() {
    // Sixty regions: a map of 597 bytes, two blocks.
    let mut regions: Vec<(u64, u64)> = (0..60).map(|i| (i * 1024, 512)).collect();
    regions.push((60 * 1024, 0));
    let real = 60 * 1024;
    let map = padded(map10(&regions));
    assert_eq!(map.len(), 2 * BLOCK);
    let mut body = map;
    body.extend(stored(&regions));
    let archive = Tar::new()
        .pax(b'x', &records10(b"many", real))
        .entry(
            Header::new("GNUSparseFile.0/many", b'0', body.len() as u64),
            &body,
        )
        .file("after", b"tail")
        .finish();
    let (entry, data, next) = read_first(&archive, Level::Compatible).unwrap();
    assert_eq!(entry.data_offset(), 5 * BLOCK as u64);
    assert_eq!(data, file(&regions, real));
    assert_eq!(next, b"after");

    let mut limits = Limits::default();
    limits.metadata = BLOCK as u64;
    let err = Reader::new(archive.as_slice())
        .with_level(Level::Compatible)
        .with_limits(limits)
        .next_entry()
        .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Sparse(SparseFlaw::MapLimit));
}

/// A map's regions and real size, and the flaw it is refused with, or
/// `None` where it is read.
type Shape = (&'static [(u64, u64)], u64, Option<SparseFlaw>);

/// Records added to and removed from format 1.0's, and the flaw.
type RecordCase = (&'static [Record], &'static [&'static [u8]], SparseFlaw);

/// A pax record's keyword and value.
type Record = (&'static [u8], &'static [u8]);

/// The flaw a format 1.0 member of `regions` and `real_size`, its map's text
/// `map`, is refused with at Compatible, or `None` where it is read.
fn flaw10(map: &[u8], regions: &[(u64, u64)], real_size: u64) -> Option<SparseFlaw> {
    let mut body = padded(map.to_vec());
    body.extend(stored(regions));
    let archive = Tar::new()
        .pax(b'x', &records10(b"sparse", real_size))
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
            &body,
        )
        .file("after", b"tail")
        .finish();
    match read_first(&archive, Level::Compatible) {
        Ok(_) => None,
        Err(err) => match err.kind() {
            ErrorKind::Sparse(flaw) => Some(*flaw),
            other => panic!("{other:?}"),
        },
    }
}

#[test]
fn a_map_is_read_only_in_the_shapes_every_reader_extracts_alike() {
    let cases: [Shape; 14] = [
        (&[(1024, 512), (2048, 0)], 2048, None),
        // Ending in data, with or without the empty region after it.
        (&[(1536, 512)], 2048, None),
        (&[(1536, 512), (2048, 0)], 2048, None),
        // An empty region where a region ends, and one at the start.
        (&[(0, 512), (512, 0), (1024, 512), (2048, 0)], 2048, None),
        (&[(0, 0), (1024, 512), (2048, 0)], 2048, None),
        // An empty file, with an empty region or none.
        (&[(0, 0)], 0, None),
        (&[], 0, None),
        (&[(1024, 512)], 2048, Some(SparseFlaw::End)),
        (&[], 2048, Some(SparseFlaw::End)),
        (
            &[(1536, 512), (0, 512), (2048, 0)],
            2048,
            Some(SparseFlaw::Order),
        ),
        (
            &[(0, 512), (512, 512), (2048, 0)],
            2048,
            Some(SparseFlaw::Adjacent),
        ),
        (
            &[(0, 512), (512, 0), (512, 512), (2048, 0)],
            2048,
            Some(SparseFlaw::Adjacent),
        ),
        (&[(0, 2048)], 2048, Some(SparseFlaw::NoHole)),
        (&[(1536, 1024)], 2048, Some(SparseFlaw::End)),
    ];
    for (regions, real_size, flaw) in cases {
        assert_eq!(
            flaw10(&map10(regions), regions, real_size),
            flaw,
            "{regions:?} of {real_size}"
        );
    }
}

#[test]
fn a_format_1_0_map_is_digits_and_newlines() {
    let regions: &[(u64, u64)] = &[(1024, 512), (2048, 0)];
    let read: [&[u8]; 4] = [
        b"2\n1024\n512\n2048\n0\n",
        b"02\n01024\n0512\n2048\n0\n",
        // What follows the map in its block is not read.
        b"2\n1024\n512\n2048\n0\n9\n9\n",
        b"2\n0000000000000001024\n512\n2048\n0\n",
    ];
    for map in read {
        assert_eq!(flaw10(map, regions, 2048), None, "{}", map.escape_ascii());
    }
    let refused: [(&[u8], SparseFlaw); 9] = [
        (
            b"2\n00000000000000001024\n512\n2048\n0\n",
            SparseFlaw::Number,
        ),
        (b"2\n+1024\n512\n2048\n0\n", SparseFlaw::Number),
        (b"2\n 1024\n512\n2048\n0\n", SparseFlaw::Number),
        (b"2\r\n1024\r\n512\r\n2048\r\n0\r\n", SparseFlaw::Number),
        (b"2\r1024\r512\r2048\r0\r", SparseFlaw::Number),
        (b"2\n\n1024\n512\n2048\n0\n", SparseFlaw::Number),
        (b"2\n1024\0\n512\n2048\n0\n", SparseFlaw::Number),
        (b"1\n1024\n512\n2048\n0\n", SparseFlaw::End),
        (b"3\n1024\n512\n2048\n0\n", SparseFlaw::Number),
    ];
    for (map, flaw) in refused {
        assert_eq!(
            flaw10(map, regions, 2048),
            Some(flaw),
            "{}",
            map.escape_ascii()
        );
    }
}

/// The flaw an archive is refused with at Compatible.
fn refusal(archive: &[u8]) -> SparseFlaw {
    let err = read_first(archive, Level::Compatible).unwrap_err();
    match err.kind() {
        ErrorKind::Sparse(flaw) => *flaw,
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_records_are_those_of_one_form() {
    let base: Vec<(&[u8], &[u8])> = vec![
        (b"GNU.sparse.major", b"1"),
        (b"GNU.sparse.minor", b"0"),
        (b"GNU.sparse.name", b"sparse"),
        (b"GNU.sparse.realsize", b"4096"),
    ];
    let with = |extra: &[(&'static [u8], &'static [u8])], drop: &[&[u8]]| {
        let mut records: Vec<(&[u8], &[u8])> = base
            .iter()
            .copied()
            .filter(|(k, _)| !drop.contains(k))
            .collect();
        records.extend_from_slice(extra);
        let mut body = padded(map10(&REGIONS));
        body.extend(stored(&REGIONS));
        Tar::new()
            .pax(b'x', &pax_records(&records))
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
                &body,
            )
            .file("after", b"tail")
            .finish()
    };
    let cases: [RecordCase; 9] = [
        (&[(b"GNU.sparse.numblocks", b"3")], &[], SparseFlaw::Records),
        (
            &[(b"GNU.sparse.map", b"1024,512")],
            &[],
            SparseFlaw::Records,
        ),
        (
            &[(b"GNU.sparse.major", b"2")],
            &[b"GNU.sparse.major"],
            SparseFlaw::Records,
        ),
        (
            &[(b"GNU.sparse.minor", b"1")],
            &[b"GNU.sparse.minor"],
            SparseFlaw::Records,
        ),
        (&[], &[b"GNU.sparse.minor"], SparseFlaw::Records),
        (&[], &[b"GNU.sparse.realsize"], SparseFlaw::Records),
        (&[(b"GNU.sparse.unknown", b"x")], &[], SparseFlaw::Records),
        (
            &[(b"GNU.sparse.realsize", b"4k")],
            &[b"GNU.sparse.realsize"],
            SparseFlaw::Number,
        ),
        (&[(b"size", b"1536")], &[], SparseFlaw::SizeRecord),
    ];
    for (extra, drop, flaw) in cases {
        assert_eq!(refusal(&with(extra, drop)), flaw, "{extra:?} {drop:?}");
    }
}

#[test]
fn the_name_is_the_member_s_path_and_agrees_with_any_other() {
    let archive = |records: Vec<u8>| {
        let mut body = padded(map10(&REGIONS));
        body.extend(stored(&REGIONS));
        Tar::new()
            .pax(b'x', &records)
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
                &body,
            )
            .file("after", b"tail")
            .finish()
    };
    let mut same = records10(b"sparse", REAL);
    same.extend(pax_records(&[(b"path", b"sparse")]));
    assert_eq!(
        read_first(&archive(same), Level::Compatible)
            .unwrap()
            .0
            .path(),
        b"sparse"
    );
    let mut other = records10(b"sparse", REAL);
    other.extend(pax_records(&[(b"path", b"other")]));
    assert_eq!(refusal(&archive(other)), SparseFlaw::Name);
    assert_eq!(refusal(&archive(records10(b"", REAL))), SparseFlaw::Name);
    assert_eq!(
        refusal(&archive(records10(b"dir/", REAL))),
        SparseFlaw::Name
    );
    assert_eq!(
        refusal(&archive(records10(b"a\0b", REAL))),
        SparseFlaw::Name
    );
    // Without the record, the header's own name.
    let records = pax_records(&[
        (b"GNU.sparse.major", b"1"),
        (b"GNU.sparse.minor", b"0"),
        (b"GNU.sparse.realsize", b"4096"),
    ]);
    assert_eq!(
        read_first(&archive(records), Level::Compatible)
            .unwrap()
            .0
            .path(),
        b"GNUSparseFile.0/sparse"
    );
}

#[test]
fn each_form_keeps_its_header_and_slots() {
    let data = stored(&REGIONS);
    let size = data.len() as u64;
    // Under POSIX magic.
    let mut block = old_header("sparse", &REGIONS, REAL, size, false);
    block[257..265].copy_from_slice(b"ustar\x0000");
    seal(&mut block);
    let archive = Tar::new()
        .block(&block)
        .body(&data)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::Magic);
    // An unused slot before a used one.
    let mut block = old_header("sparse", &REGIONS, REAL, size, false);
    let (first, rest) = block[386..482].split_at_mut(24);
    rest[24..48].copy_from_slice(first);
    first.fill(0);
    seal(&mut block);
    let archive = Tar::new()
        .block(&block)
        .body(&data)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::Extension);
    // The extension flag set beside an unused slot, and an empty extension.
    let block = old_header("sparse", &REGIONS, REAL, size, true);
    let archive = Tar::new()
        .block(&block)
        .block(&extension(&[], false))
        .body(&data)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::Extension);
    // The stored data longer than the regions.
    let block = old_header("sparse", &REGIONS, REAL, size + 512, false);
    let mut more = data.clone();
    more.extend([0u8; 512]);
    let archive = Tar::new()
        .block(&block)
        .body(&more)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::StoredSize);
    // Pax records over a header with GNU's magic.
    let mut body = padded(map10(&REGIONS));
    body.extend(stored(&REGIONS));
    let mut header = Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64);
    header.magic = Magic::Gnu;
    let archive = Tar::new()
        .pax(b'x', &records10(b"sparse", REAL))
        .entry(header, &body)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::Magic);
    // A trailing slash.
    let block = old_header("sparse/", &REGIONS, REAL, size, false);
    let archive = Tar::new()
        .block(&block)
        .body(&data)
        .file("after", b"")
        .finish();
    assert_eq!(refusal(&archive), SparseFlaw::Name);
}

#[test]
fn the_extension_flag_is_set_exactly_where_a_full_block_continues() {
    let data = stored(&REGIONS);
    let size = data.len() as u64;
    // The flag beside an unused slot, a used one after it.
    let block = old_header("sparse", &REGIONS, REAL, size, true);
    let archive = Tar::new()
        .block(&block)
        .block(&extension(&[(8192, 0)], false))
        .body(&data)
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::Extension);
    // Four slots used and an extension block with none.
    let four = [(0, 512), (1024, 512), (2048, 512), (3072, 512)];
    let data = stored(&four);
    let block = old_header("sparse", &four, 3584, data.len() as u64, true);
    let archive = Tar::new()
        .block(&block)
        .block(&extension(&[], false))
        .body(&data)
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::Extension);
    // A flag that is neither 0 nor 1, before an extension block that would
    // otherwise be read.
    let five = [(0, 512), (1024, 512), (2048, 512), (3072, 512), (4096, 0)];
    let data = stored(&five);
    let mut block = old_header("sparse", &five, 4096, data.len() as u64, true);
    let archive = Tar::new()
        .block(&block)
        .block(&extension(&five[4..], false))
        .body(&data)
        .finish();
    assert!(read_first_only(&archive).is_ok());
    block[482] = 2;
    seal(&mut block);
    let archive = Tar::new()
        .block(&block)
        .block(&extension(&five[4..], false))
        .body(&data)
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::Extension);
}

/// The first member at Compatible.
fn read_first_only(archive: &[u8]) -> Result<Option<Entry>, ferrotape::Error> {
    Reader::new(archive)
        .with_level(Level::Compatible)
        .next_entry()
}

#[test]
fn the_pax_forms_keep_their_own_records() {
    let build = |records: &[Record]| {
        Tar::new()
            .pax(b'x', &pax_records(records))
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', 1024),
                &stored(&REGIONS),
            )
            .finish()
    };
    let map: &[u8] = b"1024,512,2560,512,4096,0";
    let base: [Record; 4] = [
        (b"GNU.sparse.size", b"4096"),
        (b"GNU.sparse.numblocks", b"3"),
        (b"GNU.sparse.name", b"sparse"),
        (b"GNU.sparse.map", map),
    ];
    assert!(
        Reader::new(build(&base).as_slice())
            .with_level(Level::Compatible)
            .next_entry()
            .is_ok()
    );
    let cases: [(&[Record], SparseFlaw); 5] = [
        (&[(b"GNU.sparse.realsize", b"4096")], SparseFlaw::Records),
        (&[(b"GNU.sparse.map", map)], SparseFlaw::Records),
        (&[(b"GNU.sparse.offset", b"0")], SparseFlaw::Records),
        (&[(b"GNU.sparse.size", b"4096")], SparseFlaw::Records),
        (&[(b"GNU.sparse.name", b"sparse")], SparseFlaw::Name),
    ];
    for (extra, flaw) in cases {
        let mut records = base.to_vec();
        records.extend_from_slice(extra);
        let got = Reader::new(build(&records).as_slice())
            .with_level(Level::Compatible)
            .next_entry()
            .map(|_| ())
            .map_err(|err| err.kind().clone());
        if flaw == SparseFlaw::Name {
            // The same name twice is read, as every reader reads it.
            assert!(got.is_ok(), "{extra:?}");
        } else {
            assert_eq!(got, Err(ErrorKind::Sparse(flaw)), "{extra:?}");
        }
    }
    let mut empty = base.to_vec();
    empty[3] = (b"GNU.sparse.map", b"1024,,2560,512,4096,0");
    assert_eq!(refusal_only(&build(&empty)), SparseFlaw::Number);
    // Format 0.0's pairs, a length before its offset.
    let pairs: [Record; 8] = [
        (b"GNU.sparse.size", b"4096"),
        (b"GNU.sparse.numblocks", b"3"),
        (b"GNU.sparse.numbytes", b"512"),
        (b"GNU.sparse.offset", b"1024"),
        (b"GNU.sparse.offset", b"2560"),
        (b"GNU.sparse.numbytes", b"512"),
        (b"GNU.sparse.offset", b"4096"),
        (b"GNU.sparse.numbytes", b"0"),
    ];
    assert_eq!(refusal_only(&build(&pairs)), SparseFlaw::Count);
}

#[test]
fn nothing_is_delivered_after_the_last_member() {
    let mut reader = Reader::new(archive10_alone()).with_level(Level::Compatible);
    assert!(reader.next_entry().unwrap().unwrap().sparse().is_some());
    assert!(reader.next_entry().unwrap().is_none());
    let rest = read_whole(reader.data(), 0).unwrap();
    assert!(rest.is_empty());
}

/// [`archive10`]'s member alone.
fn archive10_alone() -> std::io::Cursor<Vec<u8>> {
    let mut body = padded(map10(&REGIONS));
    body.extend(stored(&REGIONS));
    Cursor::new(
        Tar::new()
            .pax(b'x', &records10(b"sparse", REAL))
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
                &body,
            )
            .finish(),
    )
}

#[test]
fn sparse_records_belong_on_a_regular_member_s_own_header() {
    let records = records10(b"sparse", REAL);
    for typeflag in [b'5', b'2', b'7', 0, b'Z'] {
        let mut header = Header::new("GNUSparseFile.0/sparse", typeflag, 0);
        header.link = b"x".to_vec();
        let archive = Tar::new()
            .pax(b'x', &records)
            .header(&header)
            .file("after", b"")
            .finish();
        let err = read_first(&archive, Level::Compatible).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::Sparse(SparseFlaw::NotRegular) | ErrorKind::TargetWithoutLink { .. }
            ),
            "{typeflag}: {err}"
        );
    }
    // Applied global records reach no old GNU sparse member in Python.
    let data = stored(&REGIONS);
    let archive = Tar::new()
        .pax(b'g', &pax_records(&[(b"mtime", b"100")]))
        .block(&old_header(
            "sparse",
            &REGIONS,
            REAL,
            data.len() as u64,
            false,
        ))
        .body(&data)
        .finish();
    let err = Reader::new(archive.as_slice())
        .with_level(Level::Compatible)
        .with_global_headers(ferrotape::GlobalHeaders::Apply)
        .next_entry()
        .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Sparse(SparseFlaw::Global));
    let read = Reader::new(archive.as_slice())
        .with_level(Level::Compatible)
        .with_global_headers(ferrotape::GlobalHeaders::Defer)
        .next_entry();
    assert!(read.unwrap().unwrap().sparse().is_some());
    for mode in [
        ferrotape::GlobalHeaders::Refuse,
        ferrotape::GlobalHeaders::Apply,
        ferrotape::GlobalHeaders::Defer,
    ] {
        let archive = Tar::new().pax(b'g', &records).file("after", b"").finish();
        let err = Reader::new(archive.as_slice())
            .with_level(Level::Compatible)
            .with_global_headers(mode)
            .next_entry()
            .unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::Sparse(SparseFlaw::Global),
            "{mode:?}"
        );
    }
}

#[test]
fn a_real_size_record_on_a_sparse_member_is_read() {
    // Every reader takes a sparse member's real size from its map, and
    // ignores `SCHILY.realsize` there, bsdtar included.
    let data = stored(&REGIONS);
    let archive = Tar::new()
        .pax(b'x', &pax_record(b"SCHILY.realsize", b"100000"))
        .block(&old_header(
            "sparse",
            &REGIONS,
            REAL,
            data.len() as u64,
            false,
        ))
        .body(&data)
        .file("after", b"tail")
        .finish();
    let (entry, file_data, next) = read_first(&archive, Level::Strict).unwrap();
    assert_eq!(
        (entry.size(), file_data, next),
        (REAL, file(&REGIONS, REAL), b"after".to_vec())
    );
}

#[test]
fn a_real_size_is_below_2_to_the_60() {
    let large = (1u64 << 60) - 1;
    let regions = [(large - 512, 512)];
    let mut body = padded(map10(&regions));
    body.extend(stored(&regions));
    let build = |real: u64| {
        Tar::new()
            .pax(b'x', &records10(b"sparse", real))
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
                &body,
            )
            .finish()
    };
    // Read, and its first mebibyte delivered as zeros: the file is never held.
    let archive = build(large);
    let mut reader = Reader::new(archive.as_slice()).with_level(Level::Compatible);
    let entry = reader.next_entry().unwrap().unwrap();
    assert_eq!(entry.size(), large);
    let mut start = vec![1u8; 1 << 20];
    reader.data().read_exact(&mut start).unwrap();
    assert!(start.iter().all(|byte| *byte == 0));
    // The stored view reaches the data at once.
    let stored_size = entry.sparse().expect("a sparse member").stored_size();
    let region = read_whole(reader.stored_data(), stored_size).unwrap();
    assert_eq!(region, vec![b'A'; 512]);

    let regions = [(1u64 << 60, 0)];
    let body = padded(map10(&regions));
    let archive = Tar::new()
        .pax(b'x', &records10(b"sparse", 1 << 60))
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
            &body,
        )
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::RealSize);
}

/// The flaw the first member is refused with at Compatible.
fn refusal_only(archive: &[u8]) -> SparseFlaw {
    let err = Reader::new(archive)
        .with_level(Level::Compatible)
        .next_entry()
        .unwrap_err();
    match err.kind() {
        ErrorKind::Sparse(flaw) => *flaw,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_format_1_0_member_holds_its_map() {
    // The member's data ends inside its map.
    let archive = Tar::new()
        .pax(b'x', &records10(b"sparse", REAL))
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', 10),
            b"3\n1024\n512",
        )
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::StoredSize);
    // A count of 10^18 is read only as far as its pairs go, never
    // allocated: the padding after them is not a number.
    let mut body = padded(b"1000000000000000000\n1024\n512\n".to_vec());
    body.extend(vec![b'A'; 512]);
    let archive = Tar::new()
        .pax(b'x', &records10(b"sparse", REAL))
        .entry(
            Header::new("GNUSparseFile.0/sparse", b'0', body.len() as u64),
            &body,
        )
        .finish();
    assert_eq!(refusal_only(&archive), SparseFlaw::Number);
}

#[test]
fn a_refusal_names_the_rule() {
    let err = read_first(
        &Tar::new()
            .pax(b'x', &records10(b"sparse", REAL))
            .entry(
                Header::new("GNUSparseFile.0/sparse", b'0', 512),
                &padded(map10(&[(1024, 0)])),
            )
            .finish(),
        Level::Compatible,
    )
    .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::Sparse(SparseFlaw::End));
    assert_eq!(err.offset(), BLOCK as u64 * 2);
    assert_eq!(
        err.to_string(),
        "a sparse member's map does not end at the file's real size at offset 1024"
    );
}
