//! The case catalog's checks, which need no reference reader installed.
//!
//! Every case reads, is written in its one form, states its rule, and holds a
//! reading from each reference reader at the version the catalog pins.
//! ferrotape gives each case's stated verdict in every setting, and wherever
//! it reads a case, its members are those the reference readers the setting's
//! mode stands in for read: their paths, link targets, data, kinds, owners
//! and times, as far as each reader reports them.

use std::fs;
use std::path::PathBuf;

use ferrotape_harness::case::{Case, Reader};
use ferrotape_harness::{case_files, catalog_dir, compare};

fn catalog() -> Vec<(PathBuf, String, Case)> {
    case_files(&catalog_dir())
        .unwrap()
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            let case = Case::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (path, text, case)
        })
        .collect()
}

#[test]
fn every_case_is_well_formed() {
    let catalog = catalog();
    for (path, text, case) in &catalog {
        let path = path.display();
        assert_eq!(
            case.to_string(),
            *text,
            "{path} is not in its written form; the harness would write it as shown"
        );
        assert!(!case.statement.is_empty(), "{path} states no rule");
        let readers: Vec<Reader> = case.readings.iter().map(|(r, _, _)| *r).collect();
        assert_eq!(readers, Reader::ALL, "{path} lacks a reading");
        for (reader, version, _) in &case.readings {
            assert_eq!(
                version,
                reader.pinned(),
                "{path} was read by {} {version}, not the pinned {}",
                reader.name(),
                reader.pinned()
            );
        }
    }
    assert!(catalog.len() >= 98, "{} cases", catalog.len());
}

#[test]
fn ferrotape_reads_every_case_as_stated() {
    let catalog = catalog();
    let mut failures = Vec::new();
    let mut compared = 0;
    for (path, _, case) in &catalog {
        let name = path.strip_prefix(catalog_dir()).unwrap_or(path).display();
        let checked = compare::check(case);
        compared += checked.compared;
        for failure in checked.failures {
            failures.push(format!("{name}: {failure}"));
        }
    }
    eprintln!(
        "{} cases in six settings; ferrotape's members compared with {compared} readings",
        catalog.len()
    );
    assert!(
        failures.is_empty(),
        "{} failures over {} cases:\n{}",
        failures.len(),
        catalog.len(),
        failures.join("\n")
    );
}

/// The cases the page of stated differences names: every quoted name in
/// the last column, "Cases", of each table in `src/differences.rs`.
fn named_differences() -> Vec<String> {
    const PAGE: &str = include_str!("../../src/differences.rs");
    PAGE.lines()
        .filter_map(|line| line.strip_prefix("//! |"))
        .filter_map(|row| row.trim_end().strip_suffix('|')?.rsplit('|').next())
        .flat_map(|cases| cases.split('`').skip(1).step_by(2))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_stated_differences_name_every_difference_and_nothing_else() {
    let named = named_differences();
    let catalog = catalog();
    let case_name = |path: &PathBuf| {
        let relative = path.strip_prefix(catalog_dir()).unwrap_or(path);
        relative.with_extension("").display().to_string()
    };
    let names: Vec<String> = catalog.iter().map(|(p, _, _)| case_name(p)).collect();
    let missing: Vec<&String> = named.iter().filter(|n| !names.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "named, but no case of the catalog: {missing:?}"
    );
    let mut unnamed = Vec::new();
    let mut agreed = Vec::new();
    for (path, _, case) in &catalog {
        let name = case_name(path);
        let listed = named.contains(&name);
        match (compare::undisputed(case), listed) {
            (false, false) => unnamed.push(name),
            (true, true) => agreed.push(name),
            _ => {}
        }
    }
    assert!(
        unnamed.is_empty(),
        "read otherwise by ferrotape or a reference reader, but named by no row of src/differences.rs: {unnamed:?}"
    );
    assert!(
        agreed.is_empty(),
        "named by a row of src/differences.rs, but read alike by every reader: {agreed:?}"
    );
}

#[test]
fn every_archive_is_written_back_as_items_that_build_it() {
    for (path, _, case) in catalog() {
        let lines = case.archive.lines();
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let again = ferrotape_harness::archive::Archive::parse(&lines)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            again.build(),
            case.archive.build(),
            "{}: {lines:#?}",
            path.display()
        );
    }
}
