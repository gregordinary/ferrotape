//! Test tooling for ferrotape: the case catalog, and the reference readers as
//! its oracle.
//!
//! The catalog (`catalog/` in the repository) holds the cases ferrotape is
//! measured against, one file each: the rule a case shows, its archive,
//! ferrotape's verdict in each setting, and what each reference reader read
//! from the archive at the version the catalog pins. [`case`] reads a case
//! file, [`archive`] builds its archive, [`compare`] reads it with ferrotape
//! and holds the result to the case, [`record`] runs the reference readers,
//! and [`mutate`] derives new archives from the catalog's.

pub mod archive;
pub mod case;
pub mod compare;
pub mod mutate;
pub mod reading;
pub mod record;
pub mod value;

use std::fs;
use std::path::{Path, PathBuf};

/// The case files under `path`, a case file or a directory, sorted.
pub fn case_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
        if path.is_dir() {
            let entries = fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
            for entry in entries {
                walk(&entry.map_err(|e| e.to_string())?.path(), files)?;
            }
        } else if path.extension().is_some_and(|e| e == "case") {
            files.push(path.to_owned());
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(path, &mut files)?;
    files.sort();
    Ok(files)
}

/// The catalog's directory.
pub fn catalog_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../catalog")
}

/// Reads a case file.
pub fn load(path: &Path) -> Result<case::Case, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    case::Case::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}
