//! The harness's commands.
//!
//! ```text
//! harness record [--unpinned] PATH...
//!     record each reference reader's reading of every case under PATH into
//!     its file
//! harness check [--unpinned] PATH...
//!     read every case under PATH with the reference readers, and report
//!     each reading that differs from the one recorded
//! harness build CASE OUT
//!     write a case's archive to OUT
//! harness read PATH...
//!     read every case under PATH with ferrotape, and show its verdict in
//!     each setting and, where it reads, how its members differ from each
//!     recorded reading its setting is compared with
//! harness mutate [--unpinned] [--seed N] [--count N] [--seconds N]
//!                [--jobs N] [--out DIR] PATH...
//!     read mutants of the archives of the cases under PATH with ferrotape
//!     and the reference readers, and report each mutant ferrotape reads
//!     otherwise than a reader its setting stands in for
//! ```
//!
//! `record`, `check` and `mutate` need the reference readers (see the
//! catalog's README), each at the version the catalog pins; `--unpinned`
//! reads with whatever versions are installed, as a check against a
//! reader's newer release does. `check` exits with status 1 where any
//! reading differs, and `mutate` where any mutant is read otherwise.
//!
//! `mutate` reads mutants 0, 1, 2 and on of the seed (by default 1) until
//! it has read `--count` of them or `--seconds` have passed, on `--jobs`
//! threads (by default 4). A mutant ferrotape refuses in every setting is
//! not given to the readers, since a refusal reads nothing. Each kind of
//! difference found is reported with the mutants that show it, and with
//! `--out`, the first three of each are written to DIR as cases, their
//! verdicts and readings recorded.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferrotape_harness::case::{Case, Reader};
use ferrotape_harness::record::{self, Readers};
use ferrotape_harness::{case_files, load};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("record") => record_or_check(&args[1..], true),
        Some("check") => record_or_check(&args[1..], false),
        Some("build") => build(&args[1..]),
        Some("read") => read(&args[1..]),
        Some("mutate") => mutate::run(&args[1..]),
        Some("gnu-data") => record::gnu_data().map(|()| true),
        _ => Err(
            "usage: harness record|check|mutate [OPTIONS] PATH... | harness build CASE OUT"
                .to_owned(),
        ),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("harness: {error}");
            ExitCode::from(2)
        }
    }
}

/// A scratch directory for the readers, under the system's temporary one.
fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!("ferrotape-harness-{}", std::process::id()))
}

fn record_or_check(args: &[String], record: bool) -> Result<bool, String> {
    let unpinned = args.first().is_some_and(|a| a == "--unpinned");
    let paths = if unpinned { &args[1..] } else { args };
    if paths.is_empty() {
        return Err("name a case file or a directory of them".to_owned());
    }
    let scratch = scratch();
    let readers = Readers::new(&scratch)?;
    if !unpinned && let Err(error) = pinned(&readers) {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(error);
    }
    let mut same = true;
    let mut count = 0;
    for path in paths {
        for file in case_files(Path::new(path))? {
            let mut case: Case = load(&file)?;
            let readings = readers
                .read(&case.archive.build())
                .map_err(|e| format!("{}: {e}", file.display()))?;
            count += 1;
            if record {
                case.readings = readings;
                std::fs::write(&file, case.to_string())
                    .map_err(|e| format!("{}: {e}", file.display()))?;
                continue;
            }
            for (reader, version, reading) in &readings {
                let recorded = case.readings.iter().find(|(r, _, _)| r == reader);
                if recorded.map(|(_, _, r)| r) != Some(reading) {
                    same = false;
                    let was = recorded.map_or(String::from("nothing\n"), |(_, v, r)| {
                        format!("{} {v}:\n{r}", reader.name())
                    });
                    println!(
                        "{}: {} {version} now reads:\n{reading}recorded, {was}",
                        file.display(),
                        reader.name()
                    );
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    let verb = if record { "recorded" } else { "checked" };
    eprintln!("{count} cases {verb} with {}", versions(&readers));
    Ok(same)
}

/// Each reader and its version, for a report.
fn versions(readers: &Readers) -> String {
    let versions: Vec<String> = Reader::ALL
        .iter()
        .map(|&r| format!("{} {}", r.name(), readers.version(r)))
        .collect();
    versions.join(", ")
}

/// Fails, naming each, where a reader is not at the version the catalog
/// pins.
fn pinned(readers: &Readers) -> Result<(), String> {
    let other: Vec<String> = Reader::ALL
        .iter()
        .filter(|r| readers.version(**r) != r.pinned())
        .map(|r| {
            format!(
                "{} is {}, where the catalog pins {}",
                r.name(),
                readers.version(*r),
                r.pinned()
            )
        })
        .collect();
    if other.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}; pass --unpinned to read with other versions",
        other.join("; ")
    ))
}

mod mutate {
    //! The `mutate` command.

    use std::collections::{BTreeMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use ferrotape_harness::archive::Archive;
    use ferrotape_harness::case::{Case, Reader, SETTINGS, Verdict};
    use ferrotape_harness::compare::{self, Difference};
    use ferrotape_harness::mutate::{Steps, mutant};
    use ferrotape_harness::reading::{Reading, fnv};
    use ferrotape_harness::record::Readers;
    use ferrotape_harness::{case_files, load};

    /// A mutant larger than this is not read: the catalog's archives are a
    /// few blocks, and a mutant's size comes from what it declares, not
    /// from what it holds.
    const LARGEST: usize = 1 << 20;

    /// A mutant ferrotape reads otherwise than a reader.
    struct Found {
        index: u64,
        from: PathBuf,
        steps: Steps,
        archive: Archive,
        verdicts: Vec<Verdict>,
        readings: Vec<(Reader, String, Reading)>,
        differences: Vec<(String, Difference)>,
    }

    impl Found {
        /// What kind of difference this is: each level it is found at, with
        /// each reader and what differs, so that one shape found by many
        /// mutants is reported once.
        fn signature(&self) -> String {
            let mut kinds: Vec<String> = self
                .differences
                .iter()
                .map(|(setting, d)| {
                    let level = setting.split(' ').next().unwrap_or_default();
                    format!("{level}: {} {}", d.reader.name(), d.what)
                })
                .collect();
            kinds.sort();
            kinds.dedup();
            kinds.join("; ")
        }

        /// The mutant as a case, its verdicts and readings recorded.
        fn case(&self, seed: u64) -> Result<Case, String> {
            let mut statement = format!(
                "Mutant {} of seed {seed}, from `{}`: {}.\n\nRead otherwise:",
                self.index,
                self.from.display(),
                self.steps.join(" ")
            );
            for (setting, difference) in self.differences.iter().take(6) {
                statement.push_str(&format!("\n- {setting}: {difference}"));
            }
            let archive_text = self.archive.lines();
            let verdicts = self
                .verdicts
                .clone()
                .try_into()
                .map_err(|_| "six verdicts")?;
            Ok(Case {
                statement,
                archive_text,
                archive: self.archive.clone(),
                verdicts,
                readings: self.readings.clone(),
            })
        }
    }

    /// The command's options.
    struct Options {
        unpinned: bool,
        seed: u64,
        count: Option<u64>,
        seconds: Option<u64>,
        jobs: usize,
        out: Option<PathBuf>,
        paths: Vec<String>,
    }

    fn options(args: &[String]) -> Result<Options, String> {
        let mut options = Options {
            unpinned: false,
            seed: 1,
            count: None,
            seconds: None,
            jobs: 4,
            out: None,
            paths: Vec::new(),
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let mut value = |name: &str| -> Result<String, String> {
                args.next()
                    .cloned()
                    .ok_or_else(|| format!("{name} takes a value"))
            };
            let number = |text: String| -> Result<u64, String> {
                text.parse()
                    .map_err(|_| format!("`{text}` is not a number"))
            };
            match arg.as_str() {
                "--unpinned" => options.unpinned = true,
                "--seed" => options.seed = number(value(arg)?)?,
                "--count" => options.count = Some(number(value(arg)?)?),
                "--seconds" => options.seconds = Some(number(value(arg)?)?),
                "--jobs" => {
                    options.jobs = usize::try_from(number(value(arg)?)?)
                        .map_err(|e| e.to_string())?
                        .max(1);
                }
                "--out" => options.out = Some(PathBuf::from(value(arg)?)),
                path => options.paths.push(path.to_owned()),
            }
        }
        if options.paths.is_empty() {
            return Err("name a case file or a directory of them".to_owned());
        }
        if options.count.is_none() && options.seconds.is_none() {
            return Err("bound the run with --count, --seconds or both".to_owned());
        }
        Ok(options)
    }

    /// Reads one mutant: `None` where ferrotape refuses it in every setting
    /// or every reader its settings stand in for reads it alike, and the
    /// mutant otherwise.
    fn read_one(
        readers: &Readers,
        given: &AtomicU64,
        dir: &Path,
        index: u64,
        from: &Path,
        steps: Steps,
        archive: Archive,
    ) -> Result<Option<Found>, String> {
        let bytes = archive.build();
        let ours: Vec<_> = SETTINGS
            .iter()
            .map(|&(level, mode)| compare::read(&bytes, level, mode))
            .collect();
        if ours.iter().all(|(_, verdict)| *verdict != Verdict::Read) {
            return Ok(None);
        }
        given.fetch_add(1, Ordering::Relaxed);
        let readings = readers.read_in(dir, &bytes)?;
        let mut differences = Vec::new();
        for (&(level, mode), (members, verdict)) in SETTINGS.iter().zip(&ours) {
            if *verdict != Verdict::Read {
                continue;
            }
            let setting = format!("{} {}", level.name(), mode.name());
            for &reader in mode.readers() {
                let Some((_, _, reading)) = readings.iter().find(|(r, _, _)| *r == reader) else {
                    continue;
                };
                for difference in compare::differences(members, reader, reading) {
                    if difference.stated {
                        continue;
                    }
                    differences.push((setting.clone(), difference));
                }
            }
        }
        if differences.is_empty() {
            return Ok(None);
        }
        Ok(Some(Found {
            index,
            from: from.to_owned(),
            steps,
            archive,
            verdicts: ours.into_iter().map(|(_, v)| v).collect(),
            readings,
            differences,
        }))
    }

    /// Runs the command.
    pub fn run(args: &[String]) -> Result<bool, String> {
        let options = options(args)?;
        let mut cases = Vec::new();
        for path in &options.paths {
            for file in case_files(Path::new(path))? {
                cases.push((file.clone(), load(&file)?.archive));
            }
        }
        if cases.is_empty() {
            return Err("no case to mutate".to_owned());
        }
        let archives: Vec<Archive> = cases.iter().map(|(_, a)| a.clone()).collect();
        let scratch = super::scratch();
        let readers = Readers::new(&scratch)?;
        if !options.unpinned
            && let Err(error) = super::pinned(&readers)
        {
            let _ = std::fs::remove_dir_all(&scratch);
            return Err(error);
        }

        let started = Instant::now();
        let deadline = options.seconds.map(|s| started + Duration::from_secs(s));
        let next = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        let seen = Mutex::new(HashSet::new());
        let found = Mutex::new(Vec::new());
        let failure = Mutex::new(None);
        let given = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for job in 0..options.jobs {
                let dir = scratch.join(format!("mutant-{job}"));
                let (archives, cases, readers) = (&archives, &cases, &readers);
                let (next, stop, seen, found, failure, given) =
                    (&next, &stop, &seen, &found, &failure, &given);
                scope.spawn(move || {
                    loop {
                        if stop.load(Ordering::Relaxed)
                            || deadline.is_some_and(|d| Instant::now() >= d)
                        {
                            break;
                        }
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if options.count.is_some_and(|c| index >= c) {
                            break;
                        }
                        let (from, archive, steps) = mutant(options.seed, index, archives);
                        let bytes = archive.build();
                        if bytes.len() > LARGEST
                            || !seen
                                .lock()
                                .map(|mut s| s.insert(fnv(&bytes)))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        match read_one(readers, given, &dir, index, &cases[from].0, steps, archive)
                        {
                            Ok(Some(mutant)) => {
                                if let Ok(mut found) = found.lock() {
                                    found.push(mutant);
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                if let Ok(mut failure) = failure.lock() {
                                    failure.get_or_insert(format!("mutant {index}: {error}"));
                                }
                                stop.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
        let _ = std::fs::remove_dir_all(&scratch);
        if let Some(error) = failure.into_inner().map_err(|e| e.to_string())? {
            return Err(error);
        }
        let mut found = found.into_inner().map_err(|e| e.to_string())?;
        found.sort_by_key(|f| f.index);
        let made = next.load(Ordering::Relaxed);
        let made = options.count.map_or(made, |c| made.min(c));
        let distinct = seen.into_inner().map_err(|e| e.to_string())?.len();
        let mut kinds: BTreeMap<String, Vec<&Found>> = BTreeMap::new();
        for mutant in &found {
            kinds.entry(mutant.signature()).or_default().push(mutant);
        }
        for (signature, mutants) in &kinds {
            println!("{signature}: {} mutants", mutants.len());
            for mutant in mutants.iter().take(3) {
                println!(
                    "  mutant {} from {}: {}",
                    mutant.index,
                    mutant.from.display(),
                    mutant.steps.join(" ")
                );
                for (setting, difference) in mutant.differences.iter().take(3) {
                    println!("    {setting}: {difference}");
                }
            }
        }
        if let Some(out) = &options.out {
            std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
            for mutants in kinds.values() {
                for mutant in mutants.iter().take(3) {
                    let file = out.join(format!("mutant-{}-{}.case", options.seed, mutant.index));
                    let case = mutant.case(options.seed)?;
                    std::fs::write(&file, case.to_string())
                        .map_err(|e| format!("{}: {e}", file.display()))?;
                }
            }
        }
        eprintln!(
            "{made} mutants of seed {} made, {distinct} distinct, {} read by ferrotape in some \
             setting and given to the readers ({}), {} read otherwise in {} ways, in {:.0?}",
            options.seed,
            given.load(Ordering::Relaxed),
            super::versions(&readers),
            found.len(),
            kinds.len(),
            started.elapsed()
        );
        Ok(found.is_empty())
    }
}

fn read(paths: &[String]) -> Result<bool, String> {
    use ferrotape_harness::case::{SETTINGS, Verdict};
    use ferrotape_harness::compare;
    for path in paths {
        for file in case_files(Path::new(path))? {
            let case = load(&file)?;
            let bytes = case.archive.build();
            println!("{}:", file.display());
            for (level, mode) in SETTINGS {
                let (members, verdict) = compare::read(&bytes, level, mode);
                println!("  {} {}: {verdict}", level.name(), mode.name());
                if verdict != Verdict::Read {
                    continue;
                }
                for &reader in mode.readers() {
                    let Some(reading) = case.reading(reader) else {
                        continue;
                    };
                    for difference in compare::differences(&members, reader, reading) {
                        println!("    {difference}");
                    }
                }
            }
        }
    }
    Ok(true)
}

fn build(args: &[String]) -> Result<bool, String> {
    let [case, out] = args else {
        return Err("usage: harness build CASE OUT".to_owned());
    };
    let case = load(Path::new(case))?;
    std::fs::write(out, case.archive.build()).map_err(|e| e.to_string())?;
    Ok(true)
}
