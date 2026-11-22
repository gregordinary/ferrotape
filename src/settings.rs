//! What a reader is set to: how strictly it reads, what it does with global
//! extended headers, and how much an archive may make it hold in memory.

/// Ceilings on what an archive can make the reader allocate.
///
/// The defaults suit any archive a mainstream writer produces. Set a field to
/// change one:
///
/// ```
/// let mut limits = ferrotape::Limits::default();
/// limits.metadata = 4 << 20;
/// let reader = ferrotape::Reader::new(&b""[..]).with_limits(limits);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// The most data a metadata member may declare, in bytes: a GNU long name
    /// or long link, a pax extended header, or a global one. Each is held in
    /// memory whole, and one larger is refused with
    /// [`ErrorKind::MetadataLimit`](crate::ErrorKind::MetadataLimit) before
    /// any of it is read. Reading at [`Level::Strict`] indexes an extended
    /// header's records to compare them, which holds up to about six times
    /// the header's size again while it does.
    ///
    /// It holds a sparse member's map as well: an old GNU header and its
    /// extension blocks, or the blocks of a map in GNU's pax format 1.0, are
    /// refused past it ([`SparseFlaw::MapLimit`](crate::SparseFlaw::MapLimit)),
    /// as Go refuses one past 1 MiB; a map in pax records is within its
    /// extended header.
    ///
    /// 1 MiB by default. Real metadata members are at most a few kilobytes.
    pub metadata: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { metadata: 1 << 20 }
    }
}

/// Whose readings an archive must agree with to be read.
///
/// ferrotape reads an archive as GNU tar, bsdtar, Go's `archive/tar` and
/// Python's `tarfile` read it, and refuses one they read differently, at
/// every level but for the one exception [`Compatible`](Self::Compatible)
/// states. A level says which other readers count as well. Each
/// [`ErrorKind`](crate::ErrorKind) a level adds says which readers it
/// protects.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[non_exhaustive]
pub enum Level {
    /// Every reader in wide use counts: the four above; POSIX, where it says
    /// one thing and they another; the Rust crates `tar`, `tar-core` and
    /// `tar-codec`; and GNU tar reading on past the end of an archive, as
    /// `--ignore-zeros` does. An archive any of them reads with other members
    /// is refused.
    ///
    /// For archives from sources the caller does not control: a check made
    /// with it passes nothing that a widely used extractor then reads
    /// otherwise. Mainstream writers do not produce what this level refuses
    /// and the next reads.
    #[default]
    Strict,
    /// The four readers above and POSIX count, and no others.
    ///
    /// For archives a trusted publisher vouches for, and archives the caller
    /// owns: every archive the four read alike is read, and an archive they
    /// read differently is still refused, with one exception. A member whose
    /// mode has setuid, setgid or sticky and which carries an access control
    /// list, which GNU tar extracts with those bits and bsdtar without them,
    /// is read with the header's mode, as GNU tar extracts it
    /// ([`ErrorKind::SpecialBitsWithAcl`](crate::ErrorKind::SpecialBitsWithAcl)):
    /// both tars write such members for shared setgid and sticky directories.
    /// A reader outside the four may read what this level accepts otherwise.
    Compatible,
}

/// What a reader does with a global extended header (typeflag `g`).
///
/// A global header states records for every member after it. GNU tar and
/// Python apply them, in ways that agree only on a narrow range; bsdtar and
/// Go apply none. A program reads as one family or the other, or refuses
/// what they would read apart, and the setting says which.
///
/// In every mode, a global header's records reach the caller exactly once, in
/// stream order: through [`Entry::global`](crate::Entry::global) on the
/// member that follows the header, or through
/// [`Reader::trailing_global`](crate::Reader::trailing_global) for a header
/// that follows the last member. A global header that arrives while metadata
/// waits for its member is refused in every mode, as is a second one before
/// a member: the families read neither alike.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[non_exhaustive]
pub enum GlobalHeaders {
    /// A global header carrying any record but `comment` is refused.
    ///
    /// The default: every reader reads alike what this mode accepts.
    /// `comment` changes no member; it is the record `git archive` writes,
    /// holding the commit an archive was made from.
    #[default]
    Refuse,
    /// A global header's `path`, `linkpath`, `uid`, `gid`, `uname`, `gname`
    /// and `mtime` records apply to every member after it, beneath each
    /// member's own pax records, as GNU tar and Python apply them.
    ///
    /// Refused where those two read apart: a `size` record, an empty value,
    /// any other record but `comment`, and any global header after one that
    /// has set a member's field (GNU tar replaces the earlier header's
    /// records, and Python merges the two). For a program that stands in for
    /// GNU tar or Python.
    Apply,
    /// No global header's records apply to any member, which is read from
    /// its own headers alone, as Go reads it. The records reach the caller,
    /// to apply as it chooses.
    ///
    /// bsdtar read so too until libarchive 3.8.10, which refuses an archive
    /// where a global header carrying any record but `comment` precedes a
    /// member; where this mode reads such an archive, it reads as Go alone
    /// does.
    ///
    /// For a program that stands in for bsdtar or Go, and for one that
    /// carries an archive on without reading its meaning.
    Defer,
}
