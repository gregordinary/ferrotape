//! A reader's settings: how strictly it reads, what it does with global
//! extended headers, and how much an archive can make it hold in memory.

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
    /// It limits a sparse member's map as well, as Go refuses a map past 1 MiB
    /// ([`SparseFlaw::MapLimit`](crate::SparseFlaw::MapLimit)). The map's
    /// blocks count: an old GNU header and its extension blocks, or a format
    /// 1.0 map's blocks. A map in pax records is within its extended header.
    ///
    /// 1 MiB by default. Real metadata members are at most a few kilobytes.
    /// What the reader holds for a member's metadata, its indexes included,
    /// stays within what one allocation can be. So a limit above a sixteenth
    /// of the largest allocation the target allows is read as that sixteenth:
    /// 128 MiB on a 32-bit target.
    pub metadata: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { metadata: 1 << 20 }
    }
}

impl Limits {
    /// [`metadata`](Self::metadata), at most a sixteenth of the largest
    /// allocation the target allows. What the reader builds from a metadata
    /// member is at most about six times its size. A buffer that doubles as
    /// it grows asks for twice what it holds. So no allocation it asks for is
    /// larger than one can be.
    pub(crate) fn metadata_bound(&self) -> u64 {
        self.metadata.min(allocation_bound() / 8)
    }
}

/// Half the largest allocation the target allows, `isize::MAX` bytes: 1 GiB
/// on a 32-bit target. A buffer that doubles as it grows can hold this much
/// before it asks for more than one allocation can be.
pub(crate) fn allocation_bound() -> u64 {
    u64::try_from(isize::MAX.unsigned_abs() / 2).unwrap_or(u64::MAX)
}

/// Whose readings an archive must agree with to be read.
///
/// ferrotape reads an archive as GNU tar, bsdtar, Go's `archive/tar` and
/// Python's `tarfile` read it, and refuses one they read differently. Every
/// level does so, but for the one exception [`Compatible`](Self::Compatible)
/// states. A level says which other readers count as well. Each
/// [`ErrorKind`](crate::ErrorKind) a level adds says which readers it
/// protects.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[non_exhaustive]
pub enum Level {
    /// Every reader in wide use counts:
    ///
    /// - The four above
    /// - POSIX, where it says one thing and they another
    /// - The Rust crates `tar`, `tar-core` and `tar-codec`
    /// - GNU tar reading on past the end of an archive, as `--ignore-zeros`
    ///   does
    ///
    /// An archive any of them reads with other members is refused.
    ///
    /// For archives from sources the caller does not control: a check made
    /// with it passes nothing that a widely used extractor then reads
    /// otherwise. Mainstream writers produce two kinds of archive this level
    /// refuses and the next reads. One is a sparse member in GNU's pax forms
    /// ([`SparseFlaw::PaxForm`](crate::SparseFlaw::PaxForm)), which bsdtar
    /// writes for any file with holes and GNU tar with `--format=posix
    /// --sparse`. The other is a member whose mode has setuid, setgid or
    /// sticky beside an access control list, which both tars write for
    /// shared directories.
    #[default]
    Strict,
    /// The four readers above and POSIX count, and no others.
    ///
    /// For archives a trusted publisher vouches for, and archives the caller
    /// owns. Every archive the four read alike is read, and an archive they
    /// read differently is still refused, with one exception. A member whose
    /// mode has setuid, setgid or sticky, and which has an access control
    /// list, is read with the header's mode
    /// ([`ErrorKind::SpecialBitsWithAcl`](crate::ErrorKind::SpecialBitsWithAcl)).
    /// GNU tar extracts it with those bits, and bsdtar without them. Both tars
    /// write such members for shared setgid and sticky directories.
    /// A reader outside the four can read what this level accepts otherwise.
    Compatible,
}

/// What a reader does with a global extended header (typeflag `g`).
///
/// A global header states records for every member after it. GNU tar and
/// Python apply them, in ways that agree only on a narrow range. bsdtar and
/// Go apply none. A program reads as one family or the other, or refuses
/// what they would read apart, and the setting says which.
///
/// In every mode, a global header's records reach the caller exactly once, in
/// stream order. They reach it through [`Entry::global`](crate::Entry::global)
/// on the member that follows the header, or through
/// [`Reader::trailing_global`](crate::Reader::trailing_global) for a header
/// that follows the last member. A global header that arrives while metadata
/// waits for its member is refused in every mode. A second one before a
/// member is refused too, since the families read neither alike.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[non_exhaustive]
pub enum GlobalHeaders {
    /// A global header holding any record but `comment` is refused.
    ///
    /// The default: every reader reads alike what this mode accepts.
    /// `comment` changes no member. It is the record `git archive` writes,
    /// holding the commit an archive was made from.
    #[default]
    Refuse,
    /// A global header's `path`, `linkpath`, `uid`, `gid`, `uname`, `gname`
    /// and `mtime` records apply to every member after it, as GNU tar and
    /// Python apply them. Each member's own pax records take precedence.
    ///
    /// Refused where those two read apart: a `size` record, an empty value,
    /// and any other record but `comment`. A global header after one that has
    /// set a member's field is refused too. GNU tar replaces the earlier
    /// header's records, and Python merges the two. For a program that stands in for
    /// GNU tar or Python.
    ///
    /// Each member holds a copy of the global `path`, `linkpath`, `uname` and
    /// `gname` it takes. So a value longer than 4,095 bytes is refused
    /// ([`ErrorKind::GlobalValueLimit`](crate::ErrorKind::GlobalValueLimit)),
    /// which holds the copy to a few times what a member's own header costs.
    Apply,
    /// No global header's records apply to any member, which is read from
    /// its own headers alone, as Go reads it. The records reach the caller,
    /// to apply as it chooses.
    ///
    /// bsdtar read so too until libarchive 3.8.10. From that release, it
    /// refuses an archive where a global header holding any record but
    /// `comment` precedes a member. Where this mode reads such an archive, it
    /// reads as Go alone does.
    ///
    /// For a program that stands in for bsdtar or Go, and for one that passes
    /// an archive on without reading its meaning.
    Defer,
}
