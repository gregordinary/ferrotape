# ferrotape

A tape archive (tar) reader and header writer for untrusted input, in safe
Rust.

ferrotape is in early development. Its API is not yet stable.

It reads the tar formats in use: POSIX ustar and pax, GNU, and pre-POSIX v7.
It reads an archive as GNU tar, bsdtar, Go's `archive/tar` and Python's
`tarfile` read it, and refuses one they read differently. The `Compatible`
level makes one exception (see "Settings" below). A program that checks an
archive with ferrotape therefore sees the members those readers would
extract. Such programs include a package registry validating an upload, a
scanner, and a tool that indexes a format with tar inside.

Its writer encodes ustar headers, preceded by pax records for what ustar
cannot hold, and refuses a header that would not read back as set. A member
whose mode has setuid, setgid or sticky beside an access control list reads
back at the `Compatible` level alone. The writer writes it as GNU tar does,
but the `Strict` level refuses it.

ferrotape parses and serializes. It never touches a filesystem, and has no
`unsafe` code and no dependencies. Every allocation an archive can drive has
a ceiling the caller can set.

## Reading

A `Reader` reads an archive from any `Read`, and each member's data goes
where the caller puts it. Here the regular files go into a map held in
memory, and paths that would leave a directory are refused:

```rust
use std::collections::BTreeMap;
use std::error::Error;
use std::io::Read;

use ferrotape::{EntryKind, Reader};

/// The regular files of an archive, by path.
fn files(archive: impl Read) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn Error>> {
    let mut reader = Reader::new(archive);
    let mut files = BTreeMap::new();
    while let Some(entry) = reader.next_entry()? {
        let path = entry.path().to_vec();
        if !beneath(&path) {
            return Err(format!("{} leaves the destination", path.escape_ascii()).into());
        }
        match entry.kind() {
            // Each file is held whole, and one larger than 16 MiB is refused.
            EntryKind::File => {
                let data = reader.read_entry(16 << 20)?;
                files.insert(path, data);
            }
            // A hard link names an earlier file, whose data it shares.
            EntryKind::HardLink => {
                let target = entry.link_target();
                let Some(data) = files.get(target).cloned() else {
                    let (path, target) = (path.escape_ascii(), target.escape_ascii());
                    return Err(format!("{path} links to {target}, no earlier file").into());
                };
                files.insert(path, data);
            }
            // Directories, symbolic links, devices and FIFOs hold no data.
            _ => {}
        }
    }
    // The rest of the stream, so that a decoder beneath checks its trailer.
    reader.finish(1 << 20)?;
    Ok(files)
}

/// Whether `path` stays beneath the directory it is read into: relative,
/// with no `..` component.
fn beneath(path: &[u8]) -> bool {
    !path.starts_with(b"/") && path.split(|&byte| byte == b'/').all(|part| part != b"..")
}
```

A sparse member is a file with holes, as GNU tar and bsdtar write one. It is
read as the file it stands for: `data` delivers its holes as zeros.
`Entry::size` is the file's size, which can be far larger than the archive.
`Entry::sparse` gives its map, and `Reader::stored_data` the stored regions
alone, for an extractor that writes the holes as holes. A map is read only
in the shapes the reference readers extract alike. At the `Strict` level,
only GNU's old form (typeflag `S`) is read, since Rust's `tar` reads the pax
forms as plain files of their stored data.

A compressed archive is read through its decoder, from a crate of its own:
`Reader::new(GzDecoder::new(file))` with `flate2`, and likewise for xz, zstd
and bzip2. `Reader::finish` reads on to the end of the stream, so the decoder
compares the check that closes it.

A `Decoder` is the reader without I/O. It reads a source that a `Read` does
not fit, such as an asynchronous stream or a buffer filled as data arrives.
It says what it needs next and frames every member's data itself. Its caller
only moves bytes, and every rule and limit applies as in a `Reader`. Without
its default `std` feature, the library builds on `core` and `alloc` alone and
reads through a `Decoder`.

## Writing

A `Header` describes a member, and a `Writer` appends each member's header
and data to any `Write`, then ends the archive:

```rust
use ferrotape::{Header, Timestamp, WriteError, Writer};

fn archive() -> Result<Vec<u8>, WriteError> {
    let mut writer = Writer::new(Vec::new());
    writer.append(&Header::directory("docs/"), std::io::empty())?;
    let mut readme = Header::file("docs/readme.txt", 6);
    readme
        .set_owner(1000, 1000)
        .set_mtime(Timestamp::from_secs(1_700_000_000));
    writer.append(&readme, &b"hello\n"[..])?;
    writer.finish()
}
```

## Measured against the reference readers

Every reading rule is specified by running the reference readers at pinned
versions:

- GNU tar 1.35, as Ubuntu 24.04 packages it
- bsdtar 3.8.11 (libarchive)
- Python 3.12.3, as Ubuntu 24.04 packages it
- Go 1.27.0

The repository's case catalog holds 242 archives. Each case records the rule
it shows, ferrotape's verdict in every setting, and each reader's reading,
taken by running the reader. The tests hold ferrotape to every case. CI
checks the recorded readings against the pinned readers, and reads 10,000
changed archives in every setting. A weekly workflow reads the catalog with
each reader's newest release.

The readers disagree among themselves on some archives. The `differences`
page of the documentation lists every kind of archive on which ferrotape
reads otherwise than one of them. Each row gives every reader's reading and
ferrotape's.

### Settings

Two settings choose whose readings count. `Level::Strict`, the default,
suits archives from sources the caller does not control. It counts every
reader in wide use:

- The four above
- POSIX, where it says one thing and they another
- The Rust crates `tar`, `tar-core` and `tar-codec`
- GNU tar reading on past the end of an archive, as `--ignore-zeros` does

`Level::Compatible` counts the four readers and POSIX, and no others. It
suits archives a trusted publisher vouches for. One kind of member the four
extract differently is read as GNU tar extracts it. The member's mode has
setuid, setgid or sticky, and it has an access control list.

`GlobalHeaders` chooses what is done with a global extended header. It is
refused, applied as GNU tar and Python apply it, or applied to nothing, as Go
reads it.

## Out of scope

- **Extract to a directory.** Safe extraction keeps every path and link
  inside the destination, and needs operating-system facilities that Rust's
  standard library does not expose. A member's path and link target are the
  archive's bytes, and the caller decides which of them are acceptable.
- **Decompress.** The reader takes the decoded stream.
- **Write sparse members.** `Writer` writes a file with holes whole.

## Security

[SECURITY.md](SECURITY.md) describes how to report a vulnerability, and what
counts as one. The chief case is an archive ferrotape reads at its default
settings with other members than the reference readers see.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
