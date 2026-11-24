# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

ferrotape's contract includes which archives it reads and refuses, what it
reports for their members, and the bytes it writes. A change to any of them
is recorded, with what it changes, even when no signature of the public API
does.

## [Unreleased]

The first release, measured against GNU tar 1.35 and Python 3.12.3 as Ubuntu
24.04 packages them, bsdtar 3.8.11 and Go 1.27.0.

### Added

- `Reader`, a tar archive reader over any `Read`, for POSIX ustar and pax, GNU
  and pre-POSIX v7 archives. `next_entry` yields each member as an `Entry`,
  its GNU long name, long link and pax records applied. `data` reads the
  member's data as a `Read`, and `read_entry` reads it whole under a caller's
  limit. `finish` reads the rest of the archive and, under a limit, the
  stream after it, so a decoder beneath checks its trailer. `get_ref` shows
  the source, and `into_inner` returns it where the reader left it: the
  reader reads no further than it has framed.
- `Reader::seeking`, for a source that can seek: data the caller does not
  read is passed over by seeking, each seek held to the source's length.
- `Decoder`, the reader without I/O, for a source a `Read` does not fit (an
  asynchronous stream, a buffer filled as data arrives, an archive in memory
  in a build without `std`). `step` says what it needs next (`Step`: the
  stream's next bytes, read into a buffer it lends, or bytes to pass over),
  or yields a member or the archive's end. `data` and `stored_data` say what
  a member's data holds next (`Chunk`). `filled`, `skipped` and `data_read`
  report what the caller moved, a count of zero ending the stream. The
  decoder counts every byte, and itself frames each member's data and
  padding. Every rule, level, mode and limit of `Reader` applies, since a
  `Reader` is a decoder driven over a `Read`.
- A `std` feature, on by default, holding `Reader`, `Data`, `Writer`,
  `WriteError` and the conversions into `io::Error`. Without it the library
  builds on `core` and `alloc` alone.
- Sparse members, in GNU's old form (typeflag `S`) and pax formats 0.0, 0.1
  and 1.0. `data` delivers the file with its holes as zeros, and
  `Entry::size` is its real size. `Entry::sparse` gives its map (`Sparse`,
  `Region`), and `Reader::stored_data` the stored regions alone. A map is
  read only in the shapes GNU tar, bsdtar, Go and Python extract alike. Any
  other is refused with `ErrorKind::Sparse` and the `SparseFlaw` it shows. A
  real size of 2^60 or more is refused, as is a map larger than
  `Limits::metadata`.
- `Level`, set with `Reader::with_level`. `Strict`, the default, refuses an
  archive that any reader in wide use reads with other members than GNU tar,
  bsdtar, Go and Python do. `Compatible` refuses only one those four read
  apart.
- `GlobalHeaders`, set with `Reader::with_global_headers`: what is done with a
  global extended header holding any record but `comment`. `Refuse`, the
  default, refuses it. `Apply` applies it as GNU tar and Python do. Every
  member would hold a copy of a global `path`, `linkpath`, `uname` or
  `gname`, so `Apply` refuses one longer than 4,095 bytes. `Defer`
  applies nothing, as Go reads it, and bsdtar before libarchive 3.8.10. In
  every mode its records reach the caller once: on the member after it
  (`Entry::global`), or after the last member (`Reader::trailing_global`).
- `Entry` accessors for the member's fields: `path`, `link_target`, `kind`
  (an `EntryKind`, read from the typeflag as GNU tar and bsdtar read it),
  `typeflag` (the byte), `mode`, `uid`, `gid`, `uname`, `gname` and `device`
  (0,0 for a device in a header with no device fields). For its size, `size`
  (the data delivered, zero for the types that have none) and
  `declared_size`. For its times, `mtime`, `atime` and `ctime`, each a
  `Timestamp` rounded down to the nanosecond. For where it lies and what
  described it, `header_block`, `header_offset`, `data_offset`, `pax_records`
  and `global`.
- `PaxRecords`, every record of an extended header, iterated in order
  (`iter`, `Records`) or looked up with `get`. `xattrs` (`Xattrs`) and
  `xattr` give the extended attributes from `SCHILY.xattr.` records.
  `access_acl` and `default_acl` give each access control list in both forms
  an archive records it, as `AclRecords`.
- `Header`, a member to write: a constructor for each kind (`file`,
  `directory`, `symlink`, `hard_link`, `char_device`, `block_device`, `fifo`)
  and a setter for each field (mode, owner ids and names, modification,
  access and change times to the nanosecond, extended attributes, and records
  of the caller's own). `Header::encode` writes a POSIX ustar header block,
  preceded by a pax extended header for whatever the block cannot hold
  exactly. It refuses with a `HeaderError` a header that would not read back
  as set. A member with setuid, setgid or sticky beside an access control
  list is written as GNU tar writes it, and refused by `Level::Strict`.
- `Writer`, which appends each member's header, data and padding to any
  `Write`. `finish` ends the archive and returns the destination.
  `into_inner` returns it without the end marker, for a caller that writes
  what follows itself. `get_ref` shows the destination meanwhile. A failure
  inside a member is a `WriteError` that ends the writer, and converts into
  an `io::Error`.
- `Timestamp`: `new` and `from_secs`, and `secs` and `nanos`.
- `Limits`, set on the reader: the most data a metadata member may declare, 1
  MiB by default. No buffer the reader grows asks for more than one
  allocation can be. So a limit above a sixteenth of the largest allocation
  the target allows is read as that sixteenth: 128 MiB on a 32-bit target.
  `read_entry`'s limit is read likewise as at most half of it.
- `Error`, with the `ErrorKind` and the offset in the stream. A kind's
  details are `HeaderField`, `Keyword`, `Metadata`, `Numeric`, `PaxFraming`
  and `Truncation`, and a `HeaderError`'s `TextField`. A failing source's own
  error is kept as the source. A reader's `Error` converts into an
  `io::Error` that carries it, and a reader whose source fails with one
  returns it as it was. Once a call fails, every later call fails the same
  way, except a refusal of `read_entry`'s limit. A source's failure is
  repeated with its `io::ErrorKind` and message.
- The `differences` page of the documentation. It lists every kind of archive
  on which ferrotape reads otherwise than GNU tar, bsdtar, Go or Python. Each
  row gives what each reader does, what ferrotape does at each level, and the
  catalog cases that show it.

#### Refused at every level

Each refusal has an `ErrorKind`. A stream that is no archive at all is
`ErrorKind::NotATar`, told apart from a damaged one. The reader refuses:

- A header that fails its checksum. The checksum is octal: GNU tar and bsdtar
  pass over a header whose sum is in base-256, which Python reads.
- A numeric field that does not read, or reads negative where it cannot be,
  the device numbers of every header included, whatever its magic. A field
  holding digits, then a space and more digits, does not read. Nor does a
  field of spaces alone, or one beginning with a NUL and holding anything
  else. GNU tar reads those otherwise than the others. GNU tar reads
  device numbers only for a device, so only a device's are held to this.
- A declared size of 2^60 or more, in a header or a pax record.
- A pax record that does not frame, a keyword that is empty, holds a NUL, or
  begins with a space or a tab included. GNU tar passes over the space or
  tab, and applies the record that the others do not.
- A pax record the reader applies whose value is a number in any form but
  decimal digits, or an id above 2^32 - 1.
- An empty pax `path`, `linkpath`, `uname` or `gname`, or a NUL in any of
  them.
- An empty or unreadable pax time, or a time before 1970 with a fraction of a
  second.
- A second metadata member of one kind before a member.
- A pax name and a GNU long name that differ.
- A `SCHILY.xattr.` record whose name is empty or spelled with `%3D` or `%25`,
  or whose value is empty. Readers extract these as different attributes.
- A `LIBARCHIVE.xattr.` record that does not repeat a `SCHILY.xattr.` record.
- An `RHT.security.selinux` record beside another record of the label that
  it does not repeat as GNU tar writes the two. Where it is the only record
  of the label, one given twice, empty or holding a NUL.
- A device's `SCHILY.devmajor` or `SCHILY.devminor` record, a missing one
  taken as 0, stating other numbers than its header.
- A `hdrcharset` other than POSIX's two.
- A pax or global header with no records.
- A long link whose value is empty.
- A long name or long link holding no NUL whose padding begins with a byte
  that is not one.
- A global header out of place, or holding a record its mode refuses. Where
  its records are applied, a keyword given twice with different values.
- Typeflags `X`, `A`, `M` and `V`.
- A header without the POSIX magic with bytes in its prefix area.
- A GNU header that is not typeflag `S` holding old sparse slots, or a real
  size for a member that has data.
- A header with an owner name, or a device's number other than 0, whose
  magic and version are neither POSIX's nor GNU's exactly.
- A POSIX header that names its member with a prefix ending in `/`.
- A POSIX header ending in star's trailer that names its member with a
  prefix longer than star's 131 bytes.
- A member with an empty name.
- A member named as a directory that declares data, or that has a pax record
  other than those the reader applies, `comment` and `hdrcharset`.
- A member of a typeflag GNU tar does not know, named with a trailing `/`.
- A member that is not a link with a link target from a long link or a pax
  `linkpath`.
- A member that is not a directory with a default access control list
  (`SCHILY.acl.default`).
- A hard link with no target, or that declares a size.
- A file or a hard link that is not sparse with a `SCHILY.realsize` record
  other than its size, which bsdtar takes as the size.
- A symbolic link, directory, device or FIFO whose size a pax record
  declares.
- A sparse member whose map takes a shape the readers extract otherwise.
- An archive that ends early.

#### Refused at `Level::Strict` as well

- A long name or long link with a NUL before its last byte.
- Metadata in a header whose magic and version are not exactly POSIX's or
  GNU's.
- A symbolic link, directory, device or FIFO whose header declares a size.
- A keyword repeated with different values in one pax header.
- A member with setuid, setgid or sticky and an access control list.
  `Compatible` reads it with the header's mode, as GNU tar extracts it.
- A sparse member in a pax format, which Rust's `tar` reads as a plain file
  of its stored data.
- Anything but zeros after the archive's first zero block, in `next_entry`
  and in `finish`.

### Agreement with the reference readers

- The case catalog's 264 archives. In each of the six settings, ferrotape
  gives every case its stated verdict. Wherever it reads one, it reads the
  members the readers that setting stands in for read.
- 10,000 archives made by changing the catalog's one to three ways (9,128
  distinct, 2,308 of them read by ferrotape in some setting). None is read
  otherwise than by the readers its setting stands in for.
- 4,360 tar streams in 3,994 published archives (Alpine, Debian and Gentoo
  packages and root filesystems, crates, npm packages, Python sdists,
  Homebrew bottles, container image layers, and release tarballs), 764,470
  members: every stream read at both levels and in every global-header mode,
  none refused.
- 618 members written by `Writer`, at each field's limits and generated: GNU
  tar, Python and Go read every field as written. bsdtar lists every field as
  written but one: a member with an access control list, whose mode it takes
  from the list.
