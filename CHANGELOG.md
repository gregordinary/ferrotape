# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

Which archives ferrotape reads and refuses, what it reports for their members,
and the bytes it writes are part of its contract. A change to any of them is
recorded, with what it changes, even when no signature of the public API does.

## [Unreleased]

The first release, measured against GNU tar 1.35 and Python 3.12.3 as Ubuntu
24.04 packages them, bsdtar 3.8.11 and Go 1.27.0.

### Added

- `Reader`, a tar archive reader over any `Read`, for POSIX ustar and pax, GNU
  and pre-POSIX v7 archives. `next_entry` yields each member as an `Entry`,
  its GNU long name, long link and pax records applied; `data` reads the
  member's data as a `Read`; `read_entry` reads it whole under a caller's
  limit; `finish` reads the rest of the archive and, under a limit, the
  stream after it, so a decoder beneath checks its trailer.
- `Reader::seeking`, for a source that can seek: data the caller does not
  read is passed over by seeking, each seek held to the source's length.
- Sparse members, in GNU's old form (typeflag `S`) and pax formats 0.0, 0.1
  and 1.0: `data` delivers the file with its holes as zeros, `Entry::size` is
  its real size, `Entry::sparse` its map (`Sparse`, `Region`), and
  `Reader::stored_data` the stored regions alone. A map is read only in the
  shapes GNU tar, bsdtar, Go and Python extract alike, and refused otherwise
  with `ErrorKind::Sparse` and the `SparseFlaw` it shows; a real size of
  2^60 or more is refused, and a map is held to `Limits::metadata`.
- `Level`, set with `Reader::with_level`: `Strict`, the default, refuses an
  archive that any reader in wide use reads with other members than GNU tar,
  bsdtar, Go and Python do; `Compatible` refuses only one those four read
  apart.
- `GlobalHeaders`, set with `Reader::with_global_headers`: what is done with a
  global extended header holding any record but `comment`. `Refuse`, the
  default, refuses it. `Apply` applies it as GNU tar and Python do. `Defer`
  applies nothing, as Go reads it, and bsdtar before libarchive 3.8.10. In
  every mode its records reach the caller once: on the member after it
  (`Entry::global`), or after the last member (`Reader::trailing_global`).
- What the reader refuses at every level, each with an `ErrorKind`: a header
  that fails its checksum; a numeric field that does not read (one holding
  digits, then a space and more digits, among them) or reads negative where it
  cannot be, the device numbers of every header included, whatever its magic;
  a declared size of 2^60 or more, in a header or a pax record; a pax record
  that does not frame, a keyword holding a NUL included, or holds an applied
  value it may not (a number in any form but decimal digits, an id above 2^32
  - 1, an empty `path`, `linkpath`, `uname` or `gname`, an empty or unreadable
  time, a time before 1970 with a fraction of a second, a NUL in `path` or
  `linkpath`); a second metadata member of one kind before a member; a pax
  name and a GNU long name that differ; extended attribute records that
  readers extract as different attributes (a `SCHILY.xattr.` name that is
  empty or spelled with `%3D` or `%25`, an empty value, a `LIBARCHIVE.xattr.`
  record that does not repeat a `SCHILY.xattr.` record, or an
  `RHT.security.selinux` record beside another record of the label that it
  does not repeat as GNU tar writes the two, or alone and given twice,
  empty or holding a NUL), a device's
  `SCHILY.devmajor` or `SCHILY.devminor` record, a missing one taken as 0,
  stating other numbers than its header, or a `hdrcharset` other than POSIX's
  two; a pax or global header with no records; a long link whose value is
  empty; a long name or long link holding no NUL whose padding begins with a
  byte that is not one; a global header out of place, carrying what its mode
  refuses, or, where its records are applied, a keyword twice with different
  values; typeflags `X`, `A`, `M` and `V`; a header without the POSIX magic
  with bytes in its prefix area; a GNU header that is not typeflag `S`
  holding old sparse slots, or a real size for a member that carries data; a header whose magic and version are neither
  POSIX's nor GNU's exactly that holds an owner name, or a device number other
  than 0 for a device; a POSIX header that names its member with a prefix
  ending in `/`; a member with an empty name; a member named as a directory
  that declares data, or that carries a pax record other than those the reader
  applies, `comment` and `hdrcharset`, or of a typeflag GNU tar does not know
  and named with a trailing `/`; a member that is not a link with a link
  target from a long link or a pax `linkpath`; a member that is not a
  directory carrying a default access control list (`SCHILY.acl.default`); a
  hard link with no target, or that declares a size; a symbolic link,
  directory, device or FIFO whose size a pax record declares; a sparse member
  whose map takes a shape the readers extract otherwise; and an archive that
  ends early. A stream that is no archive at all is
  `ErrorKind::NotATar`, told apart from a damaged one.
- What `Level::Strict` refuses besides: a long name or long link with a NUL
  before its last byte; metadata in a header whose magic and version are not
  exactly POSIX's or GNU's; a symbolic link, directory, device or FIFO whose
  header declares a size; a keyword repeated with different values in one pax
  header; a member with setuid, setgid or sticky that carries an access
  control list, which `Compatible` reads with the header's mode, as GNU tar
  extracts it; a sparse member in a pax format, which Rust's `tar` reads as a
  plain file of its stored data; and anything but zeros after the archive's
  first zero block, in
  `next_entry` and in `finish`.
- `Entry` accessors: `path`, `link_target`, `kind` (an `EntryKind`, read from
  the typeflag as GNU tar and bsdtar read it), `typeflag` (the byte), `mode`,
  `uid`, `gid`, `uname`, `gname`, `size` (the data delivered, zero for the
  types that carry none), `declared_size`, `mtime`, `atime` and `ctime` (as a
  `Timestamp`, floored to the nanosecond), `device` (0,0 for a device in a
  header with no device fields), `header_block`, `header_offset`,
  `data_offset`, `pax_records` and `global`.
- `PaxRecords`, every record of an extended header, iterated in order
  (`iter`, `Records`) or looked up with `get`; the extended attributes from
  `SCHILY.xattr.` records, `xattrs` (`Xattrs`) and `xattr`; and `access_acl`
  and `default_acl`, each list in both forms an archive records it, as
  `AclRecords`.
- `Header`, a member to write: a constructor for each kind (`file`,
  `directory`, `symlink`, `hard_link`, `char_device`, `block_device`, `fifo`)
  and a setter for each field (mode, owner ids and names, modification,
  access and change times to the nanosecond, extended attributes, and records
  of the caller's own). `Header::encode` writes a POSIX ustar header block,
  preceded by a pax extended header for whatever the block cannot hold
  exactly, and refuses with a `HeaderError` a header that would not read back
  as set. A member with setuid, setgid or sticky beside an access control
  list is written as GNU tar writes it, and refused by `Level::Strict`.
- `Writer`, which appends each member's header, data and padding to any
  `Write`; `finish`, which ends the archive and returns the destination; and
  `into_inner`, which returns it without the end marker, for a caller that
  writes what follows itself. `get_ref` shows the destination meanwhile. A
  failure inside a member is a `WriteError` that ends the writer, and
  converts into an `io::Error`.
- `Timestamp`: `new` and `from_secs`, and `secs` and `nanos`.
- `Limits`, set on the reader: the most data a metadata member may declare, 1
  MiB by default.
- `Error`, with the `ErrorKind` and the offset in the stream; a kind's
  details are `HeaderField`, `Keyword`, `Metadata`, `Numeric`, `PaxFraming`
  and `Truncation`, and a `HeaderError`'s `TextField`. A failing
  source's own error is kept as the source; a reader's `Error` converts into
  an `io::Error` that carries it, and a reader whose source fails with one
  returns it as it was. Once a call fails, every later call fails the same
  way, except a refusal of `read_entry`'s limit.
- The `differences` page of the documentation: every kind of archive on which
  ferrotape reads otherwise than GNU tar, bsdtar, Go or Python, what each of
  them does, and what ferrotape does at each level, each row naming the cases
  of the repository's catalog that show it.

### Agreement with the reference readers

- The case catalog's 242 archives: in each of the six settings, ferrotape
  gives every case its stated verdict, and wherever it reads one, reads the
  members the readers that setting stands in for read.
- 10,000 archives made by changing the catalog's one to three ways (9,039
  distinct, 2,354 of them read by ferrotape in some setting): none read
  otherwise than by the readers that setting stands in for.
- 4,362 tar streams in 3,996 published archives (Alpine, Debian and Gentoo
  packages and root filesystems, crates, npm packages, Python sdists,
  Homebrew bottles, container image layers, and release tarballs), 764,771
  members: every stream read at both levels and in every global-header mode,
  none refused.
- 618 members written by `Writer`, at each field's limits and generated: GNU
  tar, Python and Go read every field as written. bsdtar lists every field as
  written but the mode of a member carrying an access control list, which it
  takes from the list.
