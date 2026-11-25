# The case catalog

The archives ferrotape is measured against, each with the rule it shows,
ferrotape's verdict, and what each reference reader read from it. The
catalog is the specification ferrotape's reader is held to. The verdicts are
ferrotape's. The readings are the reference readers' own, recorded by running
them.

| Directory | What its cases show |
| --- | --- |
| `framing/` | where an archive begins and ends, and what is not one |
| `headers/` | how a header's fields are read |
| `types/` | what each typeflag is, and which types of member have data |
| `pax/` | per-member pax records |
| `gnu/` | GNU long names and long links |
| `global/` | global pax headers, in each mode |
| `sparse/` | sparse members: each form of the map, and the shapes refused |

`cargo test --workspace` checks every case, with no reference reader
installed (`harness/tests/catalog.rs`). ferrotape must give each case's
stated verdict in each setting, and wherever it reads a case, read the
members the reference readers read.

## A case

A case file is text in sections, each opened by its name in brackets:

```text
[statement]
A pax `size` record overrides the header's size, whatever the header says.
Here the record says zero and the header declares a body holding two headers,
which every reader then lists as members, and so does ferrotape.

[archive]
pax size=0
header name=outer size=1024
header name=smuggled1
header name=smuggled2
header name=tail
data "hello\n"
end

[verdict]
all: read

[gnu-tar 1.35]
member listed=- path=outer size=0 data=""
...
exit 0

[bsdtar 3.8.11]
...

[python 3.12.3]
...

[go 1.27.0]
...
```

- `[statement]` states the rule in prose.
- `[archive]` holds the archive, one item to a line (see "The archive"). A
  line beginning `#` is a comment.
- `[verdict]` gives ferrotape's verdict in each of the six settings, a level
  and a global-header mode. Each line is a selector, `: ` and a verdict. A
  selector is `all`, a level (`strict`, `compatible`), a mode (`refuse`,
  `apply`, `defer`), or a level and a mode, and the lines name each setting
  once. A verdict is `read`, or `refused`, the name of the error's
  `ErrorKind` and `at` its offset. A sparse member's refusal names its
  `SparseFlaw` in parentheses, as `Sparse(End)`.
- One section for each reference reader, named with the version that read
  it, holding its reading (see "Readings"). The harness writes these.

The verdict and the readings each have one written form, which the test
checks, so recording a case rewrites nothing but its readings.

## The archive

Each item adds bytes to the archive, in order:

| Item | Bytes |
| --- | --- |
| `header` *field=value* ... | one header block |
| `data` *value* | a body, padded with zeros to a whole block |
| `records` *key=value* ... | a body of pax records, each framed by its length, padded |
| `bytes` *value* | bytes as they are, unpadded |
| `zeros` *n* | *n* zero blocks |
| `end` | the end marker, two zero blocks |
| `pax` *key=value* ... | a pax header (`typeflag=x name=PaxHeader`) and its records |
| `global` *key=value* ... | a global header (`typeflag=g name=PaxHeader`) and its records |
| `longname` *value* | a GNU long name (`typeflag=L name=././@LongLink magic=gnu`), its value and a NUL |
| `longlink` *value* | a GNU long link, as `longname` with `typeflag=K` |

A header's fields, and what each is unless set:

| Field | Unless set |
| --- | --- |
| `name`, `linkname`, `prefix` | empty (`prefix` only in a POSIX header) |
| `mode` | `0o644` |
| `uid`, `gid`, `mtime`, `devmajor`, `devminor` | 0 |
| `size` | the length of a `data` or `records` body directly after the header, and 0 where none follows |
| `typeflag` | `0` |
| `magic` | `ustar` (POSIX, version `00`). Also `gnu` (`ustar  \0`), and `v7` (none, and nothing written past the link name) |
| `uname`, `gname` | `root` |
| `checksum` | `unsigned`, the sum POSIX specifies. Also `signed`, and `bad`, which matches neither. `base256` writes the unsigned sum in GNU's base-256 form. A quoted value of eight bytes writes them, the unsigned sum's octal digits filling its `#` bytes, as `"\0###### "` does |
| `@`*offset* | bytes written at that offset after every other field |

A numeric field is written in octal, zero-padded and ending in a NUL, from a
decimal number or one written `0o` and octal. `base256:` and a signed decimal
number writes GNU's base-256 form. A quoted value writes the field's bytes as
given.

A value is bare or quoted. A bare value is a run of printable ASCII holding
no space, `"` or `\`. A quoted value is one or more quoted pieces written
with no space between them. Each piece can be followed by `*` and a count
that repeats it. Inside quotes, `\\`, `\"`, `\n`,
`\r`, `\t`, `\0` and `\xNN` are escapes. `"a"*99"/file"` is 99 `a`s and
`/file`.

## Readings

A reading is one line to a member, in the order the reader yields them, then
how the reading ended. A member line is `member` and the fields the reader
reports:

| Field | What | Readers |
| --- | --- | --- |
| `type` | the typeflag byte | Go, Python |
| `listed` | the first character of the listing's mode column | GNU tar, bsdtar |
| `path`, `link` | the path, and a link target where there is one | all |
| `size` | the size reported | all, but a listing shows none for a device |
| `device` | a device's major and minor numbers | all |
| `mode` | the permission bits, in octal | all: Go and Python from the mode field, GNU tar and bsdtar from the listing's mode column |
| `mtime`, `uid`, `gid`, `uname`, `gname` | the time in whole seconds (rounded down), and the owner | Go, Python |
| `data` | the data, quoted, or its length and 64-bit FNV-1a digest where long | GNU tar (regular files), Go, Python |
| `note` | what a listing appends to a name, which is not part of it | GNU tar |

For Go and Python, the last line is `ok`, or `error` and the reader's
message. For GNU tar and bsdtar, each line of standard error follows as a
`warning`, then `exit` and the command's status. A reader that refuses an
archive (Go or Python failing, or a command failing having listed nothing)
is not compared: a refusal extracts nothing. A command that fails after
listing members is compared by what it listed. The exception is bsdtar
stopping at a global header it does not support (from libarchive 3.8.10, one
holding any record but `comment`), which refuses the archive from there on.

## Comparing ferrotape with a reading

Where ferrotape reads a case in a setting, its members are compared with the
readings of the readers that setting's mode stands in for. Each mode stands
in for its readers: all four in `refuse`, GNU tar and Python in `apply`,
bsdtar and Go in `defer`. The member lists must name the same members in the
same order. Each member must have the same link target, data, device, mode,
owner and times, wherever the reader reports them. Three normalizations
hold, each measured:

- Python drops a directory's trailing slash from its name, so a trailing
  slash is not compared.
- A mode is compared in its twelve permission bits. Go and Python report a
  mode field's other bits too, and no reader applies them on extraction.
- A listing's type is compared as the reader extracts it. GNU tar lists a
  contiguous file as `C`, and extracts it as a regular file, or a directory
  where its name ends in `/`. It lists an unknown typeflag as `?` and
  extracts a regular file.

Go and Python report a typeflag, not what they extract, so a member's kind
is compared with GNU tar's and bsdtar's listings alone. Where the readers
disagree on a member's type, ferrotape follows GNU tar and bsdtar.

A member can have an access control list as text: an access or default
list, or an NFSv4 one (`SCHILY.acl.access`, `SCHILY.acl.default`,
`SCHILY.acl.ace`). bsdtar takes such a member's mode from its lists rather
than from its header, and ferrotape reads the header's mode. The differences
page states this difference, which the test does not compare. bsdtar's mode
is not compared for such a member, and the page names every case where
bsdtar lists another mode.

## The harness

The `harness` crate in this repository runs the reference readers:

```sh
cargo run -p ferrotape-harness -- record catalog/pax/a-new-rule.case
cargo run -p ferrotape-harness -- check catalog
cargo run -p ferrotape-harness -- build catalog/pax/a-new-rule.case /tmp/a.tar
cargo run -p ferrotape-harness -- read catalog/pax/a-new-rule.case
cargo run -p ferrotape-harness --release -- mutate --count 20000 --out /tmp/mutants catalog
```

`record` writes each reader's reading into a case file. `check` reports every
case a reader now reads otherwise than recorded, and exits with status 1.
Both need the readers, at the versions the catalog pins, and
refuse to run with another version unless given `--unpinned`:

| Reader | Version | Build | Found as |
| --- | --- | --- | --- |
| GNU tar | 1.35 | Ubuntu 24.04's package, `1.35+dfsg-3ubuntu0.4` | `tar`, or `FERROTAPE_GNU_TAR` |
| bsdtar (libarchive) | 3.8.11 | libarchive's release, configured with `--enable-acl` and `--enable-xattr` | `bsdtar`, or `FERROTAPE_BSDTAR` |
| Python `tarfile` | 3.12.3 | Ubuntu 24.04's package, `3.12.3-1ubuntu0.17` | `python3`, or `FERROTAPE_PYTHON` |
| Go `archive/tar` | 1.27.0 | Go's release | `go`, or `FERROTAPE_GO` |

A pin names a build as well as a version, since a build can read otherwise
than its release. Ubuntu's Python includes fixes to `tarfile`. Ubuntu's GNU
tar includes fixes for CVE-2026-5704 that GNU's 1.35 release lacks, and
GNU's release reads five cases otherwise:

- It reads a device, a FIFO or a symbolic link declaring a size with the
  declared body as its data, where Ubuntu's reads none (four cases).
- It lists a directory declaring a size with that size.

`harness/readers.sh` builds bsdtar and installs Go as CI does:

```sh
harness/readers.sh install libarchive 3.8.11 a3dc0872b1b39da34dc18ef1b944f0f11ffd37425d70ae04be679279f1cf43d2 ~/readers/libarchive
harness/readers.sh install go 1.27.0 675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685 ~/readers/go
```

CI checks every case's readings with the pinned readers on each pull
request. A weekly workflow reads the catalog with each reader's newest
release, and reports each reading that changes. A change that is understood,
where the pin stays, is listed in `known-changes.txt` as `check` reports it.
The weekly workflow passes that file to `check --known`, and fails only on a
change the file does not list. A change is matched by its case, its reader,
the newer reading and the recorded one. A later release reading the same way
is therefore still known, and a case recorded again is not.

GNU tar and bsdtar are read through their verbose listings, in the C locale
and UTC, each run under its plain name. GNU tar's regular files' data is read
through an extraction to a command. Python and Go are read through the
small programs in `harness/drivers/`. `build` writes a case's archive, for
reading it with any other tool. `read` shows ferrotape's verdict on a case in
each setting, and how its members differ from each recorded reading its
setting is compared with.

`mutate` changes the catalog's archives, one to three changes at a time. A
change is one of these:

- A header's size, other numeric fields, checksum, magic, typeflag, names,
  prefix or raw bytes. A numeric field or the checksum can take a blank or a
  NUL in its digits, around them, or in their place. It can also take spaces
  and a NUL before the digits, or a NUL and a byte after them. A prefix
  can come with star's trailer, and numbers, blanks or letters where star
  keeps its times.
- A pax record's key, value or framing. A blank or a NUL can come before the
  record's length, or before, inside or after its keyword. The keyword can
  be empty, or a zero can lead the length.
- The items themselves: removed, repeated, swapped, cut short, or joined by
  another case's member

It reads each mutant with ferrotape in every setting. Where ferrotape reads it
in any setting, it reads the mutant with the reference readers too. It
reports each mutant ferrotape reads otherwise than a reader its setting
stands in for, grouped by the kind of difference. Go or Python failing after
listing members is compared by what it listed, so ferrotape listing members
past them is reported.

Mutant `n` of a seed is always the same archive, so `--seed` and `--count`
make a run reproducible whatever `--jobs` is. `--seconds` bounds a run by
time instead. With `--out`, the first three mutants of each kind are written
as cases with their verdicts and readings. Each is then reduced, and added to
the catalog with the rule it shows.

## Adding a case

1. Write the statement, the archive and the verdict.
2. Run `record`.
3. Read the readings, and check that the statement says what they show.

Name the file for what its archive holds, in a few words. Put variants of one
case beside it, with a suffix that says what differs.
