# Security policy

ferrotape reads tar archives from sources its caller does not control. A
program that checks an archive with it, and a program that extracts the
archive, must see the same members. Where they do not, the check passes what
the extraction then does otherwise. A defect can also let an archive crafted for
it stop it answering. Security reports are therefore handled separately from
ordinary bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's [private
vulnerability reporting](https://github.com/gregordinary/ferrotape/security/advisories/new)
for this repository, which opens a draft advisory visible only to you and the
maintainers.

Please include, as far as you can:

- The archive, or a short program that writes it, and the settings ferrotape
  read it with.
- What ferrotape reported: its members, each with its path, type, size and
  link target, or the error. What GNU tar (`tar -tvf`), bsdtar, Go's
  `archive/tar` or Python's `tarfile` report for the same archive, and their
  versions.
- The commit or version of ferrotape.

You will get an acknowledgement within a few days. A fixed vulnerability is
announced in a GitHub security advisory and a RustSec advisory, which name the
reporter unless you ask otherwise.

## Scope

- **A member-set difference.** With its default settings, ferrotape reads an
  archive only where GNU tar, bsdtar, Go's `archive/tar` and Python's
  `tarfile` agree on its members. It refuses the rest. An archive it reads
  otherwise than they do is a vulnerability, fixed and announced as one. Such
  an archive has a member only one side sees, or a member whose path, link
  target, data, owner, mode, times or extended attributes differ.
- **A member-set difference at another setting.** Every other setting names,
  in its documentation, the readers it reads as. A member-set difference from
  those readers is a vulnerability at that setting too. `Level::Compatible`
  names the same four, `GlobalHeaders::Apply` GNU tar and Python, and
  `GlobalHeaders::Defer` bsdtar and Go, for the global headers each applies
  as they do.
- **A header that reads back as another member.** A header ferrotape writes
  that ferrotape or one of those readers reads back with another path, link
  target, size, owner, mode or time. A difference the documentation lists is
  the exception.
- **Panics and runaway resource use on hostile input.** The library is
  written not to panic, and every allocation an archive can drive has a
  ceiling the caller can set. Reading takes time linear in the archive's
  length, apart from sorting a pax extended header's records to compare them
  (n log n in the header's length). A panic, memory beyond those ceilings, or
  time beyond that, on any archive, is a vulnerability. A sparse member's
  data is the one exception (below).

## Out of scope

- **A sparse member's size.** `Reader::data` delivers the file a sparse
  member stands for, holes as zeros, which can be up to 2^60 - 1 bytes. The
  archive states that size before any data is read (`Entry::size`).
  `Reader::stored_data` reads only what the archive holds.

- **The documented differences from those readers.** The documentation lists
  where ferrotape reads an archive otherwise than they do, on purpose. A
  difference it does not list is a defect, welcome as an ordinary issue unless
  it is one of the cases above. A refusal reads nothing, so an archive refused
  that the readers all read alike is an ordinary issue too.
- **What a path means.** ferrotape reports a member's path and link target as
  the archive's bytes. The caller decides whether an absolute path, a `..`
  component or a link out of a directory is acceptable. The caller also
  decides how to write members to a filesystem safely.
- **Decompression.** ferrotape reads the bytes it is given. A decoder beneath
  it is outside this crate.

If you are unsure which side of the line a finding falls on, report it
privately, and the maintainers will work it out with you.

## Supported versions

Security fixes are made to the newest release, and published as a release of
their own. Earlier releases are not patched, so receiving a fix means
upgrading to the newest release. While the major version is 0, a fix that
breaks compatibility with the public API is published as a new minor version
(such as 0.2.0 after 0.1.x). Any other fix is published as a new patch
version.
