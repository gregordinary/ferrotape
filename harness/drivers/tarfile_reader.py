"""Reads a tar archive with Python's tarfile and prints each member.

Usage: python3 -I tarfile_reader.py ARCHIVE

One line per member, its fields separated by tabs and every text field in
hexadecimal: `member`, the typeflag, the path, the link target, the size,
the device's major and minor numbers, the mode in decimal, the modification
time in whole seconds (floored), the uid, the gid, the owner's name, the
group's name, and the data, or `-` where tarfile gives none. Then `ok`, or
`error` and the exception, in hexadecimal.

A member's data is what `extractfile` returns, which is the member's own
data for a regular file and for a typeflag tarfile does not know; it is not
read for a link, whose `extractfile` returns the target's data.
"""

import math
import sys
import tarfile


def text(value):
    return value.encode("utf-8", "surrogateescape").hex()


def main():
    out = sys.stdout
    try:
        with tarfile.open(sys.argv[1], mode="r:") as archive:
            for member in archive:
                data = "-"
                if not (member.islnk() or member.issym()):
                    handle = archive.extractfile(member)
                    if handle is not None:
                        data = handle.read().hex()
                fields = [
                    "member",
                    member.type.hex(),
                    text(member.name),
                    text(member.linkname),
                    str(member.size),
                    str(member.devmajor),
                    str(member.devminor),
                    str(member.mode),
                    str(math.floor(member.mtime)),
                    str(member.uid),
                    str(member.gid),
                    text(member.uname),
                    text(member.gname),
                    data,
                ]
                out.write("\t".join(fields) + "\n")
        out.write("ok\n")
    except Exception as error:  # A reader's refusal, whatever its type.
        message = "%s: %s" % (type(error).__name__, error)
        out.write("error\t%s\n" % text(message))


main()
